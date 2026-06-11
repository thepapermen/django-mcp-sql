"""Reconcile each profile's Postgres role SELECT grants against its `ALLOWED_MODELS`.

Single public entry point: `reconcile_grants(*, strict, apply) -> DriftDiff`.
It loops `MCP_SQL["PROFILES"]`, reconciling each profile's role against
that profile's whitelist independently (per-role drift — never global).

- `strict=True`: preflight failures (role missing, no membership, self-
  referential whitelist) raise `GrantsReconcileError`. Used by the
  `mcp_sql_grants` deploy-pipeline command.
- `strict=False`: env-level preflight failures (role missing,
  no membership) log a WARNING and return an empty `DriftDiff` with
  `skipped_reason` set. Code-level misconfigs (self-referential
  whitelist) raise regardless. Used by the `post_migrate` signal so a
  fresh environment without `role_setup.sql` does not crash `migrate`.
- `apply=True`: also execute the GRANT / REVOKE statements implied by the
  diff. `apply=False` is read-only; the returned `DriftDiff` describes
  what WOULD have been done.

The signal observes (`apply=False`); the deploy command applies
(`apply=True`). Keeping detection and execution behind one flag means
adding "what would change" output to the apply command is a one-line
edit, not a refactor.
"""

import logging
from dataclasses import dataclass
from dataclasses import field

from django.apps import apps
from django.db import connection
from django.db import transaction
from mcp_sql.conf import Profile
from mcp_sql.conf import mcp_sql_settings

logger = logging.getLogger(__name__)


class GrantsReconcileError(Exception):
    """Strict-mode preflight failure (role missing, no membership) or
    code-level misconfiguration (self-referential whitelist)."""


def _verify_default_alias() -> None:
    """Raise if the implicit `connection` is not the default alias.

    Every grants-pipeline helper uses the implicit `from django.db import
    connection` — i.e. the connection routed by the project's router /
    `using=...` chain at call time. The `mcp_readonly` alias is a
    NOLOGIN read-only path; running grants reconciliation through it
    would either error opaquely (NOLOGIN role can't issue GRANT) or, if
    the alias ever gets remapped in a future settings refactor, silently
    operate against the wrong DB. Defense-in-depth assertion mirrors
    `executor._verify_executor_alias()` for the symmetric case (executor
    must NOT be on `default`, grants must be ON `default`).
    """
    if connection.alias != "default":
        msg = (
            f"grants.py expects the 'default' DB alias, got "
            f"{connection.alias!r}. The grants pipeline must run against "
            "the writeable default alias (mcp_readonly is NOLOGIN read-only)."
        )
        raise GrantsReconcileError(msg)


@dataclass
class ProfileDrift:
    """Per-profile drift between a profile's declared whitelist and the
    SELECT grants on its Postgres role.

    - `granted`, `revoked`: sorted `db_table` names to grant / revoke on
      this profile's role (with `apply=False`) or that were granted /
      revoked (with `apply=True`).
    - `skipped_reason`: non-empty in lenient mode when this profile's
      env-level preflight failed (`"role_missing"` / `"no_membership"`);
      both action lists are empty and the apply path is a no-op for it.
    """

    granted: list[str] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.granted or self.revoked)


@dataclass
class DriftDiff:
    """Reconciliation result across every profile, keyed by profile name.

    Aggregate convenience properties (`granted` / `revoked` / `changed` /
    `skipped_reason`) summarise across profiles for the deploy command's
    exit code and the `post_migrate` signal's drift WARNING; `per_profile`
    carries the per-role detail for the command's profile/table matrix.
    """

    per_profile: dict[str, ProfileDrift] = field(default_factory=dict)

    @property
    def granted(self) -> list[str]:
        return sorted({t for d in self.per_profile.values() for t in d.granted})

    @property
    def revoked(self) -> list[str]:
        return sorted({t for d in self.per_profile.values() for t in d.revoked})

    @property
    def granted_count(self) -> int:
        """Total GRANTs across profiles — a table two roles both need counts
        twice here, matching the number of statements actually executed
        (unlike `granted`, which dedupes table names for display)."""
        return sum(len(d.granted) for d in self.per_profile.values())

    @property
    def revoked_count(self) -> int:
        return sum(len(d.revoked) for d in self.per_profile.values())

    @property
    def changed(self) -> bool:
        return any(d.changed for d in self.per_profile.values())

    @property
    def skipped_reason(self) -> str:
        """First profile skip-reason, or '' if every profile was reconciled.

        Informational only — callers must NOT treat a truthy value as "no
        drift anywhere": with N profiles, one skipped profile (role not yet
        created) says nothing about drift on the profiles that DID
        reconcile. Per-profile skips are already logged at WARNING inside
        `reconcile_grants`.
        """
        for d in self.per_profile.values():
            if d.skipped_reason:
                return d.skipped_reason
        return ""


def declared_tables(profile: Profile) -> dict[str, str]:
    """Resolve a profile's `ALLOWED_MODELS` to `{dotted_path: db_table}`.

    Resolution happens here (runtime) rather than at boot so that an
    optional / not-yet-installed app does not crash startup.
    """
    out: dict[str, str] = {}
    for entry in profile.allowed_models:
        model = apps.get_model(entry)
        out[entry] = model._meta.db_table
    return out


def granted_tables(role: str) -> set[str]:
    """The public-schema tables on which `role` currently holds SELECT."""
    _verify_default_alias()
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.role_table_grants
            WHERE grantee = %s
              AND privilege_type = 'SELECT'
              AND table_schema = 'public'
            """,
            [role],
        )
        return {row[0] for row in cur.fetchall()}


def role_exists(role: str) -> bool:
    _verify_default_alias()
    with connection.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s",
            [role],
        )
        return cur.fetchone() is not None


def has_role_membership(role: str) -> bool:
    """Does the current DB user have MEMBER rights on `role`?

    A required precondition for SET ROLE at executor time. Granted by
    `role_setup.sql` (`GRANT <role> TO <app role>`), which requires
    admin-option and so must be issued by a DBA.
    """
    _verify_default_alias()
    with connection.cursor() as cur:
        cur.execute(
            "SELECT pg_has_role(current_user, %s, 'MEMBER')",
            [role],
        )
        return bool(cur.fetchone()[0])


def self_referential_entries(profile: Profile) -> list[str]:
    """Return the profile's `ALLOWED_MODELS` entries that point at this app.

    Granting SELECT on the MCP audit table to the role that the audit
    table is meant to constrain defeats the audit. The reconciler refuses
    to apply such a whitelist regardless of strict/lenient mode.
    """
    return [
        entry
        for entry in profile.allowed_models
        if entry.lower().startswith("mcp_sql.")
    ]


def _verify_view_parity(profile: Profile) -> None:
    """Raise on column-list drift between unmanaged whitelist models and their views.

    Each curated MCPxxx view has its column list duplicated in three
    places (CREATE_SQL string, migration `state_operations` CreateModel,
    unmanaged `models.py` declaration). Nothing structural keeps the
    three in sync; the failure modes are (a) model field missing from
    the view → `ProgrammingError` on first real query, or (b) view
    column missing from the model → invisible to `apps.get_model`.

    For every declared model whose Django `Meta.managed = False` (the
    curated-view shape), issue `SELECT * FROM <view> LIMIT 0` and compare
    the live column set to `model._meta.fields`. Mismatch raises
    `GrantsReconcileError` listing the diff on both sides. The
    `SELECT * LIMIT 0` also forces PG to evaluate the view's projection
    — so the case where the underlying table changed and the view's
    SELECT is broken raises before the assertion.
    """
    _verify_default_alias()
    mismatches: list[str] = []
    for entry, table in declared_tables(profile).items():
        model = apps.get_model(entry)
        if model._meta.managed:
            # Real Django-managed table; no view parity to check.
            continue
        model_columns = {f.column for f in model._meta.fields}
        with connection.cursor() as cur:
            # `table` comes from `model._meta.db_table` (Django model
            # metadata, not user input). Ruff's S608 false-positives
            # f-string SQL even when the only interpolation is a trusted
            # Django identifier — there is no parameterisable form for
            # the table name in `SELECT * FROM ...`.
            cur.execute(f'SELECT * FROM "{table}" LIMIT 0')  # noqa: S608
            view_columns = {col.name for col in cur.description}
        if model_columns != view_columns:
            mismatches.append(
                f"  {entry} ↔ view {table!r}: "
                f"model-only={sorted(model_columns - view_columns)}, "
                f"view-only={sorted(view_columns - model_columns)}"
            )
    if mismatches:
        msg = (
            "Curated MCPxxx view ↔ unmanaged-model column drift:\n"
            + "\n".join(mismatches)
            + "\nUpdate the CREATE_SQL, the state_operations CreateModel "
            "field list, and the unmanaged model in the owning app so all "
            "three agree."
        )
        raise GrantsReconcileError(msg)


def reconcile_grants(*, strict: bool, apply: bool) -> DriftDiff:
    """Compute drift for every profile; optionally apply.

    See module docstring for the strict/apply matrix. Returns a
    `DriftDiff` whose `per_profile` maps each profile name to its
    `ProfileDrift`. Self-referential whitelist entries and view-parity
    drift always raise (`GrantsReconcileError`) — those are code-level
    misconfigurations, not env-level state. In strict mode a missing role
    or membership raises; in lenient mode that profile is skipped with a
    WARNING and the others are still reconciled.
    """
    _verify_default_alias()
    result = DriftDiff()
    for profile in mcp_sql_settings.profiles().values():
        result.per_profile[profile.name] = _reconcile_profile(
            profile, strict=strict, apply=apply
        )
    return result


def _reconcile_profile(profile: Profile, *, strict: bool, apply: bool) -> ProfileDrift:
    """Reconcile one profile's role against its declared whitelist.

    Drift is computed strictly per role — declared-for-this-profile minus
    granted-to-this-profile's-role — so a table shared with another
    profile is never revoked here just because some OTHER profile does not
    declare it.
    """
    bad = self_referential_entries(profile)
    if bad:
        msg = (
            f"Refusing to grant on mcp_sql models for profile {profile.name!r}: "
            f"{bad!r}. Remove these entries from the profile's ALLOWED_MODELS."
        )
        raise GrantsReconcileError(msg)

    if not role_exists(profile.role):
        msg = (
            f"Role {profile.role} (profile {profile.name!r}) does not exist. "
            "Apply the role setup SQL first "
            "(see mcp_sql/docs/role-setup.md)."
        )
        if strict:
            raise GrantsReconcileError(msg)
        logger.warning("MCP grants reconcile skipped: %s", msg)
        return ProfileDrift(skipped_reason="role_missing")

    if not has_role_membership(profile.role):
        msg = (
            f"Current DB user is NOT a member of {profile.role} (profile "
            f"{profile.name!r}). The executor's SET ROLE will fail at runtime. "
            "Apply role_setup as a DBA — see mcp_sql/docs/role-setup.md."
        )
        if strict:
            raise GrantsReconcileError(msg)
        logger.warning("MCP grants reconcile skipped: %s", msg)
        return ProfileDrift(skipped_reason="no_membership")

    # Curated MCPxxx view ↔ unmanaged-model column parity. Runs here
    # rather than as a separate helper because the parity contract is
    # part of "what the MCP read surface exposes", same as grants. The
    # signal path (apply=False) catches drift at every `migrate`; the
    # deploy path (apply=True) catches it before GRANT/REVOKE issues
    # statements against an out-of-sync view.
    _verify_view_parity(profile)

    declared = set(declared_tables(profile).values())
    current = granted_tables(profile.role)
    drift = ProfileDrift(
        granted=sorted(declared - current),
        revoked=sorted(current - declared),
    )
    if apply and drift.changed:
        role = profile.role
        with transaction.atomic(), connection.cursor() as cur:
            for table in drift.granted:
                cur.execute(f'GRANT SELECT ON "{table}" TO {role};')
            for table in drift.revoked:
                cur.execute(f'REVOKE SELECT ON "{table}" FROM {role};')  # noqa: S608
    return drift
