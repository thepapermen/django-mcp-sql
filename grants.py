"""Reconcile each profile's Postgres role SELECT grants against its `ALLOWED_MODELS`.

Single public entry point: `reconcile_grants(*, strict, apply) -> DriftDiff`.
It loops `MCP_SQL["PROFILES"]`, reconciling each profile's role against
that profile's whitelist independently (per-role drift — never global).

- `strict=True`: preflight failures (role missing, no membership, self-
  referential whitelist, overlong `db_table`) raise `GrantsReconcileError`.
  Used by the `mcp_sql_grants` deploy-pipeline command.
- `strict=False`: env-level preflight failures (role missing,
  no membership) log a WARNING and return an empty `DriftDiff` with
  `skipped_reason` set. Code-level misconfigs (self-referential
  whitelist, overlong `db_table`) raise regardless. Used by the
  `post_migrate` signal so a fresh environment without `role_setup.sql`
  does not crash `migrate`.
- `apply=True`: also execute the GRANT / REVOKE statements implied by the
  diff, then re-read the grants in the same transaction and roll back with
  `GrantsReconcileError` if any drift is left (PostgreSQL only warns on a
  GRANT / REVOKE the app login may not make). `apply=False` is read-only;
  the returned `DriftDiff` describes what WOULD have been done.

The signal observes (`apply=False`); the deploy command applies
(`apply=True`). Keeping detection and execution behind one flag means
adding "what would change" output to the apply command is a one-line
edit, not a refactor.
"""

import logging
import re
from dataclasses import dataclass
from dataclasses import field

from django.apps import apps
from django.db import connection
from django.db import transaction
from mcp_sql.conf import Profile
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.parser import DEFAULT_SCHEMA
from mcp_sql.parser import names_schema
from mcp_sql.parser import relation_of

logger = logging.getLogger(__name__)

# A relation as `(schema, name)`, each exactly as the catalog stores it.
Relation = tuple[str, str]

# PostgreSQL's identifier length limit in bytes (`NAMEDATALEN - 1`, the
# server's `max_identifier_length`; 63 unless the server was built with
# another `NAMEDATALEN`). A longer name is truncated wherever it is used.
MAX_IDENTIFIER_BYTES = 63


class GrantsReconcileError(Exception):
    """Strict-mode preflight failure (role missing, no membership),
    code-level misconfiguration (self-referential whitelist, a `db_table`
    longer than PostgreSQL keeps), or an `--apply` whose statements left
    drift (rolled back)."""


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

    - `granted`, `revoked`: sorted relations, `(schema, name)`, to grant /
      revoke on this profile's role (with `apply=False`) or that were
      granted / revoked (with `apply=True`). `relation_sql` renders one for
      SQL, `relation_display` for a message.
    - `skipped_reason`: non-empty in lenient mode when this profile's
      env-level preflight failed (`"role_missing"` / `"no_membership"`);
      both action lists are empty and the apply path is a no-op for it.
    """

    granted: list[Relation] = field(default_factory=list)
    revoked: list[Relation] = field(default_factory=list)
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
    def granted(self) -> list[Relation]:
        return sorted({t for d in self.per_profile.values() for t in d.granted})

    @property
    def revoked(self) -> list[Relation]:
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


def quote_ident(identifier: str) -> str:
    """`identifier` as a quoted SQL identifier that names exactly it.

    Every `"` is doubled (the relations come from the catalog, where any
    role that can create a relation chooses its name: `x" FROM r; DROP …`
    is a valid table name). A name with a character that does not print
    (a newline, a control or format character) is written as a Unicode
    escape identifier, `U&"…"` with each such character as `\\+XXXXXX`,
    so a printed statement is one line and shows what it names; Postgres
    reads it as the same identifier."""
    if identifier.isprintable():
        return '"' + identifier.replace('"', '""') + '"'
    body = "".join(
        c if c.isprintable() and c != "\\" else f"\\+{ord(c):06X}" for c in identifier
    )
    return 'U&"' + body.replace('"', '""') + '"'


def relation_sql(relation: Relation) -> str:
    """A relation as a schema-qualified SQL name, `"public"."t"`: GRANT and
    REVOKE name the relation the parser matches, never whatever the app
    role's own `search_path` finds first."""
    schema, name = relation
    return f"{quote_ident(schema)}.{quote_ident(name)}"


_PLAIN_NAME = re.compile(r"[a-z_][a-z0-9_]*")


def relation_display(relation: Relation) -> str:
    """A relation for a message: the bare name for a plainly named relation
    in `DEFAULT_SCHEMA`, else `relation_sql` (quoted, so a crafted name
    cannot pass for another relation or another line)."""
    schema, name = relation
    if schema == DEFAULT_SCHEMA and _PLAIN_NAME.fullmatch(name):
        return name
    return relation_sql(relation)


def granted_tables(role: str) -> set[Relation]:
    """Every relation outside the system schemas on which `role` currently
    holds SELECT, as `(schema, name)`.

    Not only `public`: a grant on a relation in another schema (a
    `GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO <role>`, or a
    same-named copy of a whitelisted table) is a grant nothing declares, so
    the drift check reports it and `--apply` revokes it. The names are
    whatever the relations' owners chose; they are compared as tuples and
    rendered for SQL only through `relation_sql`.

    Limits of the inventory (`information_schema.role_table_grants`):
    materialized views are not listed, nor are grants to `PUBLIC` or grants
    the role holds only through membership in another role (ledger F42 /
    F64); relations in temporary schemas are skipped. With
    `PIN_SEARCH_PATH` off, a relation shadowing a whitelisted name and
    readable through any of these is served to the agent and never
    reported (docs/architecture.md "`search_path` is pinned only on
    request")."""
    _verify_default_alias()
    with connection.cursor() as cur:
        cur.execute(
            r"""
            SELECT table_schema, table_name
            FROM information_schema.role_table_grants
            WHERE grantee = %s
              AND privilege_type = 'SELECT'
              AND table_schema NOT IN ('pg_catalog', 'information_schema')
              AND table_schema NOT LIKE 'pg\_%%'
            """,
            [role],
        )
        return {(str(schema), str(name)) for schema, name in cur.fetchall()}


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


def overlong_entries(profile: Profile) -> list[str]:
    """The profile's `ALLOWED_MODELS` entries whose `db_table` has a schema
    or table name longer than `MAX_IDENTIFIER_BYTES` (UTF-8 bytes).

    PostgreSQL truncates such a name (on a character boundary) wherever it
    appears, so the catalog lists the truncated name: the inventory never
    shows the declared relation, and each `--apply` granted it and revoked
    the truncated one in turn. The reconciler refuses such a whitelist
    regardless of strict/lenient mode; the fix is a shorter `db_table`."""
    return [
        f"{entry} ({table!r})"
        for entry, table in declared_tables(profile).items()
        if any(
            len(part.encode("utf-8")) > MAX_IDENTIFIER_BYTES
            for part in relation_of(table)
        )
    ]


def relations_off_default_schema(tables: dict[str, str]) -> dict[str, str]:
    """`{entry: schema}` for each unqualified `db_table` in `tables`
    (`{dotted_path: db_table}`) that names no relation in `DEFAULT_SCHEMA`
    while the login's `search_path` finds one of that name in `schema`.

    An unqualified `db_table` is the relation in `public` to the parser,
    the grants and the read path (round 16; until 0.1.0b5 GRANT resolved it
    through the login's `search_path`). For such an entry `--apply` fails
    with `relation "public.<name>" does not exist`, and an unmanaged one's
    view-parity probe fails the same way. Resolved as Postgres resolves an
    unqualified name on this connection (`current_schemas(true)`: the
    schemas on the `search_path` that exist and the login may use, with
    `pg_catalog` and the session's temporary schema where Postgres implies
    them), from the catalog, so no name is parsed as SQL. A `db_table`
    that is nowhere yet (a migration still to run) is not reported."""
    _verify_default_alias()
    names = {
        entry: relation_of(table)[1]
        for entry, table in tables.items()
        if not names_schema(table)
    }
    if not names:
        return {}
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT w.name, (
                SELECT s.nspname
                FROM unnest(current_schemas(true)) WITH ORDINALITY
                    AS s(nspname, pos)
                JOIN pg_namespace n ON n.nspname = s.nspname
                JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = w.name
                ORDER BY s.pos
                LIMIT 1
            )
            FROM unnest(%s::text[]) AS w(name)
            WHERE NOT EXISTS (
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = w.name
            )
            """,
            [sorted(set(names.values())), DEFAULT_SCHEMA],
        )
        found = {str(name): str(schema) for name, schema in cur.fetchall() if schema}
    return {entry: found[name] for entry, name in names.items() if name in found}


def off_default_schema_message(
    profile_name: str, entry: str, db_table: str, schema: str
) -> tuple[str, str]:
    """`(message, remedy)` for an entry `relations_off_default_schema`
    reported: shared by the system check (`mcp_sql.E001`) and the
    reconciler, so `check`, `migrate` and `mcp_sql_grants` say the same."""
    message = (
        f"MCP_SQL profile {profile_name!r} whitelists {entry}, whose db_table "
        f"{db_table!r} names no schema, so it is the relation in schema "
        f"{DEFAULT_SCHEMA!r} to the parser, mcp_sql_grants and the read path; "
        f"there is none there — the login's search_path finds it in schema "
        f"{schema!r}."
    )
    qualified = f'{schema}"."{relation_of(db_table)[1]}'
    remedy = (
        f"Name the schema: db_table = {qualified!r} (and grant the profile "
        "role USAGE on the schema). For a model you cannot edit (a "
        "third-party app), whitelist instead an unmanaged model of your own "
        "(Meta.managed = False) with that db_table, declaring exactly the "
        "relation's columns, or a curated view in public over the relation "
        '(docs/architecture.md "Curated-view pattern").'
    )
    return message, remedy


def _verify_off_default_schema(profile: Profile) -> None:
    """Raise `GrantsReconcileError` for an entry that names a relation
    `public` does not have but the `search_path` does
    (`relations_off_default_schema`) — before the view-parity probe and
    GRANT would fail on it with a bare `ProgrammingError` (which the
    `post_migrate` receiver let through, failing `migrate`)."""
    tables = declared_tables(profile)
    off = relations_off_default_schema(tables)
    if off:
        msg = "\n".join(
            " ".join(off_default_schema_message(profile.name, e, tables[e], schema))
            for e, schema in sorted(off.items())
        )
        raise GrantsReconcileError(msg)


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
            # metadata, not user input), quoted by `relation_sql` all the
            # same; there is no parameterisable form for the table name in
            # `SELECT * FROM ...`.
            probe = f"SELECT * FROM {relation_sql(relation_of(table))} LIMIT 0"  # noqa: S608
            cur.execute(probe)
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
    `ProfileDrift`. Self-referential whitelist entries, an overlong
    `db_table` and view-parity drift always raise (`GrantsReconcileError`)
    — those are code-level misconfigurations, not env-level state. In
    strict mode a missing role or membership raises; in lenient mode that
    profile is skipped with a WARNING and the others are still reconciled.

    Every profile is checked and its drift computed before anything is
    applied, and all profiles' GRANT / REVOKE statements run in one
    transaction: a refusal of any profile changes no grant (review round
    19: the profiles before the refused one had been applied already).
    The grants are re-read in that transaction before it commits, and any
    drift left — a statement PostgreSQL only warned about — rolls it back
    with `GrantsReconcileError` (`_apply_and_verify`).
    Roles are unique per profile (boot-validated), so one profile's
    changes never alter another's drift.
    """
    _verify_default_alias()
    result = DriftDiff()
    profiles = list(mcp_sql_settings.profiles().values())
    for profile in profiles:
        result.per_profile[profile.name] = _profile_drift(profile, strict=strict)
    if apply and result.changed:
        _apply_and_verify(
            [(profile, result.per_profile[profile.name]) for profile in profiles]
        )
    return result


def _reconcile_profile(profile: Profile, *, strict: bool, apply: bool) -> ProfileDrift:
    """Reconcile one profile's role against its declared whitelist (the
    checks and the drift of `_profile_drift`, then `_apply_and_verify`)."""
    drift = _profile_drift(profile, strict=strict)
    if apply and drift.changed:
        _apply_and_verify([(profile, drift)])
    return drift


def _profile_drift(profile: Profile, *, strict: bool) -> ProfileDrift:
    """Check one profile and compute its role's drift; nothing is applied.

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

    too_long = overlong_entries(profile)
    if too_long:
        msg = (
            f"Refusing to reconcile grants for profile {profile.name!r}: "
            f"{too_long!r} name a relation longer than PostgreSQL's "
            f"{MAX_IDENTIFIER_BYTES}-byte identifier limit, which it "
            "truncates: shorten Meta.db_table."
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

    _verify_off_default_schema(profile)

    # Curated MCPxxx view ↔ unmanaged-model column parity. Runs here
    # rather than as a separate helper because the parity contract is
    # part of "what the MCP read surface exposes", same as grants. The
    # signal path (apply=False) catches drift at every `migrate`; the
    # deploy path (apply=True) catches it before GRANT/REVOKE issues
    # statements against an out-of-sync view.
    _verify_view_parity(profile)

    return _role_drift(profile)


def _role_drift(profile: Profile) -> ProfileDrift:
    """The profile role's drift from its whitelist as the catalog stands
    now: declared minus granted, granted minus declared."""
    # Relations, `(schema, name)`, on both sides (`"t"` and `t` are the same
    # table; `s"."t` is not `t`).
    declared = {relation_of(table) for table in declared_tables(profile).values()}
    current = granted_tables(profile.role)
    return ProfileDrift(
        granted=sorted(declared - current),
        revoked=sorted(current - declared),
    )


def _apply_and_verify(drifts: list[tuple[Profile, ProfileDrift]]) -> None:
    """Run every profile's GRANT / REVOKE statements in one transaction,
    then re-read each role's grants in it; if any drift is left, roll the
    transaction back and raise `GrantsReconcileError` naming it.

    PostgreSQL does not always fail a GRANT or REVOKE the executing role
    may not make: on a relation the app login neither owns (nor is a
    member of the owning role of) nor holds `WITH GRANT OPTION` on, but
    holds some other privilege on, GRANT warns "no privileges were
    granted" and REVOKE "no privileges could be revoked", and nothing
    changes (with no privilege at all it raises "permission denied"); a
    REVOKE also removes only grants its role made itself. Before,
    `--apply` reported such statements as applied and exited 0 while check
    mode kept reporting the same drift. A whitelisted materialized view
    fails here too: the inventory (`information_schema`) never lists its
    grants, so its GRANT never shows (check mode reports it on every run
    as well — `granted_tables`)."""
    with transaction.atomic():
        for profile, drift in drifts:
            _apply_drift(profile.role, drift)
        left = {
            profile.name: remaining
            for profile, drift in drifts
            if drift.changed and (remaining := _role_drift(profile)).changed
        }
        if left:
            raise GrantsReconcileError(_unapplied_message(left))


def _unapplied_message(left: dict[str, ProfileDrift]) -> str:
    """Name each profile's drift `--apply` left, with each relation's owner
    and the login that ran the statements."""
    info = _catalog_info({r for d in left.values() for r in d.granted + d.revoked})

    def shown(relations: list[Relation]) -> str:
        out = []
        for relation in relations:
            text = relation_display(relation)
            if relation in info:
                owner, relkind = info[relation]
                text += f" (owner {quote_ident(owner)}"
                if relkind == "m":
                    text += (
                        "; a materialized view: information_schema lists no "
                        "grants on one, so the drift check never sees them"
                    )
                text += ")"
            out.append(text)
        return ", ".join(out)

    lines = []
    for name, drift in left.items():
        if drift.granted:
            lines.append(f"  [{name}] still not granted: {shown(drift.granted)}")
        if drift.revoked:
            lines.append(f"  [{name}] still granted: {shown(drift.revoked)}")
    with connection.cursor() as cur:
        cur.execute("SELECT current_user")
        login = cur.fetchone()[0]
    return (
        "After the GRANT / REVOKE statements the grants still drift, so "
        "nothing was applied (rolled back):\n"
        + "\n".join(lines)
        + "\nPostgreSQL only warns, changing nothing, when the role running "
        f"a GRANT / REVOKE (the login running mcp_sql_grants, {login!r}) "
        "may not change the privilege: it can grant or revoke only on a "
        "relation it owns (or whose owning role it is a member of) or holds "
        "WITH GRANT OPTION on, and REVOKE removes only the grants it made "
        "itself. Run `mcp_sql_grants --apply` as the relations' owner, or "
        "have the owner run the statements `mcp_sql_grants` prints without "
        "--apply."
    )


def _catalog_info(relations: set[Relation]) -> dict[Relation, tuple[str, str]]:
    """`(owning role, relkind)` of each of `relations` that exists."""
    if not relations:
        return {}
    schemas, names = zip(*sorted(relations), strict=True)
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner), c.relkind
            FROM unnest(%s::text[], %s::text[]) AS r(nspname, relname)
            JOIN pg_namespace n ON n.nspname = r.nspname
            JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = r.relname
            """,
            [list(schemas), list(names)],
        )
        return {
            (str(s), str(n)): (str(owner), str(kind))
            for s, n, owner, kind in cur.fetchall()
        }


def _apply_drift(role: str, drift: ProfileDrift) -> None:
    """Run the GRANT / REVOKE statements `drift` implies for `role`, in the
    caller's transaction."""
    with connection.cursor() as cur:
        # `role` is boot-validated as a plain identifier
        # (`validation._PG_IDENTIFIER_RE`), as for `SET LOCAL ROLE`.
        for relation in drift.granted:
            cur.execute(f"GRANT SELECT ON {relation_sql(relation)} TO {role};")
        for relation in drift.revoked:
            revoke = f"REVOKE SELECT ON {relation_sql(relation)} FROM {role};"  # noqa: S608
            cur.execute(revoke)
