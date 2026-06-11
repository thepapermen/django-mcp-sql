"""Signal receivers: revoke MCP tokens on user_logged_out; provision the
per-profile groups/permissions on post_migrate; alert (Sentry ERROR) when a
user is added to an MCP profile group (and, layered on top, when the addition
leaves them in >1 profile = ambiguous); log a WARNING on grants drift after
post_migrate (advisory only — apply happens via `mcp_sql_grants --apply`).
See `docs/architecture.md` file-map row for `signals.py`."""

import logging
from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.signals import user_logged_out
from django.db import DatabaseError
from django.db import transaction
from django.db.models import Q
from django.db.models.signals import m2m_changed
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.utils import timezone
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.grants import GrantsReconcileError
from mcp_sql.grants import reconcile_grants
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.schemas import AuthRejectionReason

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser

logger = logging.getLogger(__name__)

User = get_user_model()


@receiver(user_logged_out)
def revoke_mcp_tokens_on_logout(
    sender, request, user: "AbstractBaseUser | None", **kwargs
):
    if user is None:
        # Anonymous logout (rare but allowed by Django) — nothing to revoke.
        return
    # Defer the revocation to `on_commit` so a failure in it can NEVER abort
    # the logout transaction — the user must always be able to log out. The
    # delete + audit run only after the logout commits; if the logout itself
    # rolls back, no tokens are revoked (consistent: the user isn't logged
    # out either). `request` and the timestamp are read synchronously (the
    # callback fires outside the request scope); `user` is captured by
    # reference and stays valid post-commit — logout does not delete the user
    # row, so its `pk` and the audit FK resolve fine. `started_at` is the
    # logout moment, not the (marginally later) post-commit callback time.
    client_ip = request.META.get("REMOTE_ADDR") if request is not None else None
    logged_out_at = timezone.now()
    transaction.on_commit(
        lambda: _revoke_and_audit_on_logout(
            user=user, client_ip=client_ip, logged_out_at=logged_out_at
        )
    )


def _revoke_and_audit_on_logout(*, user, client_ip, logged_out_at):
    """Best-effort post-commit MCP token revocation + a forensic audit row.

    Runs after the logout transaction commits. Both the delete and the
    audit write are wrapped so a DB blip is logged (Sentry via
    `logger.exception`) rather than surfacing as a 500 on an already-
    completed logout.
    """
    # Lazy import keeps `apps.ready()` import-graph small.
    from oauth2_provider.models import AccessToken

    # Match BOTH the curated `mcp-sql` Application (exact name) AND every
    # DCR-minted `mcp-sql-<token>` Application (prefix). The prefix carries
    # a trailing dash, so a `startswith` on it does NOT match the canonical
    # name — that's why the Q-OR is required here.
    try:
        deleted, _ = AccessToken.objects.filter(
            Q(application__name=mcp_sql_settings.APPLICATION_NAME)
            | Q(application__name__startswith=mcp_sql_settings.APPLICATION_NAME_PREFIX),
            user=user,
        ).delete()
    except DatabaseError:
        logger.exception("Failed to revoke MCP tokens on logout for user %s", user.pk)
        return
    if not deleted:
        return
    logger.info("Revoked %d MCP token(s) on logout for user %s", deleted, user.pk)
    # Record the revocation in the access-ending audit table alongside the
    # per-request gate denials, so the timeline of why a user lost MCP
    # access is complete.
    try:
        MCPAuthRejectionLog.objects.create(
            user=user,
            token_pk="",
            application_name="",
            reason=AuthRejectionReason.SESSION_LOGOUT,
            error=f"Revoked {deleted} MCP token(s) on logout",
            client_ip=client_ip,
            started_at=logged_out_at,
        )
    except DatabaseError:
        logger.exception(
            "Revoked MCP tokens on logout for user %s but failed to write the "
            "audit row",
            user.pk,
        )


@receiver(post_migrate)
def provision_mcp_profiles(sender, **kwargs) -> None:
    """Ensure one Permission + one Group per `MCP_SQL["PROFILES"]` entry.

    Idempotent (get_or_create); runs after every `migrate` on the default
    alias. Replaces both the static `MCPQueryLog.Meta.permissions` and any
    per-profile data migration a consumer would otherwise need — the package
    cannot enumerate consumer-defined profile names at migration-authoring
    time, but it CAN read them from settings at apply time. Existing rows
    (e.g. the `default` profile's `mcp_sql_users` group + `use_mcp_session`
    permission that the original migration 0004 created on already-deployed
    environments) are found and left untouched, so cohort membership survives
    the upgrade with zero data migration.

    Assumes the `auth` / `contenttypes` tables exist when it fires — true for
    any standard `migrate` (their migrations run before mcp_sql's, and
    `post_migrate` is emitted after the whole plan completes). The old
    in-migration provisioning declared that dependency explicitly; the
    signal-based form relies on the standard full-plan `migrate` flow rather
    than `migrate mcp_sql` against a DB where `auth` was never migrated.
    """
    if sender is None or getattr(sender, "label", None) != "mcp_sql":
        return
    using = kwargs.get("using")
    if using and using != "default":
        return

    from django.contrib.auth.models import Permission
    from django.contrib.contenttypes.models import ContentType
    from mcp_sql.models import MCPQueryLog

    content_type = ContentType.objects.get_for_model(MCPQueryLog)
    for profile in mcp_sql_settings.profiles().values():
        # `defaults` only applies on CREATE: an already-deployed env keeps the
        # permission's original (unsuffixed) `name`, a fresh env gets the
        # `(<profile>)` suffix. Cosmetic only — binding is by codename — so the
        # benign cross-env name drift is accepted rather than force-updated.
        perm, _ = Permission.objects.get_or_create(
            codename=profile.codename,
            content_type=content_type,
            defaults={
                "name": f"Can use the MCP read-only SQL session ({profile.name})"
            },
        )
        group, _ = Group.objects.get_or_create(name=profile.group_name)
        group.permissions.add(perm)


@receiver(post_migrate)
def audit_grants_drift_after_migrate(sender, **kwargs) -> None:
    """Detect drift between each profile role's grants and its
    `MCP_SQL["PROFILES"][...]["ALLOWED_MODELS"]` whitelist after `migrate`
    completes. Logs only; never applies.

    Fires once per full `migrate` invocation (gated on the mcp_sql app
    config sender). Lenient mode: a missing role or missing membership
    logs a warning (via `reconcile_grants` itself) and returns an empty
    diff. Code-level misconfiguration (self-referential whitelist) is
    caught and logged at ERROR rather than propagating into `migrate`'s
    exception chain — the manual `mcp_sql_grants --apply` command would
    surface the same error loudly at deploy time.
    """
    if sender is None or getattr(sender, "label", None) != "mcp_sql":
        return

    # `kwargs["using"]` is the alias migrate was invoked against. Only
    # the `default` alias hosts `mcp_readonly_role`; the read-only alias
    # is not used by the migrate flow.
    using = kwargs.get("using")
    if using and using != "default":
        return

    try:
        drift = reconcile_grants(strict=False, apply=False)
    except GrantsReconcileError:
        # Self-referential whitelist or other code-level misconfig.
        # `mcp_sql_grants --apply` will refuse to deploy with this state;
        # logging here ensures the issue shows up in the migrate output
        # for any operator who notices it locally too.
        logger.exception("MCP grants drift detection failed")
        return

    # Deliberately NO early-return on `drift.skipped_reason`: with N
    # profiles, one skipped profile (role not yet created — already logged
    # at WARNING inside reconcile_grants) must not silence the drift
    # WARNING for the profiles that DID reconcile. That is exactly the
    # phased-rollout state where the deploy-watched signal matters most.
    if drift.changed:
        logger.warning(
            "MCP grants DRIFT detected against the MCP_SQL[PROFILES] "
            "whitelists: +%d to grant, -%d to revoke (across profiles). Run "
            "`python manage.py mcp_sql_grants --apply` to reconcile "
            "(typically a deploy-pipeline step).",
            drift.granted_count,
            drift.revoked_count,
        )


def _mcp_group_pks() -> dict[int, str]:
    """Map each existing MCP profile group's pk → its profile name.

    Cohort grants are rare (admin actions), so a per-event query is fine.
    Empty on a fresh DB before `provision_mcp_profiles` ran, so the receiver
    no-ops instead of crashing the m2m save.
    """
    name_to_profile = {
        p.group_name: p.name for p in mcp_sql_settings.profiles().values()
    }
    return {
        g.pk: name_to_profile[g.name]
        for g in Group.objects.filter(name__in=name_to_profile).only("pk", "name")
    }


def _user_label(user) -> str:
    """`get_username()` (the email here), guarded so an alert never raises."""
    try:
        return user.get_username()
    except Exception:  # noqa: BLE001 — an alert path must never raise
        return "?"


def _mcp_memberships(
    user_ids: set[int], mcp_group_pks: dict[int, str]
) -> dict[int, list[str]]:
    """`{user_id: sorted [profile_name, ...]}` — each user's current MCP
    profile-group memberships. Per-user queries; cohort changes are rare."""
    out: dict[int, list[str]] = {}
    for uid in user_ids:
        try:
            pks = Group.objects.filter(user__pk=uid, pk__in=mcp_group_pks).values_list(
                "pk", flat=True
            )
            out[uid] = sorted(mcp_group_pks[pk] for pk in pks)
        except DatabaseError:
            logger.exception("MCP membership query failed for user pk=%s", uid)
            out[uid] = []
    return out


def _alert_mcp_group_grant(user_ids: set[int], mcp_group_pks: dict[int, str]) -> None:
    if not user_ids:
        return
    memberships = _mcp_memberships(user_ids, mcp_group_pks)
    try:
        users = {u.pk: u for u in User.objects.filter(pk__in=user_ids)}
    except DatabaseError:
        users = {}
    for uid in user_ids:
        label = _user_label(users[uid]) if uid in users else "?"
        profiles = memberships.get(uid, [])
        logger.error(
            "MCP cohort change: %s (pk=%s) GAINED MCP access via profile "
            "group(s) [%s] — confirm this grant was authorized.",
            label,
            uid,
            ", ".join(profiles) or "?",
        )
        # A user now in >1 MCP profile group is ambiguous and will be DENIED by
        # resolve_profile until fixed — page once, here at assignment time. The
        # per-request denial only logs a deduped WARNING (aggregate-alert
        # convention: alert at the cause, not per consequence).
        if len(profiles) > 1:
            logger.error(
                "MCP profile AMBIGUITY: user pk=%s is in %d MCP profile groups "
                "(%s) — MCP access will be DENIED until exactly one remains.",
                uid,
                len(profiles),
                ", ".join(profiles),
            )


@receiver(m2m_changed, sender=User.groups.through)
def alert_on_mcp_group_grant(sender, instance, action, pk_set, reverse, **kwargs):
    """Alert (Sentry ERROR) when a user is ADDED to an MCP profile group.

    Two layered alerts: the "gained access" page (any addition to a profile
    group is the privilege-escalation signal worth paging on) and, on top, an
    ambiguity page when the addition leaves the user in >1 MCP profile group
    (which denies them until fixed). Deliberately narrow — only the GAIN, only
    via group membership. OUT of scope by design: losing a group
    (de-escalation is safe), direct `user_permissions` grants/revokes, and
    changes to a group's own permission set. Fires on `post_add` only —
    Django admin's m2m save uses `.set()`, which emits `post_add` of the
    added diff, so an admin adding the group is covered with no `clear()` /
    double-fire concern.
    """
    if action != "post_add":
        return
    mcp_group_pks = _mcp_group_pks()
    if not mcp_group_pks:
        return
    if not reverse:
        # Forward: `instance` is a User, `pk_set` is the Group pks added.
        if set(mcp_group_pks) & (pk_set or set()):
            _alert_mcp_group_grant({instance.pk}, mcp_group_pks)
    # Reverse: `instance` is a Group, `pk_set` is the User pks added
    # (e.g. `group.user_set.add(user)`).
    elif instance.pk in mcp_group_pks:
        _alert_mcp_group_grant(set(pk_set or set()), mcp_group_pks)
