"""Signal receivers: revoke MCP tokens on user_logged_out and on a password
change; provision the per-profile groups/permissions on post_migrate; alert
(Sentry ERROR) when a user is added to an MCP profile group (and, layered on
top, when the addition leaves them in >1 profile = ambiguous); log a WARNING
on grants drift after post_migrate (advisory only — apply happens via
`mcp_sql_grants --apply`). See `docs/architecture.md` file-map row for
`signals.py`."""

import functools
import logging
from collections.abc import Iterator
from contextlib import ExitStack
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING
from typing import Any

from django.apps import AppConfig
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group
from django.contrib.auth.signals import user_logged_out
from django.db import DEFAULT_DB_ALIAS
from django.db import DatabaseError
from django.db import connections
from django.db import router
from django.db import transaction
from django.db.models import Q
from django.db.models.signals import m2m_changed
from django.db.models.signals import post_migrate
from django.db.models.signals import post_save
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.http import HttpRequest
from django.utils import timezone
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.grants import GrantsReconcileError
from mcp_sql.grants import reconcile_grants
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.models import audit_client_ip
from mcp_sql.schemas import AuthRejectionReason

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

User = get_user_model()


@receiver(user_logged_out)
def revoke_mcp_tokens_on_logout(
    sender: object,
    request: HttpRequest | None,
    user: "AbstractBaseUser | None",
    **kwargs: object,
) -> None:
    if user is None:
        # Anonymous logout (rare but allowed by Django) — nothing to revoke.
        return
    # Defer the revocation to `on_commit` so a failure in it can NEVER abort
    # the logout transaction — the user must always be able to log out. The
    # delete + audit run only after the logout commits; if the logout itself
    # rolls back, no tokens are revoked (consistent: the user isn't logged
    # out either). The signal carries no database alias, so this waits for
    # the default database's transaction: where a database session backend
    # writes unless a router sends sessions elsewhere — then a rollback of
    # the session database's transaction does not hold the revocation back.
    # A transaction open on the token database does not undo it
    # (`_revoke_and_audit`). `request` and the timestamp are read
    # synchronously (the callback fires outside the request scope); `user`
    # is captured by reference and stays valid post-commit — logout does
    # not delete the user row, so its `pk` and the audit FK resolve fine.
    # `started_at` is the logout moment, not the (marginally later)
    # post-commit callback time.
    client_ip = (
        audit_client_ip(request.META.get("REMOTE_ADDR"))
        if request is not None
        else None
    )
    logged_out_at = timezone.now()
    transaction.on_commit(
        lambda: _revoke_and_audit_on_logout(
            user=user, client_ip=client_ip, logged_out_at=logged_out_at
        ),
        using=DEFAULT_DB_ALIAS,
    )


def _revoke_and_audit_on_logout(*, user, client_ip, logged_out_at):
    """Post-commit logout revocation; see `_revoke_and_audit`."""
    _revoke_and_audit(
        user=user,
        client_ip=client_ip,
        at=logged_out_at,
        reason=AuthRejectionReason.SESSION_LOGOUT,
        event="logout",
        committed=DEFAULT_DB_ALIAS,
    )


# How long a revocation run on its own connection (see
# `_outside_open_transaction`) waits for a row lock before giving up. The
# lock it would wait for may be held by the very transaction it steps
# around (same thread: it would wait forever), so it must not wait long.
_OWN_CONNECTION_LOCK_TIMEOUT = "5s"


@contextmanager
def _outside_open_transaction(alias: str, committed: str) -> Iterator[bool]:
    """Make `connections[alias]` a connection with no transaction of this
    thread's open on it, for the duration; yield whether it is a new one.

    The revocation runs once the transaction on `committed` (the alias the
    triggering write went to) has committed. On that alias nothing of ours
    is open then. On another alias, this thread may be inside an unrelated
    transaction (`ATOMIC_REQUESTS`, an `atomic()` around the view); work
    done on that connection would join it and be undone by its rollback,
    although the password change or logout stands. So, in that case only,
    the work runs on a new connection to the same database, in its own
    transaction, and the original connection is put back afterwards.
    That connection does not see what the open transaction has written
    and not yet committed, and waits for row locks that transaction holds
    (bounded: `_OWN_CONNECTION_LOCK_TIMEOUT` on PostgreSQL)."""
    current = connections[alias]
    if alias == committed or not current.in_atomic_block:
        yield False
        return
    own = connections.create_connection(alias)
    connections[alias] = own
    try:
        yield True
    finally:
        try:
            own.close()
        finally:
            connections[alias] = current


@contextmanager
def _transaction(alias: str, *, own_connection: bool) -> Iterator[None]:
    """`transaction.atomic(using=alias)`, with a bounded lock wait on a
    connection `_outside_open_transaction` opened."""
    with transaction.atomic(using=alias):
        connection = connections[alias]
        if own_connection and connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SET LOCAL lock_timeout = '{_OWN_CONNECTION_LOCK_TIMEOUT}'"
                )
        yield


def _revoke_and_audit(*, user, client_ip, at, reason, event, committed):  # noqa: PLR0913
    """Best-effort post-commit MCP token revocation + a forensic audit row.

    Deletes the user's MCP-purpose access tokens, refresh tokens (they
    exist only when `MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]` enables them;
    one left behind would mint new access tokens) and pending authorization
    codes (`Grant` rows: a code issued just before would otherwise still
    exchange for a fresh token) in one transaction, and in that same
    transaction writes one `MCPAuthRejectionLog` row with `reason` — only
    when something was deleted: the table records access that ended, and a
    logout or password change of a user who held no MCP token or code ended
    none.

    Runs after the triggering transaction (logout, password change) on the
    alias `committed` has committed. What is guaranteed from then on:
    - the deletes and the audit row commit in a transaction of their own,
      never inside another transaction this thread has open on the token
      or audit database (`_outside_open_transaction`), so a later rollback
      there cannot undo them;
    - the audit row commits only with the deletes (when both live on one
      database; on two, it commits just before them); it is written in a
      savepoint, so a failure to write it — a database error or any other
      exception — is rolled back to that savepoint, logged with
      `logger.exception` (Sentry), and does not undo the deletes. When
      that savepoint cannot be rolled back either (the connection failed),
      the deletes cannot commit: that is a failed deletion;
    - a failed deletion (a database error, a row lock held past the
      bounded wait, the connection lost before the commit) rolls back all
      three deletes and writes no audit row: the access did not end. It is
      logged with `logger.exception` only and nothing is retried: the
      tokens then live until they expire, and an operator must delete
      them. "Revoked ..." is logged (INFO) only after the deletes
      committed;
    - no exception leaves this function. When no transaction is open the
      callback runs inside `logout()` (before the session is flushed) or
      inside the user's `save()`; an error escaping would turn the
      completed logout / password change into a 500.
    Not covered: tokens the open transaction itself created and has not
    committed (the own connection cannot see them).
    """
    # Lazy import keeps `apps.ready()` import-graph small.
    from oauth2_provider.models import AccessToken
    from oauth2_provider.models import Grant
    from oauth2_provider.models import RefreshToken

    # Match BOTH the curated `mcp-sql` Application (exact name) AND every
    # DCR-minted `mcp-sql-<token>` Application (prefix). The prefix carries
    # a trailing dash, so a `startswith` on it does NOT match the canonical
    # name — that's why the Q-OR is required here.
    mcp_apps = Q(application__name=mcp_sql_settings.APPLICATION_NAME) | Q(
        application__name__startswith=mcp_sql_settings.APPLICATION_NAME_PREFIX
    )
    # DOT's token models reference each other and their Application by
    # foreign key, so they live in one database; DOT opens its own token
    # transactions on `db_for_write(AccessToken)` (`save_bearer_token`,
    # `RefreshToken.revoke`). All three deletes run there, explicitly, so
    # they are one transaction whatever a router says per model.
    tokens = router.db_for_write(AccessToken)
    audit = router.db_for_write(MCPAuthRejectionLog)
    audit_failed = False
    try:
        with ExitStack() as stack:
            own = {
                alias: stack.enter_context(_outside_open_transaction(alias, committed))
                for alias in dict.fromkeys((tokens, audit))
            }
            with _transaction(tokens, own_connection=own[tokens]):
                refresh_deleted, _ = (
                    RefreshToken.objects.using(tokens)
                    .filter(mcp_apps, user=user)
                    .delete()
                )
                access_deleted, _ = (
                    AccessToken.objects.using(tokens)
                    .filter(mcp_apps, user=user)
                    .delete()
                )
                grants_deleted, _ = (
                    Grant.objects.using(tokens).filter(mcp_apps, user=user).delete()
                )
                deleted = access_deleted + refresh_deleted
                if not (deleted or grants_deleted):
                    return
                # Record the revocation in the access-ending audit table
                # alongside the per-request gate denials, so the timeline of
                # why a user lost MCP access is complete.
                try:
                    # Nested in the deletes' transaction (one database), a
                    # savepoint: anything raised in it rolls back to the
                    # savepoint, never the deletes. On a separate audit
                    # database, a transaction of its own.
                    with _transaction(audit, own_connection=own[audit]):
                        # By pk: the user instance may come from another
                        # database than the audit table's (a router would
                        # refuse the cross-database relation).
                        MCPAuthRejectionLog.objects.using(audit).create(
                            user_id=user.pk,
                            token_pk="",
                            application_name="",
                            reason=reason,
                            error=(
                                f"Revoked {deleted} MCP token(s) and "
                                f"{grants_deleted} pending authorization "
                                f"code(s) on {event}"
                            ),
                            client_ip=client_ip,
                            started_at=at,
                        )
                except Exception:
                    if connections[tokens].needs_rollback:
                        # The savepoint could not be rolled back (the
                        # connection failed; Django also sets the flag when
                        # it closes a connection inside `atomic`): the
                        # deletes' transaction can only roll back now, which
                        # Django would do without raising on leaving it. A
                        # failed revocation, not a missing audit row.
                        raise
                    audit_failed = True
                    logger.exception(
                        "Revoking MCP tokens on %s for user %s: failed to write "
                        "the audit row",
                        event,
                        user.pk,
                    )
    except Exception:
        logger.exception(
            "Failed to revoke MCP tokens on %s for user %s", event, user.pk
        )
        return
    logger.info(
        "Revoked %d MCP token(s) and %d pending authorization code(s) on %s "
        "for user %s%s",
        deleted,
        grants_deleted,
        event,
        user.pk,
        " (no audit row)" if audit_failed else "",
    )


# Per-instance flag from `pre_save` to `post_save` for a pending revocation.
_PENDING_REVOCATION_ATTR = "_mcp_sql_password_changed"


@receiver(pre_save)
def note_password_change(sender, instance, **kwargs):
    """Flag a saved user whose password hash is about to change.

    A password change (the user's own, an admin reset, `set_unusable_password`)
    ends every other credential the old password stood behind, so the MCP
    access and refresh tokens and pending authorization codes go too (ledger
    F15) — via model signals, with no dependency on a session table, so it
    holds with `SESSION_MODEL=None`. Bulk `QuerySet.update(password=...)`
    and `QuerySet.bulk_update(users, ["password"])` send no signals and are
    not seen; revoke tokens explicitly there.

    Connected without a `sender` and filtered with `isinstance`: Django sends
    `pre_save` / `post_save` with the class that was saved, so a proxy of the
    user model (e.g. an admin registered on one) would slip past
    `sender=User`. Not a change:
    - saves whose `update_fields` omit `password` (e.g. `update_last_login`
      on every login), skipped without a lookup;
    - Django's login-time hash upgrade (`_is_hash_upgrade`).
    The flag is reset first on every save, so one from a save that then
    failed cannot leak into a later save of the same instance.
    """
    if not isinstance(instance, User):
        return
    setattr(instance, _PENDING_REVOCATION_ATTR, False)
    update_fields = kwargs.get("update_fields")
    if kwargs.get("raw") or instance.pk is None:
        return
    if update_fields is not None and "password" not in update_fields:
        return
    # The stored hash, read through the base manager on the alias being
    # written: a consumer's default manager may filter rows (active users
    # only, soft delete), and a hidden row would read as "no stored hash"
    # and skip the revocation — reactivating a user with a new password
    # is exactly such a save. A multi-database install writes the user on
    # `using`, which need not be the default database.
    old = (
        User._base_manager.db_manager(kwargs.get("using"))
        .filter(pk=instance.pk)
        .values_list("password", flat=True)
        .first()
    )
    if old is None or old == instance.password:
        return
    if _is_hash_upgrade(instance, old, update_fields):
        return
    setattr(instance, _PENDING_REVOCATION_ATTR, True)


def _is_hash_upgrade(
    instance: "AbstractBaseUser", old: str, update_fields: "Iterable[str] | None"
) -> bool:
    """True only for the save `AbstractBaseUser.check_password` makes when it
    re-hashes the SAME password (a login after the preferred hasher or its
    parameters changed): its setter saves with `update_fields=["password"]`
    while `check_password` runs for this very instance, which
    `install_password_check_marker` records — and the hash it checked is the
    one stored (`old`). Otherwise the instance carried a different, unsaved
    hash (a legacy hash for a new password assigned in memory and then
    checked, review round 5), and the save stores a new password.

    That is positive evidence, not an inference from the save's shape: a
    real change written as `user.password = make_password(new);
    user.save(update_fields=["password"])` (SSO / LDAP sync, imports, a
    scripted reset) — even through `set_password`, even on an instance
    whose stored hash needs upgrading — happens outside `check_password`,
    so it revokes (review round 4). A user model that overrides
    `check_password` without calling `super()` never sets the marker; its
    hash upgrades then revoke too (the safe direction)."""
    checking = _CHECKING_PASSWORD.get()
    return (
        update_fields is not None
        and set(update_fields) == {"password"}
        and checking is not None
        and checking[0] is instance
        and checking[1] == old
    )


# While `AbstractBaseUser.check_password` runs: the instance and the hash it
# is checking the password against.
_CHECKING_PASSWORD: ContextVar[tuple[object, str] | None] = ContextVar(
    "mcp_sql_checking_password", default=None
)
_MARKED = "_mcp_sql_marks_password_check"


def install_password_check_marker() -> None:
    """Wrap `AbstractBaseUser.check_password` (and `acheck_password`, Django
    5.0+) so that, while it runs, `_CHECKING_PASSWORD` holds the instance
    and the hash being checked.
    Behaviour is unchanged; the wrapper only sets and resets the context
    variable. Idempotent. Called from `McpSqlConfig.ready()`."""
    check = AbstractBaseUser.check_password
    if not getattr(check, _MARKED, False):
        setattr(AbstractBaseUser, "check_password", _marked(check))  # noqa: B010
    acheck = getattr(AbstractBaseUser, "acheck_password", None)
    if acheck is not None and not getattr(acheck, _MARKED, False):
        setattr(AbstractBaseUser, "acheck_password", _amarked(acheck))  # noqa: B010


def _marked(check: "Callable[..., bool]") -> "Callable[..., bool]":
    @functools.wraps(check)
    def check_password(self: AbstractBaseUser, raw_password: Any) -> bool:
        token = _CHECKING_PASSWORD.set((self, self.password))
        try:
            return check(self, raw_password)
        finally:
            _CHECKING_PASSWORD.reset(token)

    setattr(check_password, _MARKED, True)
    return check_password


def _amarked(acheck: "Callable[..., Any]") -> "Callable[..., Any]":
    @functools.wraps(acheck)
    async def acheck_password(self: AbstractBaseUser, raw_password: Any) -> bool:
        token = _CHECKING_PASSWORD.set((self, self.password))
        try:
            correct: bool = await acheck(self, raw_password)
            return correct
        finally:
            _CHECKING_PASSWORD.reset(token)

    setattr(acheck_password, _MARKED, True)
    return acheck_password


@receiver(post_save)
def revoke_mcp_tokens_on_password_change(sender, instance, created, **kwargs):
    """Revoke the user's MCP tokens once a password change commits.

    Deferred to `on_commit` like the logout revocation, so a failure in it
    can never abort the password change; if the change rolls back, nothing
    is revoked.
    """
    if not getattr(instance, _PENDING_REVOCATION_ATTR, False):
        return
    setattr(instance, _PENDING_REVOCATION_ATTR, False)
    changed_at = timezone.now()
    # On the alias the user was saved to: the revocation waits for THAT
    # transaction, and runs only if it commits. A transaction open on
    # another alias does not hold it back or undo it
    # (`_outside_open_transaction`).
    using = kwargs.get("using")
    transaction.on_commit(
        lambda: _revoke_and_audit(
            user=instance,
            client_ip=None,
            at=changed_at,
            reason=AuthRejectionReason.PASSWORD_CHANGE,
            event="password change",
            committed=using,
        ),
        using=using,
    )


@receiver(post_migrate)
def provision_mcp_profiles(sender: AppConfig | None, **kwargs: object) -> None:
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
def provision_mcp_cloud_clients(sender: AppConfig | None, **kwargs: object) -> None:
    """Materialise one OAuth `Application` row per `MCP_SQL["CLOUD_CLIENTS"]`
    entry (opt-in cloud-client support).

    Full login flow + provider onboarding: `docs/oauth.md` → "Cloud clients".

    Same config-derived, idempotent shape as `provision_mcp_profiles`:
    settings is the source of truth; the row exists ONLY to satisfy DOT's
    non-null `Grant` / `AccessToken` FK to `Application` (a client_id must
    resolve to a real row before a code/token can be persisted). Reuses the
    curated migration-0005 posture (public client, authorization-code, PKCE,
    no secret) EXCEPT `skip_authorization=False`: a cloud client's non-loopback
    redirect makes the consent screen load-bearing — it is what breaks the
    silent-GET phishing chain the loopback rule otherwise prevents.

    `update_or_create` keeps the row's stored `redirect_uris` in sync with
    settings on every migrate. Rows for entries later REMOVED from settings are
    deliberately NOT deleted here: recognition is settings-gated
    (`consts.is_mcp_application_name` only accepts a cloud client while its
    entry is present), so a removed client is denied at the next request
    regardless of a lingering row, and logout revocation still covers it via
    the `mcp-sql-` prefix. Empty CLOUD_CLIENTS (the default) is a no-op.

    Fires under the same full-plan `migrate` assumption as
    `provision_mcp_profiles` — `oauth2_provider`'s tables exist by the time
    any `post_migrate` is emitted.
    """
    if sender is None or getattr(sender, "label", None) != "mcp_sql":
        return
    using = kwargs.get("using")
    if using and using != "default":
        return

    from oauth2_provider.models import Application

    for client in mcp_sql_settings.cloud_clients().values():
        Application.objects.update_or_create(
            client_id=client.client_id,
            defaults={
                "name": client.client_id,
                "client_secret": "",
                "client_type": Application.CLIENT_PUBLIC,
                "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
                # Consent required for cloud clients — see docstring.
                "skip_authorization": False,
                "redirect_uris": client.redirect_uri,
                "algorithm": "",
            },
        )
        # Surface the value the operator must paste into the provider's
        # connector, at the moment they run `migrate` — the derived client_id
        # is otherwise easy to miss. (Also findable via `docs/oauth.md` and
        # `mcp_sql_settings.cloud_clients()`.)
        logger.info(
            "MCP cloud client %r provisioned — paste client_id %r into your "
            "provider's connector as the OAuth Client ID (leave the secret "
            "blank); callback %s.",
            client.name,
            client.client_id,
            client.redirect_uri,
        )


@receiver(post_migrate)
def audit_grants_drift_after_migrate(
    sender: AppConfig | None, **kwargs: object
) -> None:
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


def _mcp_group_pks(using: str) -> dict[int, str]:
    """Map each existing MCP profile group's pk → its profile name, on the
    database the membership change was written to (`using`).

    Cohort grants are rare (admin actions), so a per-event query is fine.
    Empty on a fresh DB before `provision_mcp_profiles` ran, so the receiver
    no-ops instead of crashing the m2m save.
    """
    name_to_profile = {
        p.group_name: p.name for p in mcp_sql_settings.profiles().values()
    }
    return {
        g.pk: name_to_profile[g.name]
        for g in Group.objects.db_manager(using)
        .filter(name__in=name_to_profile)
        .only("pk", "name")
    }


def _user_label(user: "AbstractBaseUser") -> str:
    """`get_username()` (the email here), guarded so an alert never raises."""
    try:
        return user.get_username()
    except Exception:  # noqa: BLE001 — an alert path must never raise
        return "?"


def _mcp_memberships(
    user_ids: set[int], mcp_group_pks: dict[int, str], using: str
) -> dict[int, list[str]]:
    """`{user_id: sorted [profile_name, ...]}` — each user's current MCP
    profile-group memberships. Per-user queries; cohort changes are rare."""
    out: dict[int, list[str]] = {}
    for uid in user_ids:
        try:
            pks = (
                Group.objects.db_manager(using)
                .filter(user__pk=uid, pk__in=mcp_group_pks)
                .values_list("pk", flat=True)
            )
            out[uid] = sorted(mcp_group_pks[pk] for pk in pks)
        except DatabaseError:
            logger.exception("MCP membership query failed for user pk=%s", uid)
            out[uid] = []
    return out


def _alert_mcp_group_grant(
    user_ids: set[int], mcp_group_pks: dict[int, str], using: str
) -> None:
    """Page once per user who gained an MCP profile group on `using` (the
    database the membership change was written to: the users, groups and
    memberships are read there, so a multi-database install names the user
    the grant was made to, not a same-pk user elsewhere)."""
    if not user_ids:
        return
    memberships = _mcp_memberships(user_ids, mcp_group_pks, using)
    try:
        users = {
            u.pk: u
            for u in User._base_manager.db_manager(using).filter(pk__in=user_ids)
        }
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
    using = kwargs.get("using", DEFAULT_DB_ALIAS)
    mcp_group_pks = _mcp_group_pks(using)
    if not mcp_group_pks:
        return
    if not reverse:
        # Forward: `instance` is a User, `pk_set` is the Group pks added.
        if set(mcp_group_pks) & (pk_set or set()):
            _alert_mcp_group_grant({instance.pk}, mcp_group_pks, using)
    # Reverse: `instance` is a Group, `pk_set` is the User pks added
    # (e.g. `group.user_set.add(user)`).
    elif instance.pk in mcp_group_pks:
        _alert_mcp_group_grant(set(pk_set or set()), mcp_group_pks, using)
