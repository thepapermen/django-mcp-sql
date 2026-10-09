"""Tests for the `mcp_sql.signals` receivers: `user_logged_out` → revoke MCP
tokens, and the `m2m_changed` MCP-group-grant alert."""

import logging
import secrets
from datetime import timedelta

import pytest
from django.contrib.auth.signals import user_logged_out
from django.test import RequestFactory
from django.utils import timezone
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP
from mcp_sql.tests.factories import UserFactory


def _logout_request():
    """A real `HttpRequest` that satisfies `axes`'s receiver expectations.

    `django-axes` listens on `user_logged_out` and reads `request.axes_ip_address`
    via its own middleware proxy. A bare `None` (or a non-axes-aware mock) makes
    its receiver raise `AttributeError`. Passing a real `RequestFactory` request
    keeps axes happy without needing to mock its internals.
    """
    return RequestFactory().get("/logout/")


def _mgr(*, filter_delete_return=(0, {}), filter_delete_side_effect=None):
    """A stand-in Django manager whose `.filter(...).delete()` returns a
    `(count, {})` pair (or raises), for driving the receivers' DatabaseError
    branches without a real DB fault."""
    from unittest.mock import MagicMock

    manager = MagicMock()
    # `.using(alias)` / `.db_manager(alias)` hand back the same stand-in.
    manager.using.return_value = manager
    manager.db_manager.return_value = manager
    if filter_delete_side_effect is not None:
        manager.filter.return_value.delete.side_effect = filter_delete_side_effect
    else:
        manager.filter.return_value.delete.return_value = filter_delete_return
    return manager


@pytest.mark.django_db
class TestRevokeMcpTokensOnLogout:
    def _mint_token(self, user, mcp_app):
        from oauth2_provider.models import AccessToken

        return AccessToken.objects.create(
            user=user,
            token="test_" + secrets.token_urlsafe(16),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )

    def test_logout_deletes_only_calling_users_tokens(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        from oauth2_provider.models import AccessToken

        user_a = UserFactory()
        user_b = UserFactory()
        self._mint_token(user_a, mcp_app)
        self._mint_token(user_a, mcp_app)
        self._mint_token(user_b, mcp_app)

        # The revocation now runs in `transaction.on_commit`; capture+execute
        # so the deferred callback fires within the test transaction.
        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user_a), request=_logout_request(), user=user_a
            )

        assert AccessToken.objects.filter(user=user_a).count() == 0
        assert AccessToken.objects.filter(user=user_b).count() == 1
        assert "Revoked 2 MCP token(s)" in caplog.text

    def test_logout_does_not_delete_tokens_from_other_applications(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        """Scoping contract: logout deletes only `mcp-sql` Application
        tokens. If a second OAuth Application is ever added, the user's
        tokens for THAT Application must survive logout."""
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        other_app = Application.objects.create(
            name="other-app",
            client_id="other",
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1",
        )
        user = UserFactory()
        self._mint_token(user, mcp_app)
        AccessToken.objects.create(
            user=user,
            token="other_" + secrets.token_urlsafe(16),
            application=other_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="other:scope",
        )

        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        assert AccessToken.objects.filter(user=user, application=mcp_app).count() == 0
        assert AccessToken.objects.filter(user=user, application=other_app).count() == 1

    def test_logout_without_tokens_is_silent(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        user = UserFactory()
        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        # `signals.py` logs (and writes an audit row) only when `deleted > 0`.
        assert "Revoked" not in caplog.text

    def test_logout_writes_session_logout_audit_row(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        from mcp_sql.models import MCPAuthRejectionLog
        from mcp_sql.schemas import AuthRejectionReason

        user = UserFactory()
        self._mint_token(user, mcp_app)
        self._mint_token(user, mcp_app)

        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        row = MCPAuthRejectionLog.objects.get(user=user)
        assert row.reason == AuthRejectionReason.SESSION_LOGOUT.value
        assert "Revoked 2 MCP token(s)" in row.error
        # No single token/application — it's a bulk, user-scoped revocation.
        assert row.token_pk == ""
        assert row.application_name == ""

    def test_logout_without_tokens_writes_no_audit_row(
        self, mcp_app, django_capture_on_commit_callbacks
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        assert not MCPAuthRejectionLog.objects.filter(user=user).exists()

    def test_anonymous_logout_is_a_noop(self):
        # Sanity: the `if user is None: return` guard fires without raising.
        # Invoking the handler directly bypasses axes (which can't handle
        # anonymous logout without further setup).
        from mcp_sql.signals import revoke_mcp_tokens_on_logout

        revoke_mcp_tokens_on_logout(sender=None, request=None, user=None)


def _cohort_alerts(caplog):
    return [r for r in caplog.records if "cohort change" in r.getMessage()]


@pytest.mark.django_db
class TestMcpGroupGrantAlert:
    """The `m2m_changed` receiver fires an ERROR only when a user is ADDED to
    the MCP group — gain-only, group-only by design."""

    def test_group_add_alerts(self, mcp_group, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(mcp_group)
        alerts = _cohort_alerts(caplog)
        assert len(alerts) == 1
        msg = alerts[0].getMessage()
        assert "GAINED" in msg
        assert user.get_username() in msg  # names the user (email)
        assert f"pk={user.pk}" in msg
        assert "default" in msg  # names the profile the user gained

    def test_group_add_names_a_user_the_default_manager_hides(
        self, mcp_group, caplog, monkeypatch
    ):
        """The alert names the user through the base manager, so a consumer
        `objects` manager that filters rows (active users only, soft delete)
        cannot turn the name into "?" (A14)."""
        user = UserFactory()
        user_model = type(user)

        class HidesEveryRow(type(user_model._default_manager)):  # type: ignore[misc]
            def get_queryset(self):
                return super().get_queryset().none()

        manager = HidesEveryRow()
        manager.model = user_model
        monkeypatch.setattr(user_model, "objects", manager, raising=False)
        monkeypatch.setattr(user_model._meta, "default_manager", manager)
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(mcp_group)
        (alert,) = _cohort_alerts(caplog)
        assert alert.getMessage().startswith(
            f"MCP cohort change: {user.get_username()} (pk={user.pk})"
        )

    def test_group_remove_is_silent(self, mcp_group, caplog):
        user = UserFactory()
        user.groups.add(mcp_group)  # the grant alert
        # caplog accumulates ERROR records for the whole test regardless of
        # `at_level`, so drop the grant alert before exercising the remove.
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.remove(mcp_group)
        # De-escalation is out of scope — only post_add fires.
        assert _cohort_alerts(caplog) == []

    def test_direct_permission_grant_is_silent(self, use_mcp_perm, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.user_permissions.add(use_mcp_perm)
        # Direct-permission grants are out of scope (group is the canonical path).
        assert _cohort_alerts(caplog) == []

    def test_unrelated_group_add_is_silent(self, mcp_group, caplog):
        from django.contrib.auth.models import Group

        other = Group.objects.create(name="some-other-group")
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(other)
        assert _cohort_alerts(caplog) == []

    def test_reverse_group_add_alerts(self, mcp_group, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            mcp_group.user_set.add(user)  # reverse direction
        alerts = _cohort_alerts(caplog)
        assert len(alerts) == 1
        assert f"pk={user.pk}" in alerts[0].getMessage()

    def test_two_profile_groups_fires_ambiguity_alert(self, two_profiles, caplog):
        """The paging alert (TIC-585): adding a user to a SECOND MCP profile
        group fires one extra ERROR — they are now ambiguous and will be denied
        until fixed. This is the assignment-time half of the alert split."""
        from django.contrib.auth.models import Group

        user = UserFactory()
        g_default = Group.objects.get(name="mcp_sql_users")
        g_second = Group.objects.get(name=SECOND_PROFILE_GROUP)
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(g_default, g_second)
        ambiguity = [r for r in caplog.records if "AMBIGUITY" in r.getMessage()]
        assert len(ambiguity) == 1
        msg = ambiguity[0].getMessage()
        assert f"pk={user.pk}" in msg
        assert "default" in msg
        assert "second_profile" in msg
        # The gain alert still fires exactly once (and lists both profiles).
        assert len(_cohort_alerts(caplog)) == 1

    def test_missing_group_is_noop(self, db, caplog):
        # No `mcp_group` fixture → the MCP group does not exist (mirrors a
        # fresh DB before migration 0004). The receiver must no-op, not crash.
        from django.contrib.auth.models import Group

        other = Group.objects.create(name="unrelated")
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(other)
        assert _cohort_alerts(caplog) == []


@pytest.mark.django_db
class TestProvisionMcpProfilesIdempotency:
    """The zero-data-migration upgrade story rests on `get_or_create`
    reasoning — pin it: re-running the receiver must neither duplicate nor
    mutate the Permission/Group rows."""

    def test_second_run_creates_nothing_new(self):
        from django.apps import apps as django_apps
        from django.contrib.auth.models import Group
        from django.contrib.auth.models import Permission
        from mcp_sql.signals import provision_mcp_profiles

        sender = django_apps.get_app_config("mcp_sql")
        provision_mcp_profiles(sender=sender)
        provision_mcp_profiles(sender=sender)

        assert (
            Permission.objects.filter(
                codename="use_mcp_session",
                content_type__app_label="mcp_sql",
                content_type__model="mcpquerylog",
            ).count()
            == 1
        )
        assert Group.objects.filter(name="mcp_sql_users").count() == 1
        group = Group.objects.get(name="mcp_sql_users")
        assert group.permissions.filter(codename="use_mcp_session").count() == 1

    def test_non_default_alias_is_skipped(self):
        # `provision_mcp_profiles` provisions only on the default alias; a
        # post_migrate on a replica/other alias must no-op (no DB touched).
        from django.apps import apps as django_apps
        from mcp_sql.signals import provision_mcp_profiles

        sender = django_apps.get_app_config("mcp_sql")
        provision_mcp_profiles(sender=sender, using="replica")


class TestAlertHelperGuards:
    """Pure-unit guards on the alert helpers — they must never raise, since an
    alert path failing would be worse than the privilege change it reports."""

    def test_user_label_falls_back_on_error(self):
        from unittest.mock import MagicMock

        from mcp_sql.signals import _user_label

        broken = MagicMock()
        broken.get_username.side_effect = RuntimeError("no username")
        assert _user_label(broken) == "?"

    def test_alert_with_no_user_ids_is_noop(self):
        from mcp_sql.signals import _alert_mcp_group_grant

        # Empty user set → returns immediately, no queries.
        _alert_mcp_group_grant(set(), {1: "default"}, "default")


@pytest.mark.django_db
class TestSignalDatabaseErrorResilience:
    """The logout revocation + audit and the cohort-alert membership lookups
    are best-effort: a DB blip is logged (Sentry via `logger.exception`) but
    never propagates — logout must always complete and an alert must never
    raise."""

    def test_token_delete_db_error_is_swallowed(self, monkeypatch, caplog):
        from django.db import DatabaseError
        from mcp_sql.signals import _revoke_and_audit_on_logout
        from oauth2_provider.models import AccessToken

        user = UserFactory()
        manager = _mgr(filter_delete_side_effect=DatabaseError("boom"))
        monkeypatch.setattr(AccessToken, "objects", manager)
        with caplog.at_level(logging.ERROR):
            _revoke_and_audit_on_logout(
                user=user, client_ip="1.2.3.4", logged_out_at=timezone.now()
            )
        assert "Failed to revoke MCP tokens on logout" in caplog.text

    def test_audit_write_db_error_is_swallowed(self, monkeypatch, caplog):
        import mcp_sql.signals as signals_mod
        from django.db import DatabaseError
        from mcp_sql.signals import _revoke_and_audit_on_logout
        from oauth2_provider.models import AccessToken

        user = UserFactory()
        # Deletion "succeeds" (1 token) so control reaches the audit write,
        # which then fails.
        manager = _mgr(filter_delete_return=(1, {}))
        monkeypatch.setattr(AccessToken, "objects", manager)
        audit = _mgr()
        audit.create.side_effect = DatabaseError("audit down")
        monkeypatch.setattr(signals_mod.MCPAuthRejectionLog, "objects", audit)
        with caplog.at_level(logging.ERROR):
            _revoke_and_audit_on_logout(
                user=user, client_ip=None, logged_out_at=timezone.now()
            )
        assert "failed to write the audit row" in caplog.text

    def test_membership_query_db_error_yields_empty(self, monkeypatch, caplog):
        import mcp_sql.signals as signals_mod
        from django.db import DatabaseError
        from mcp_sql.signals import _mcp_memberships

        group_mgr = _mgr()
        group_mgr.filter.side_effect = DatabaseError("groups down")
        monkeypatch.setattr(signals_mod.Group, "objects", group_mgr)
        with caplog.at_level(logging.ERROR):
            out = _mcp_memberships({7}, {10: "default"}, "default")
        assert out == {7: []}
        assert "MCP membership query failed" in caplog.text


def _mcp_credentials(user):
    """An access token, a refresh token and a pending code for `user` on
    the canonical `mcp-sql` Application."""
    from mcp_sql.conf import mcp_sql_settings
    from oauth2_provider.models import AccessToken
    from oauth2_provider.models import Application
    from oauth2_provider.models import Grant
    from oauth2_provider.models import RefreshToken

    app, _ = Application.objects.get_or_create(
        name=mcp_sql_settings.APPLICATION_NAME,
        defaults={
            "client_id": "mcp-sql",
            "client_secret": "",
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "redirect_uris": "http://127.0.0.1",
            "algorithm": "",
        },
    )
    access = AccessToken.objects.create(
        user=user,
        token=secrets.token_urlsafe(24),
        application=app,
        expires=timezone.now() + timedelta(hours=1),
        scope="mcp:sql",
    )
    RefreshToken.objects.create(
        user=user,
        token=secrets.token_urlsafe(24),
        application=app,
        access_token=access,
    )
    Grant.objects.create(
        user=user,
        code=secrets.token_urlsafe(24),
        application=app,
        expires=timezone.now() + timedelta(minutes=1),
        redirect_uri="http://127.0.0.1",
        scope="mcp:sql",
        code_challenge="x" * 43,
        code_challenge_method="S256",
    )


def _remaining_credentials(user) -> int:
    from oauth2_provider.models import AccessToken
    from oauth2_provider.models import Grant
    from oauth2_provider.models import RefreshToken

    return sum(
        model.objects.filter(user_id=user.pk).count()
        for model in (AccessToken, RefreshToken, Grant)
    )


def _logged_in_request(user, remote_addr="127.0.0.1"):
    """A request with a saved database session, as `logout()` gets it."""
    from django.contrib.sessions.backends.db import SessionStore

    request = RequestFactory().get("/logout/", REMOTE_ADDR=remote_addr)
    request.session = SessionStore()
    request.session["marker"] = "logged-in"
    request.session.save()
    request.user = user
    return request


@pytest.fixture
def _session_gate_off(settings):
    settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("_session_gate_off")
class TestNothingEscapesIntoLogout:
    """Review round 18. With no transaction open, the logout revocation
    runs inside `logout()` itself — `user_logged_out` is sent before the
    session is flushed — so anything it raised would 500 the logout and
    leave the session alive."""

    def test_a_forwarded_list_in_remote_addr(self, caplog):
        """A `REMOTE_ADDR` that is not one IP address (a real-IP
        middleware copying `X-Forwarded-For` whole): psycopg 3 adapts the
        `inet` value with `ipaddress.ip_address` and raised `ValueError`
        from the audit write, which rolled the deletes back and escaped
        `logout()`. The row is now written without the address."""
        from django.contrib.auth import logout
        from django.contrib.sessions.models import Session
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        _mcp_credentials(user)
        request = _logged_in_request(user, remote_addr="10.0.0.1, 10.0.0.2")
        session_key = request.session.session_key
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            logout(request)
        assert _remaining_credentials(user) == 0
        row = MCPAuthRejectionLog.objects.get(user=user)
        assert row.client_ip is None
        assert not Session.objects.filter(session_key=session_key).exists()
        assert "marker" not in request.session
        assert caplog.records == []

    def test_a_single_address_is_recorded(self):
        from django.contrib.auth import logout
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        _mcp_credentials(user)
        logout(_logged_in_request(user, remote_addr="2001:db8::7"))
        assert MCPAuthRejectionLog.objects.get(user=user).client_ip == "2001:db8::7"

    def test_an_error_outside_the_audit_write(self, monkeypatch, caplog):
        """Any exception in the revocation (here: not a database error) is
        logged; `logout()` completes and flushes the session."""
        from django.contrib.auth import logout
        from django.contrib.sessions.models import Session
        from oauth2_provider.models import RefreshToken

        user = UserFactory()
        _mcp_credentials(user)
        monkeypatch.setattr(
            RefreshToken,
            "objects",
            _mgr(filter_delete_side_effect=RuntimeError("not a database error")),
        )
        request = _logged_in_request(user)
        session_key = request.session.session_key
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            logout(request)
        assert "Failed to revoke MCP tokens on logout" in caplog.text
        assert not Session.objects.filter(session_key=session_key).exists()

    def test_an_error_before_the_deletes(self, settings, caplog):
        """Review round 20: the code before the deletes (a consumer router
        raising in `db_for_write`) ran outside the handler, so its error
        escaped `logout()` (a 500, the session kept)."""
        from django.contrib.auth import logout
        from django.contrib.sessions.models import Session

        user = UserFactory()
        _mcp_credentials(user)
        request = _logged_in_request(user)
        session_key = request.session.session_key
        settings.DATABASE_ROUTERS = [
            "mcp_sql.tests.test_signals._ExplodingTokenRouter",
            *settings.DATABASE_ROUTERS,
        ]
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            logout(request)
        assert "Failed to revoke MCP tokens on logout" in caplog.text
        assert "a consumer router" in caplog.text  # the traceback is logged
        assert not Session.objects.filter(session_key=session_key).exists()
        assert _remaining_credentials(user) == 3  # nothing was revoked


class _ExplodingTokenRouter:
    """A consumer router that fails for DOT's token model."""

    def db_for_write(self, model, **hints):
        if model._meta.label == "oauth2_provider.AccessToken":
            msg = "a consumer router exploded"
            raise RuntimeError(msg)


@pytest.mark.django_db
class TestAFailedAuditWriteKeepsTheDeletes:
    """Review round 18: the audit row is written in a savepoint inside the
    deletes' transaction; whatever makes it fail is rolled back to that
    savepoint, never the deletes."""

    def _logout(self, user, django_capture_on_commit_callbacks):
        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

    def test_a_database_error(self, caplog, django_capture_on_commit_callbacks):
        """A real failure in PostgreSQL (a constraint every new audit row
        violates), no mocks."""
        from django.db import connection
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        _mcp_credentials(user)
        table = MCPAuthRejectionLog._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                f'ALTER TABLE "{table}" ADD CONSTRAINT mcp_sql_a18_refuse_rows '
                "CHECK (false) NOT VALID"
            )
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            self._logout(user, django_capture_on_commit_callbacks)
        assert _remaining_credentials(user) == 0
        assert not MCPAuthRejectionLog.objects.filter(user=user).exists()
        assert "failed to write the audit row" in caplog.text
        assert "(no audit row)" in caplog.text

    def test_any_other_exception(
        self, monkeypatch, caplog, django_capture_on_commit_callbacks
    ):
        import mcp_sql.signals as signals_mod

        user = UserFactory()
        _mcp_credentials(user)
        audit = _mgr()
        audit.create.side_effect = ValueError("not a database error")
        monkeypatch.setattr(signals_mod.MCPAuthRejectionLog, "objects", audit)
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            self._logout(user, django_capture_on_commit_callbacks)
        assert _remaining_credentials(user) == 0
        assert "failed to write the audit row" in caplog.text
        assert "(no audit row)" in caplog.text


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("_session_gate_off")
class TestAConnectionLostDuringTheAuditWrite:
    """Review round 19. The connection dies while the audit row is written
    (one database): the savepoint cannot be rolled back, so Django rolls
    the deletes' transaction back on leaving it — without raising. That
    used to be logged as "Revoked N MCP token(s) ... (no audit row)" while
    every token survived; it is a failed revocation."""

    def test_the_failure_is_logged_as_a_failed_revocation(self, monkeypatch, caplog):
        import mcp_sql.signals as signals_mod
        from django.db import connection
        from django.db import connections
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        _mcp_credentials(user)
        real = MCPAuthRejectionLog.objects

        class _KillsItsConnection:
            """`.using(alias).create(...)` terminates the alias's backend
            first (from another connection), then writes."""

            def using(self, alias):
                manager = real.using(alias)

                class _Create:
                    def create(self, **fields):
                        with connections[alias].cursor() as cursor:
                            cursor.execute("SELECT pg_backend_pid()")
                            pid = cursor.fetchone()[0]
                        other = connections.create_connection(alias)
                        try:
                            with other.cursor() as cursor:
                                cursor.execute("SELECT pg_terminate_backend(%s)", [pid])
                        finally:
                            other.close()
                        return manager.create(**fields)

                return _Create()

        monkeypatch.setattr(
            signals_mod.MCPAuthRejectionLog, "objects", _KillsItsConnection()
        )
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            user_logged_out.send(
                sender=type(user), request=_logged_in_request(user), user=user
            )
        connection.close()  # the next query reconnects
        assert _remaining_credentials(user) == 3  # nothing was revoked
        messages = [record.getMessage() for record in caplog.records]
        assert not any(message.startswith("Revoked") for message in messages)
        [failure] = caplog.records
        assert failure.levelno == logging.ERROR
        assert failure.getMessage().startswith("Failed to revoke MCP tokens on logout")
        assert failure.exc_info is not None


@pytest.mark.django_db
class TestASaveSignalWithoutAnAlias:
    """Review round 20: a `post_save` sent without `using` (by hand, by a
    consumer) passed `committed=None`, so the revocation never counted as
    running on the database that committed: with a transaction open it
    ran on a separate connection, which does not see that transaction's
    rows. Django's own `on_commit(using=None)` means the default database;
    so does the revocation now."""

    def test_revokes_as_on_the_default_database(
        self, django_capture_on_commit_callbacks
    ):
        from django.db.models.signals import post_save
        from django.db.models.signals import pre_save

        user = UserFactory()
        _mcp_credentials(user)  # written by the test's open transaction
        user.set_password("a different one")
        with django_capture_on_commit_callbacks(execute=True):
            pre_save.send(sender=type(user), instance=user)
            post_save.send(sender=type(user), instance=user, created=False)
        assert _remaining_credentials(user) == 0
