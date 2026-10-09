"""Revocation and cohort alerts on a multi-database install (review round 17).

A real second database (`settings.SECOND_DB_ALIAS`, same server): the user is
saved to one database while the OAuth tokens live in another, or a router
sends the token models elsewhere.

- A password change commits on the database the user is saved to; the
  revocation then runs in a transaction of its own. Before, its deletes and
  audit row ran inside whatever transaction this thread had open on the
  token database, and a rollback there (`ATOMIC_REQUESTS`, an `atomic()`
  around the view) undid them although the password change stood. Logout
  likewise (its revocation waits for the default database).
- The three token deletes run on `db_for_write(AccessToken)`, the database
  DOT keeps its tokens on, whatever a router says per model.
- The cohort-grant alert reads the user, groups and memberships on the
  database the membership change was written to.
"""

import logging
import re
import secrets
import time
from datetime import timedelta

import pytest
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.signals import user_logged_out
from django.db import DatabaseError
from django.db import connections
from django.db import transaction
from django.utils import timezone
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.tests.factories import UserFactory
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Application
from oauth2_provider.models import Grant
from oauth2_provider.models import RefreshToken

SECOND = getattr(django_settings, "SECOND_DB_ALIAS", "second")

pytestmark = [
    pytest.mark.skipif(
        SECOND not in django_settings.DATABASES,
        reason="needs the second database alias of the package's test settings",
    ),
    pytest.mark.django_db(transaction=True, databases=["default", SECOND]),
]

_NEW_PASSWORD = "a-brand-new-password-17"


class TokensOnSecond:
    """Every OAuth and mcp_sql model on the second database."""

    def _route(self, model):
        if model._meta.app_label in ("oauth2_provider", "mcp_sql"):
            return SECOND
        return None

    def db_for_read(self, model, **hints):
        return self._route(model)

    def db_for_write(self, model, **hints):
        return self._route(model)


class RefreshAndGrantWritesOnSecond:
    """Splits DOT's models: refresh-token and grant writes to the second
    database, access tokens (and the rows themselves) on the default one."""

    def db_for_write(self, model, **hints):
        if model in (RefreshToken, Grant):
            return SECOND
        return None


def _routers(*first: type) -> list[str]:
    return [f"{__name__}.{r.__name__}" for r in first] + [
        "mcp_sql.db_router.McpSqlRouter"
    ]


@pytest.fixture(autouse=True)
def _no_session_gate(settings):
    settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}


# Watchdog (review round 18). The revocation's own connection can wait on a
# lock the test's connection holds while that connection, in the same
# thread, waits for it: a regression there (no bounded wait, the original
# connection not put back) hung the suite. PostgreSQL ends a session left
# idle inside a transaction this long, which releases the lock, so such a
# regression fails the test instead.
_WATCHDOG = "10s"


@pytest.fixture(autouse=True)
def _idle_transaction_watchdog():
    for alias in ("default", SECOND):
        with connections[alias].cursor() as cursor:
            cursor.execute(f"SET idle_in_transaction_session_timeout = '{_WATCHDOG}'")
    yield
    for alias in ("default", SECOND):
        connection = connections[alias]
        try:
            with connection.cursor() as cursor:
                cursor.execute("RESET idle_in_transaction_session_timeout")
        except DatabaseError:
            connection.close()


@pytest.fixture
def own_connections(monkeypatch):
    """Each connection `_outside_open_transaction` opens, with the SQL run
    on it."""
    opened: list[tuple[object, list[str]]] = []
    create = connections.create_connection

    def recording(alias):
        connection = create(alias)
        statements: list[str] = []

        def record(execute, sql, params, many, context):
            statements.append(sql)
            return execute(sql, params, many, context)

        connection.execute_wrappers.append(record)
        opened.append((connection, statements))
        return connection

    monkeypatch.setattr(connections, "create_connection", recording)
    return opened


def _application(using: str) -> Application:
    return Application.objects.db_manager(using).create(
        name=mcp_sql_settings.APPLICATION_NAME,
        client_id="mcp-sql",
        client_secret="",
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="http://127.0.0.1",
        algorithm="",
    )


def _credentials(user, using: str) -> None:
    """An access token, a refresh token and a pending code on `using`."""
    app = _application(using)
    access = AccessToken.objects.db_manager(using).create(
        user=user,
        token=secrets.token_urlsafe(24),
        application=app,
        expires=timezone.now() + timedelta(hours=1),
        scope="mcp:sql",
    )
    RefreshToken.objects.db_manager(using).create(
        user=user,
        token=secrets.token_urlsafe(24),
        application=app,
        access_token=access,
    )
    Grant.objects.db_manager(using).create(
        user=user,
        code=secrets.token_urlsafe(24),
        application=app,
        expires=timezone.now() + timedelta(minutes=1),
        redirect_uri="http://127.0.0.1",
        scope="mcp:sql",
        code_challenge="x" * 43,
        code_challenge_method="S256",
    )


def _copy_user(user, using: str):
    """The same user row on `using` (the FK target there)."""
    copy = get_user_model()._base_manager.using("default").get(pk=user.pk)
    copy.save(using=using, force_insert=True)
    return get_user_model()._base_manager.using(using).get(pk=user.pk)


def _remaining(user, using: str) -> dict[str, int]:
    return {
        "access": AccessToken.objects.using(using).filter(user_id=user.pk).count(),
        "refresh": RefreshToken.objects.using(using).filter(user_id=user.pk).count(),
        "grant": Grant.objects.using(using).filter(user_id=user.pk).count(),
    }


def _audited(user, using: str, reason) -> bool:
    return (
        MCPAuthRejectionLog.objects.using(using)
        .filter(user_id=user.pk, reason=reason)
        .exists()
    )


def _then_roll_back(using: str, work) -> None:
    """Run `work` inside a transaction on `using` that then rolls back (as
    a request that fails after the write would)."""
    with transaction.atomic(using=using):
        work()
        raise RuntimeError


_ALL = {"access": 1, "refresh": 1, "grant": 1}
_NONE = {"access": 0, "refresh": 0, "grant": 0}


class TestPasswordChangeOnAnotherDatabase:
    """The user is saved to the second database; tokens and the audit
    table are on the default one."""

    @pytest.fixture
    def user(self):
        user = UserFactory()
        _credentials(user, "default")
        return _copy_user(user, SECOND)

    def _change(self, user) -> None:
        user.set_password(_NEW_PASSWORD)
        user.save()  # to SECOND (`user._state.db`), autocommit there

    def test_a_rollback_on_the_token_database_does_not_undo_it(self, user):
        with pytest.raises(RuntimeError):
            # The change commits on SECOND; the default transaction rolls back.
            _then_roll_back("default", lambda: self._change(user))
        stored = get_user_model()._base_manager.using(SECOND).get(pk=user.pk)
        assert stored.check_password(_NEW_PASSWORD)
        assert _remaining(user, "default") == _NONE
        assert _audited(user, "default", AuthRejectionReason.PASSWORD_CHANGE)

    def test_a_commit_on_the_token_database(self, user):
        with transaction.atomic(using="default"):
            self._change(user)
        assert _remaining(user, "default") == _NONE
        assert _audited(user, "default", AuthRejectionReason.PASSWORD_CHANGE)

    def test_a_rollback_of_the_change_itself_revokes_nothing(self, user):
        with pytest.raises(RuntimeError):
            _then_roll_back(SECOND, lambda: self._change(user))
        assert _remaining(user, "default") == _ALL
        assert not MCPAuthRejectionLog.objects.exists()

    def test_a_lock_the_open_transaction_holds_is_waited_for_briefly(
        self, user, monkeypatch, caplog
    ):
        """The open transaction on the token database locked a row the
        revocation deletes. The revocation's own connection would wait for
        it forever (same thread); it gives up after the bounded wait, logs
        the failure (no audit row: the access did not end) and the request
        goes on."""
        from mcp_sql import signals

        monkeypatch.setattr(signals, "_OWN_CONNECTION_LOCK_TIMEOUT", "200ms")
        started = time.monotonic()
        with (
            caplog.at_level(logging.ERROR, logger="mcp_sql.signals"),
            transaction.atomic(using="default"),
        ):
            AccessToken.objects.filter(user_id=user.pk).update(scope="mcp:sql")
            self._change(user)
        assert time.monotonic() - started < 5
        assert "Failed to revoke MCP tokens on password change" in caplog.text
        assert _remaining(user, "default") == _ALL
        assert not MCPAuthRejectionLog.objects.exists()

    def test_the_own_connection(self, user, own_connections):
        """Review round 18: the lock bound is `SET LOCAL` (a bare `SET`
        would outlive the transaction), the connection is closed, and the
        original one is back in place inside the still-open transaction."""
        from mcp_sql import signals

        with transaction.atomic(using="default"):
            original = connections["default"]
            self._change(user)
            current = connections["default"]
            in_atomic = original.in_atomic_block
        assert current is original
        assert in_atomic
        assert len(own_connections) == 1
        own, statements = own_connections[0]
        assert own is not original
        assert own.connection is None  # closed
        assert statements[0] == (
            f"SET LOCAL lock_timeout = '{signals._OWN_CONNECTION_LOCK_TIMEOUT}'"
        )
        assert not [s for s in statements if re.match(r"\s*SET\s+(?!LOCAL\b)", s)]
        assert _remaining(user, "default") == _NONE
        assert _audited(user, "default", AuthRejectionReason.PASSWORD_CHANGE)

    def test_no_own_connection_outside_a_transaction(self, user, own_connections):
        self._change(user)
        assert own_connections == []
        assert _remaining(user, "default") == _NONE


class TestLogoutWithTokensOnAnotherDatabase:
    """Logout's revocation waits for the default database; a router keeps
    the tokens and the audit table on the second one."""

    @pytest.fixture
    def user(self, settings):
        user = UserFactory()
        _credentials(_copy_user(user, SECOND), SECOND)
        settings.DATABASE_ROUTERS = _routers(TokensOnSecond)
        return user

    def test_a_rollback_on_the_token_database_does_not_undo_it(self, user):
        with pytest.raises(RuntimeError):
            _then_roll_back(
                SECOND,
                lambda: user_logged_out.send(
                    sender=type(user), request=None, user=user
                ),
            )
        assert _remaining(user, SECOND) == _NONE
        assert _audited(user, SECOND, AuthRejectionReason.SESSION_LOGOUT)


class TestTokenModelsSplitByARouter:
    def test_every_delete_runs_where_the_access_tokens_are(self, settings):
        """DOT keeps its token models in one database (foreign keys) and
        opens its token transactions on `db_for_write(AccessToken)`; a
        router naming another alias for refresh tokens and grants must not
        send their deletes to a database that does not hold them."""
        user = UserFactory()
        _credentials(user, "default")
        settings.DATABASE_ROUTERS = _routers(RefreshAndGrantWritesOnSecond)
        user.set_password(_NEW_PASSWORD)
        user.save()
        assert _remaining(user, "default") == _NONE


class TestCohortAlertOnAnotherDatabase:
    def test_the_alert_names_the_user_on_the_database_written(self, caplog):
        """The same pk is another person on the default database; the
        alert reads the user, groups and memberships where the membership
        change was written."""
        here = UserFactory()
        there = get_user_model()._base_manager.using("default").get(pk=here.pk)
        there.username = there.email = "mallory-second@example.com"
        there.save(using=SECOND, force_insert=True)
        profile = next(iter(mcp_sql_settings.profiles().values()))
        group = Group.objects.db_manager(SECOND).create(name=profile.group_name)
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            there.groups.add(group)
        alerts = [
            r.getMessage()
            for r in caplog.records
            if r.getMessage().startswith("MCP cohort change")
        ]
        assert alerts == [
            f"MCP cohort change: {there.get_username()} (pk={there.pk}) GAINED "
            f"MCP access via profile group(s) [{profile.name}] — confirm this "
            "grant was authorized."
        ]
