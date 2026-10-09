"""`mcp_sql_grants --apply` verifies what it applied.

PostgreSQL does not fail a GRANT or REVOKE the executing role may not make:
on a relation the app login neither owns nor holds `WITH GRANT OPTION` on
but holds some privilege on (the app's own read/write grants on tables a
migration role owns; the profile role's SELECT, through membership), GRANT
warns "no privileges were granted" and REVOKE "no privileges could be
revoked", and nothing changes. (With no privilege at all it fails with
"permission denied", which already stopped `--apply`.) `--apply` printed
`Applied: … -N revoke(s)` and exited 0 all the same, while check mode
reported the same drift on every run (review: soltys-m). The suite's own
grants tests run as the CI superuser, which may change any privilege, so
they could not see it.

Here the apply path runs as a non-superuser login (`SET LOCAL ROLE`, which
makes it `current_user` for every privilege check PostgreSQL makes) against
relations another role owns, and the test asserts PostgreSQL really emitted
the WARNING: the failure is the database's, not a mock's.
"""

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from mcp_sql import grants
from mcp_sql.grants import GrantsReconcileError
from mcp_sql.tests.test_executor import _DEFAULT_PROFILE

pytestmark = pytest.mark.django_db

_ROLE = _DEFAULT_PROFILE.role
_OWNER = "mcp_sql_fu6_owner"
_LOGIN = "mcp_sql_fu6_login"
_DECLARED = "mcp_sql_fu6_declared"
_STALE = "mcp_sql_fu6_stale"
_OWN_STALE = "mcp_sql_fu6_own_stale"


@pytest.fixture
def notices():
    """The messages PostgreSQL sends this connection (WARNINGs included)."""
    connection.ensure_connection()
    raw = connection.connection
    if not hasattr(raw, "add_notice_handler"):
        pytest.skip("needs psycopg 3 (the `test` extra installs it)")
    seen: list[str] = []

    def handler(diag) -> None:
        seen.append(diag.message_primary)

    raw.add_notice_handler(handler)
    yield seen
    raw.remove_notice_handler(handler)


@pytest.fixture
def unowned(monkeypatch):
    """A login (not a superuser, a member of the profile role, as
    `role_setup` makes the app login) with read/write grants on relations
    another role owns, as when migrations run as a separate owner role:
    `_DECLARED`, whitelisted (once a test adds it) and not granted,
    `_STALE`, granted to the profile role (by its owner) and not
    whitelisted, and `_OWN_STALE`. Everything — roles included — rolls back
    with the test."""
    declared: dict[str, str] = {}
    monkeypatch.setattr("mcp_sql.grants.declared_tables", lambda _profile: declared)
    with connection.cursor() as cur:
        cur.execute(f"CREATE ROLE {_OWNER} NOLOGIN")
        cur.execute(f"CREATE ROLE {_LOGIN} NOLOGIN")
        cur.execute(f"GRANT {_ROLE} TO {_LOGIN}")
        for table in (_DECLARED, _STALE, _OWN_STALE):
            cur.execute(f"CREATE TABLE public.{table} (id int)")
            cur.execute(f"ALTER TABLE public.{table} OWNER TO {_OWNER}")
            dml = "SELECT, INSERT, UPDATE, DELETE"
            cur.execute(f"GRANT {dml} ON public.{table} TO {_LOGIN}")
        cur.execute(f"GRANT SELECT ON public.{_STALE} TO {_ROLE}")
    return declared


def _as_login() -> None:
    with connection.cursor() as cur:
        cur.execute(f"SET LOCAL ROLE {_LOGIN}")


def _reset_role() -> None:
    with connection.cursor() as cur:
        cur.execute("RESET ROLE")


def _apply() -> str:
    out = StringIO()
    call_command("mcp_sql_grants", "--apply", stdout=out)
    return out.getvalue()


class TestApplyAsALoginThatOwnsNothing:
    def test_an_unrevokable_grant_fails_the_apply(self, unowned, notices):
        _as_login()
        with pytest.raises(CommandError) as exc:
            _apply()
        _reset_role()
        assert any("no privileges could be revoked" in n for n in notices), notices
        message = str(exc.value)
        assert f'[default] still granted: {_STALE} (owner "{_OWNER}")' in message
        assert repr(_LOGIN) in message
        assert ("public", _STALE) in grants.granted_tables(_ROLE)

    def test_an_ungrantable_relation_fails_the_apply(self, unowned, notices):
        unowned["mcp_sql_testapp.Widget"] = _DECLARED
        with connection.cursor() as cur:
            revoke = f"REVOKE SELECT ON public.{_STALE} FROM {_ROLE}"  # noqa: S608
            cur.execute(revoke)
        _as_login()
        with pytest.raises(CommandError) as exc:
            _apply()
        _reset_role()
        assert any("no privileges were granted" in n for n in notices), notices
        assert f'[default] still not granted: {_DECLARED} (owner "{_OWNER}")' in str(
            exc.value
        )
        assert ("public", _DECLARED) not in grants.granted_tables(_ROLE)

    def test_the_statements_that_did_apply_are_rolled_back(self, unowned):
        # The login owns `_OWN_STALE`, so its REVOKE works — and is undone
        # with the rest, as a refusal of any profile changes no grant.
        with connection.cursor() as cur:
            cur.execute(f"ALTER TABLE public.{_OWN_STALE} OWNER TO {_LOGIN}")
            cur.execute(f"GRANT SELECT ON public.{_OWN_STALE} TO {_ROLE}")
        _as_login()
        with pytest.raises(GrantsReconcileError, match=_STALE) as exc:
            grants.reconcile_grants(strict=True, apply=True)
        _reset_role()
        assert _OWN_STALE not in str(exc.value)
        assert {("public", _STALE), ("public", _OWN_STALE)} <= grants.granted_tables(
            _ROLE
        )

    def test_check_mode_still_reports_the_drift(self, unowned):
        _as_login()
        with pytest.raises(CommandError):
            _apply()
        with pytest.raises(CommandError, match=f"granted but not declared: {_STALE}"):
            call_command("mcp_sql_grants", stdout=StringIO())


class TestApplyAsTheOwner:
    """The success path, as a non-superuser that owns what it changes."""

    def test_applies_reports_and_is_in_sync(self, unowned, notices):
        unowned["mcp_sql_testapp.Widget"] = _DECLARED
        with connection.cursor() as cur:
            for table in (_DECLARED, _STALE):
                cur.execute(f"ALTER TABLE public.{table} OWNER TO {_LOGIN}")
        _as_login()
        out = _apply()
        assert "Applied: +1 grant(s), -1 revoke(s) across 1 profile(s)." in out
        assert not notices, notices
        assert grants.granted_tables(_ROLE) == {("public", _DECLARED)}
        check = StringIO()
        call_command("mcp_sql_grants", stdout=check)
        assert "Grants in sync" in check.getvalue()


class TestAMaterializedViewIsNamedAsSuch:
    """The inventory (`information_schema.role_table_grants`) lists no
    grants on a materialized view, so a whitelisted one is drift on every
    run (check mode included); `--apply` says why rather than blaming the
    owner."""

    def test_named(self, monkeypatch):
        monkeypatch.setattr(
            "mcp_sql.grants.declared_tables",
            lambda _profile: {"mcp_sql_testapp.Widget": "mcp_sql_fu6_mv"},
        )
        with connection.cursor() as cur:
            cur.execute(
                "CREATE MATERIALIZED VIEW public.mcp_sql_fu6_mv AS SELECT 1 AS id"
            )
        with pytest.raises(
            CommandError, match="a materialized view: information_schema"
        ):
            _apply()
