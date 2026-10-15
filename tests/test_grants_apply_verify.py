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


_MV = "mcp_sql_fu6_mv"


@pytest.fixture
def matview(monkeypatch):
    """A materialized view, whitelisted (as a managed model's table, so no
    view-parity probe) and not yet granted."""
    monkeypatch.setattr(
        "mcp_sql.grants.declared_tables",
        lambda _profile: {"mcp_sql_testapp.Widget": _MV},
    )
    with connection.cursor() as cur:
        cur.execute(f"CREATE MATERIALIZED VIEW public.{_MV} AS SELECT 1 AS id")


class TestMaterializedViews:
    """`information_schema.role_table_grants` lists no materialized views,
    so with it as the inventory a whitelisted one was drift on every run;
    once `--apply` re-read its grants, `--apply` failed on it too although
    its GRANT had applied. The inventory reads the catalog's ACLs now."""

    def test_apply_grants_and_verifies_it(self, matview):
        out = _apply()
        assert "Applied: +1 grant(s), -0 revoke(s)" in out
        assert grants.granted_tables(_ROLE) == {("public", _MV)}
        check = StringIO()
        call_command("mcp_sql_grants", stdout=check)
        assert "Grants in sync" in check.getvalue()

    def test_a_silent_no_op_still_fails_naming_it(self, unowned, matview, notices):
        with connection.cursor() as cur:
            revoke = f"REVOKE SELECT ON public.{_STALE} FROM {_ROLE}"  # noqa: S608
            cur.execute(revoke)
            cur.execute(f"ALTER MATERIALIZED VIEW public.{_MV} OWNER TO {_OWNER}")
            cur.execute(f"GRANT SELECT ON public.{_MV} TO {_LOGIN}")
        _as_login()
        with pytest.raises(CommandError) as exc:
            _apply()
        _reset_role()
        assert any("no privileges were granted" in n for n in notices), notices
        assert f'still not granted: {_MV} (owner "{_OWNER}")' in str(exc.value)
        assert ("public", _MV) not in grants.granted_tables(_ROLE)

    def test_an_undeclared_grant_on_one_is_drift(self, matview):
        """The other half of what the view hid: check mode reports, and
        `--apply` revokes, a grant on a materialized view nothing declares."""
        with connection.cursor() as cur:
            cur.execute("CREATE MATERIALIZED VIEW public.mcp_sql_fu6_mv2 AS SELECT 1")
            cur.execute(f"GRANT SELECT ON public.mcp_sql_fu6_mv2 TO {_ROLE}")
        with pytest.raises(
            CommandError, match="granted but not declared: mcp_sql_fu6_mv2"
        ):
            call_command("mcp_sql_grants", stdout=StringIO())
        _apply()
        assert grants.granted_tables(_ROLE) == {("public", _MV)}


class TestTheInventoryIsTheViewsForOtherKinds:
    """For tables, views and partitioned tables the catalog inventory lists
    exactly what `information_schema.role_table_grants` lists: check mode's
    output is unchanged by the switch."""

    def test_same_rows(self, unowned):
        with connection.cursor() as cur:
            cur.execute("CREATE SCHEMA mcp_sql_fu6_s")
            cur.execute("CREATE TABLE mcp_sql_fu6_s.t (id int)")
            cur.execute("CREATE VIEW public.mcp_sql_fu6_v AS SELECT 1 AS id")
            cur.execute(
                "CREATE TABLE public.mcp_sql_fu6_p (id int) PARTITION BY RANGE (id)"
            )
            cur.execute(
                "CREATE TABLE public.mcp_sql_fu6_p1 PARTITION OF public.mcp_sql_fu6_p"
                " FOR VALUES FROM (0) TO (10)"
            )
            cur.execute("CREATE TABLE public.mcp_sql_fu6_ins (id int)")
            for relation in (
                "mcp_sql_fu6_s.t",
                "public.mcp_sql_fu6_v",
                "public.mcp_sql_fu6_p",
            ):
                cur.execute(f"GRANT SELECT ON {relation} TO {_ROLE}")
            # Not SELECT: in neither.
            cur.execute(f"GRANT INSERT ON public.mcp_sql_fu6_ins TO {_ROLE}")
            # Owned by the role: its implicit privileges, in both.
            cur.execute("CREATE TABLE public.mcp_sql_fu6_owned (id int)")
            cur.execute(f"ALTER TABLE public.mcp_sql_fu6_owned OWNER TO {_ROLE}")
            cur.execute(
                r"""
                SELECT table_schema, table_name
                FROM information_schema.role_table_grants
                WHERE grantee = %s AND privilege_type = 'SELECT'
                  AND table_schema NOT IN ('pg_catalog', 'information_schema')
                  AND table_schema NOT LIKE 'pg\_%%'
                """,
                [_ROLE],
            )
            view = {(str(a), str(b)) for a, b in cur.fetchall()}
        assert ("public", "mcp_sql_fu6_owned") in view
        assert ("mcp_sql_fu6_s", "t") in view
        assert grants.granted_tables(_ROLE) == view
