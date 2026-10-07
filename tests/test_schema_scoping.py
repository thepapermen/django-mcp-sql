"""The whitelist names a relation in a schema, not a bare name (review round 16).

A whitelisted `db_table` is a relation in `public` (or in the schema a
`db_table` written `schema"."name` names). Before round 16 the parser matched
the bare name only, so `SELECT secret FROM analytics.<whitelisted name>` read
a same-named relation in another schema whenever the role held SELECT on it
(an accidental `GRANT SELECT ON ALL TABLES IN SCHEMA analytics`), and the
drift check, which listed `public` only, never reported that grant. An
unqualified name resolved through the login's `search_path` (`"$user"`,
database / role settings, a temporary table first), which the read
transaction now pins to `public, pg_temp`.

End to end on Postgres: a real second schema holding a same-named table the
read role can SELECT.
"""

import pytest
from django.db import connection
from mcp_sql import grants
from mcp_sql.executor import run_query
from mcp_sql.schemas import OutcomeReason
from mcp_sql.session import enter_readonly_session
from mcp_sql.tests.factories import UserFactory
from mcp_sql.tests.test_executor import _DEFAULT_PROFILE

pytestmark = pytest.mark.django_db

_TABLE = "mcp_sql_a16_t"
_SHADOW = "mcp_sql_a16_shadow"
_ROLE = _DEFAULT_PROFILE.role


def _make_copy(cur, schema: str, value: str) -> None:
    cur.execute(f"CREATE SCHEMA {schema}")
    cur.execute(f"CREATE TABLE {schema}.{_TABLE} (id int, name text, secret text)")
    insert = f"INSERT INTO {schema}.{_TABLE} VALUES (1, %s, 'S-{schema}')"  # noqa: S608
    cur.execute(insert, [value])
    cur.execute(f"GRANT USAGE ON SCHEMA {schema} TO {_ROLE}")
    cur.execute(f"GRANT SELECT ON {schema}.{_TABLE} TO {_ROLE}")


@pytest.fixture
def shadowed(settings, monkeypatch):
    """`public.<t>` (whitelisted) and a same-named `<shadow>.<t>`, both
    readable by the read role; everything rolls back with the test."""
    settings.MCP_SQL = {**settings.MCP_SQL, "DB_ALIAS": "default"}
    monkeypatch.setattr(
        "mcp_sql.executor.declared_tables", lambda _profile: {"x.T": _TABLE}
    )
    with connection.cursor() as cur:
        cur.execute("CREATE TABLE public.mcp_sql_a16_t (id int, name text)")
        cur.execute("INSERT INTO public.mcp_sql_a16_t VALUES (1, 'public')")
        cur.execute("GRANT SELECT ON public.mcp_sql_a16_t TO mcp_readonly_role")
        _make_copy(cur, _SHADOW, "shadow")


def _run(sql: str):
    return run_query(
        user=UserFactory(), profile=_DEFAULT_PROFILE, raw_sql=sql, limit=10
    )


@pytest.mark.usefixtures("shadowed")
class TestQualifiedReferences:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT secret FROM mcp_sql_a16_shadow.mcp_sql_a16_t",
            "SELECT name FROM mcp_sql_a16_shadow.mcp_sql_a16_t",
            'SELECT name FROM "mcp_sql_a16_shadow"."mcp_sql_a16_t"',
            "SELECT s.name FROM mcp_sql_a16_t p"
            " JOIN mcp_sql_a16_shadow.mcp_sql_a16_t s ON s.id = p.id",
            "SELECT name FROM mcp_sql_a16_t"
            " WHERE id IN (SELECT id FROM mcp_sql_a16_shadow.mcp_sql_a16_t)",
        ],
    )
    def test_the_same_name_in_another_schema_is_refused(self, sql):
        result = _run(sql)
        assert result.rejection_reason == OutcomeReason.DISALLOWED_TABLE, result
        assert result.rows == []

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT name FROM mcp_sql_a16_t",
            "SELECT name FROM public.mcp_sql_a16_t",
            'SELECT name FROM "public"."mcp_sql_a16_t"',
            "SELECT name FROM PUBLIC.mcp_sql_a16_t",
        ],
    )
    def test_the_whitelisted_relation_is_read(self, sql):
        result = _run(sql)
        assert result.rejection_reason == "", (result.rejection_reason, result.error)
        assert result.rows == [["public"]]


@pytest.mark.usefixtures("shadowed")
class TestUnqualifiedNamesResolveToPublic:
    """`FROM <t>` is the relation in `public` whatever the login's
    `search_path` says: the read transaction pins it."""

    def test_the_profile_roles_own_schema(self):
        # The default `search_path` is `"$user", public`; under `SET ROLE`,
        # `$user` is the profile role, so a schema named after it came first.
        with connection.cursor() as cur:
            _make_copy(cur, _ROLE, "user-schema")
        assert _run("SELECT name FROM mcp_sql_a16_t").rows == [["public"]]

    def test_a_login_search_path(self):
        # As a database- / role-level setting or a connection option would.
        with connection.cursor() as cur:
            cur.execute("SET LOCAL search_path = mcp_sql_a16_shadow, public")
        result = _run("SELECT name FROM mcp_sql_a16_t")
        assert result.rows == [["public"]], (result.rejection_reason, result.error)

    def test_a_temporary_table(self):
        # Unlisted, `pg_temp` is searched first for relations.
        with connection.cursor() as cur:
            cur.execute("CREATE TEMP TABLE mcp_sql_a16_t (id int, name text)")
            cur.execute("INSERT INTO pg_temp.mcp_sql_a16_t VALUES (1, 'temp')")
            cur.execute("GRANT SELECT ON pg_temp.mcp_sql_a16_t TO mcp_readonly_role")
        assert _run("SELECT name FROM mcp_sql_a16_t").rows == [["public"]]

    def test_the_session_pins_it(self):
        with connection.cursor() as cur:
            cur.execute("SET LOCAL search_path = mcp_sql_a16_shadow, public")
            enter_readonly_session(cur, role=_ROLE)
            cur.execute("SHOW search_path")
            assert cur.fetchone() == ("public, pg_temp",)


@pytest.mark.usefixtures("shadowed")
class TestDriftSeesEverySchema:
    """A SELECT grant to a profile role on a relation outside `public` is
    drift: reported by the check, revoked by `--apply`."""

    @pytest.fixture(autouse=True)
    def _declared(self, monkeypatch):
        monkeypatch.setattr(
            "mcp_sql.grants.declared_tables", lambda _profile: {"x.T": _TABLE}
        )
        monkeypatch.setattr("mcp_sql.grants._verify_view_parity", lambda _profile: None)

    def test_the_inventory_lists_other_schemas(self):
        granted = grants.granted_tables(_ROLE)
        assert _TABLE in granted
        assert 'mcp_sql_a16_shadow"."mcp_sql_a16_t' in granted

    def test_check_reports_and_apply_revokes(self):
        drift = grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=False)
        assert 'mcp_sql_a16_shadow"."mcp_sql_a16_t' in drift.revoked
        assert _TABLE not in drift.revoked
        assert drift.granted == []

        grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=True)
        granted = grants.granted_tables(_ROLE)
        assert 'mcp_sql_a16_shadow"."mcp_sql_a16_t' not in granted
        assert _TABLE in granted
        assert (
            grants._reconcile_profile(
                _DEFAULT_PROFILE, strict=True, apply=False
            ).revoked
            == []
        )

    def test_a_missing_grant_is_granted_on_the_public_relation(self):
        with connection.cursor() as cur:
            cur.execute("REVOKE SELECT ON public.mcp_sql_a16_t FROM mcp_readonly_role")
        drift = grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=True)
        assert drift.granted == [_TABLE]
        assert _TABLE in grants.granted_tables(_ROLE)
