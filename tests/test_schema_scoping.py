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

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test.utils import CaptureQueriesContext
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
_PUBLIC = ("public", _TABLE)
_SHADOWED = (_SHADOW, _TABLE)


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
        assert _PUBLIC in granted
        assert _SHADOWED in granted

    def test_the_inventory_skips_temporary_relations(self):
        # A grant on a temporary table (schema `pg_temp_<n>`) is not drift:
        # the relation ends with the session that made it.
        with connection.cursor() as cur:
            cur.execute("CREATE TEMP TABLE mcp_sql_a17_tmp (id int)")
            cur.execute(f"GRANT SELECT ON pg_temp.mcp_sql_a17_tmp TO {_ROLE}")
            cur.execute(
                "SELECT table_schema FROM information_schema.role_table_grants"
                " WHERE grantee = %s AND table_name = 'mcp_sql_a17_tmp'",
                [_ROLE],
            )
            assert cur.fetchone()[0].startswith("pg_temp_")
        assert not [
            r for r in grants.granted_tables(_ROLE) if r[1] == "mcp_sql_a17_tmp"
        ]

    @pytest.mark.parametrize("search_path", ["public", "mcp_sql_a16_shadow, public"])
    def test_check_reports_and_apply_revokes(self, search_path):
        # Whatever the app role's own `search_path`: GRANT / REVOKE name the
        # relation schema-qualified.
        with connection.cursor() as cur:
            cur.execute(f"SET LOCAL search_path = {search_path}")
        drift = grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=False)
        assert _SHADOWED in drift.revoked
        assert _PUBLIC not in drift.revoked
        assert drift.granted == []

        grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=True)
        granted = grants.granted_tables(_ROLE)
        assert _SHADOWED not in granted
        assert _PUBLIC in granted
        assert (
            grants._reconcile_profile(
                _DEFAULT_PROFILE, strict=True, apply=False
            ).revoked
            == []
        )

    @pytest.mark.parametrize("search_path", ["public", "mcp_sql_a16_shadow, public"])
    def test_a_missing_grant_is_granted_on_the_public_relation(self, search_path):
        with connection.cursor() as cur:
            cur.execute("REVOKE SELECT ON public.mcp_sql_a16_t FROM mcp_readonly_role")
            cur.execute(f"SET LOCAL search_path = {search_path}")
        drift = grants._reconcile_profile(_DEFAULT_PROFILE, strict=True, apply=True)
        assert drift.granted == [_PUBLIC]
        granted = grants.granted_tables(_ROLE)
        assert _PUBLIC in granted
        assert _SHADOWED not in granted


@pytest.mark.usefixtures("shadowed")
class TestViewParityProbe:
    def test_view_parity_reads_the_relation_in_its_schema(self, monkeypatch):
        # A same-named relation with other columns first on the app role's
        # `search_path` must not be what the parity probe reads.
        view = "mcp_widget_second_profile"
        monkeypatch.setattr(
            "mcp_sql.grants.declared_tables",
            lambda _profile: {"mcp_sql_testapp.MCPWidgetSecondProfileView": view},
        )
        with connection.cursor() as cur:
            cur.execute(
                f"CREATE VIEW public.{view} AS"  # noqa: S608
                " SELECT id, name FROM mcp_sql_testapp_widget"
            )
            cur.execute(f"CREATE TABLE {_SHADOW}.{view} (other int)")
            cur.execute(f"SET LOCAL search_path = {_SHADOW}, public")
        grants._verify_view_parity(_DEFAULT_PROFILE)


@pytest.mark.usefixtures("shadowed")
class TestSmokeNamesTheRelation:
    """`mcp_sql_smoke` reads (and tries to write) the relation a `db_table`
    names, in either spelling Django accepts for a schema-qualified table
    (round 17; before, `"s"."t"` became `""s"."t""`)."""

    @pytest.mark.parametrize(
        "db_table",
        [
            f'{_SHADOW}"."{_TABLE}',
            f'"{_SHADOW}"."{_TABLE}"',
        ],
    )
    def test_read_and_write_probes(self, db_table):
        from mcp_sql.management.commands.mcp_sql_smoke import Command

        command = Command(stdout=StringIO())
        command._verify_read_path(_DEFAULT_PROFILE, db_table)
        command._verify_write_rejected(_DEFAULT_PROFILE, db_table)
        assert "SELECT FROM" in command.stdout.getvalue()


_OWNER = "mcp_sql_a17_owner"
_OWNED = "mcp_a17o"
# Names a role that owns a schema can give its relations (round 17).
_INJECTION = f'x" FROM {_ROLE}; CREATE TABLE {_OWNED}.p (); --'
_DOTTED = 'a"."b'


class TestCatalogNamesAreQuoted:
    """Review round 17: the drift inventory reads relation names from the
    catalog, where the owner of any schema chooses them. Before, they were
    joined into `schema"."name` and interpolated unescaped: `--apply` ran a
    name carrying `" FROM r; …` as SQL (as the operator's role), and a name
    containing `"."` became a three-part name that PostgreSQL rejected,
    rolling back every revoke of the run."""

    @pytest.fixture(autouse=True)
    def _crafted(self, monkeypatch):
        # A managed model (no view parity probe) standing for the one
        # whitelisted relation.
        monkeypatch.setattr(
            "mcp_sql.grants.declared_tables",
            lambda _profile: {"mcp_sql_testapp.Widget": _TABLE},
        )
        with connection.cursor() as cur:
            cur.execute(f"CREATE TABLE public.{_TABLE} (id int)")
            cur.execute(f"GRANT SELECT ON public.{_TABLE} TO {_ROLE}")
            cur.execute(f"CREATE ROLE {_OWNER} NOLOGIN")
            cur.execute(f"CREATE SCHEMA {_OWNED} AUTHORIZATION {_OWNER}")
            cur.execute(f"SET LOCAL ROLE {_OWNER}")
            for name in (_INJECTION, _DOTTED):
                quoted = name.replace('"', '""')
                relation = f'{_OWNED}."{quoted}"'
                cur.execute(f"CREATE TABLE {relation} (id int)")
                cur.execute(f"GRANT SELECT ON {relation} TO {_ROLE}")
            cur.execute("RESET ROLE")

    def _revokes(self):
        return {
            f'REVOKE SELECT ON "{_OWNED}"."x"" FROM {_ROLE}; CREATE TABLE '  # noqa: S608
            f'{_OWNED}.p (); --" FROM {_ROLE};',
            f'REVOKE SELECT ON "{_OWNED}"."a"".""b" FROM {_ROLE};',  # noqa: S608
        }

    def _relations(self, cur, schema):
        cur.execute(
            "SELECT relname FROM pg_class c JOIN pg_namespace n"
            " ON n.oid = c.relnamespace WHERE nspname = %s",
            [schema],
        )
        return {name for (name,) in cur.fetchall()}

    def test_the_check_prints_quoted_revokes(self):
        out = StringIO()
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", stdout=out)
        printed = set(out.getvalue().splitlines())
        assert self._revokes() <= printed
        assert f'"{_OWNED}"."a"".""b"' in str(exc.value)

    def test_apply_revokes_them_and_runs_nothing_else(self):
        with CaptureQueriesContext(connection) as ran:
            call_command("mcp_sql_grants", "--apply", stdout=StringIO())
        statements = {
            q["sql"] for q in ran.captured_queries if q["sql"].startswith("REVOKE")
        }
        assert self._revokes() <= statements
        assert grants.granted_tables(_ROLE) == {("public", _TABLE)}
        with connection.cursor() as cur:
            assert self._relations(cur, _OWNED) == {_INJECTION, _DOTTED}
        out = StringIO()
        call_command("mcp_sql_grants", stdout=out)
        assert "Grants in sync" in out.getvalue()


class TestOverlongDbTable:
    """Review round 18: PostgreSQL truncates a name longer than 63 bytes
    (on a character boundary), so the catalog lists the truncated name.
    A declared `db_table` that long never matched the inventory: each
    `--apply` granted the declared name (PostgreSQL granted the truncated
    relation) and revoked the truncated one, every run. Such a `db_table`
    is refused instead."""

    @pytest.fixture
    def declared(self, monkeypatch):
        def declare(db_table):
            monkeypatch.setattr(
                "mcp_sql.grants.declared_tables",
                lambda _profile: {"mcp_sql_testapp.Widget": db_table},
            )
            with connection.cursor() as cur:
                cur.execute(f'CREATE TABLE public."{db_table}" (id int)')
                cur.execute(f'GRANT SELECT ON public."{db_table}" TO {_ROLE}')
                cur.execute(
                    "SELECT table_name FROM information_schema.role_table_grants"
                    " WHERE grantee = %s AND table_schema = 'public'",
                    [_ROLE],
                )
                return {name for (name,) in cur.fetchall()}

        return declare

    @pytest.mark.parametrize(
        "db_table",
        [
            "mcp_sql_a18_" + "l" * 52,  # 64 bytes
            "mcp_sql_a18_" + "é" * 26,  # 38 characters, 64 bytes
        ],
    )
    @pytest.mark.parametrize("apply", [False, True])
    def test_refused(self, declared, db_table, apply):
        before = declared(db_table)
        truncated = db_table.encode()[:63].decode("utf-8", "ignore")
        assert truncated in before
        assert db_table not in before
        args = ["--apply"] if apply else []
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", *args, stdout=StringIO())
        assert "63-byte identifier limit" in str(exc.value)
        assert "mcp_sql_testapp.Widget" in str(exc.value)
        assert grants.granted_tables(_ROLE) >= {("public", truncated)}

    def test_63_bytes_is_in_sync_after_apply(self, declared):
        db_table = "mcp_sql_a18_" + "é" * 25 + "x"  # 63 bytes
        assert db_table in declared(db_table)
        call_command("mcp_sql_grants", "--apply", stdout=StringIO())
        for _ in range(2):
            out = StringIO()
            call_command("mcp_sql_grants", stdout=out)
            assert "Grants in sync" in out.getvalue()
        assert grants.granted_tables(_ROLE) == {("public", db_table)}


class TestARefusedProfileChangesNoGrant:
    """Review round 19. The code-level checks (a self-referential or an
    overlong entry) ran inside the per-profile loop, so with several
    profiles `--apply` had already granted and revoked for the profiles
    before the refused one. Every profile is now checked before any grant
    changes, and all of them apply in one transaction."""

    _TABLE = "mcp_sql_a19_widget"

    @pytest.fixture
    def two_profiles(self, settings, monkeypatch):
        """Profile `a` (the default role) has drift: its table is not
        granted. Profile `b` comes after it."""
        tables = {"a": {"mcp_sql_testapp.Widget": self._TABLE}}
        monkeypatch.setattr(
            "mcp_sql.grants.declared_tables",
            lambda profile: tables.get(profile.name, {}),
        )
        with connection.cursor() as cur:
            cur.execute(f"CREATE TABLE public.{self._TABLE} (id int)")

        def configure(b_models, b_tables):
            tables["b"] = b_tables
            settings.MCP_SQL = {
                **settings.MCP_SQL,
                "PROFILES": {
                    "a": {
                        "ROLE": _ROLE,
                        "PERMISSION_CODENAME": "use_mcp_session",
                        "GROUP_NAME": "mcp_sql_users",
                        "ALLOWED_MODELS": ["mcp_sql_testapp.Widget"],
                    },
                    "b": {
                        "ROLE": "mcp_sql_a19_b",
                        "PERMISSION_CODENAME": "use_mcp_session_a19_b",
                        "GROUP_NAME": "mcp_sql_a19_b",
                        "ALLOWED_MODELS": b_models,
                    },
                },
            }

        return configure

    @pytest.mark.parametrize(
        ("b_models", "b_tables", "message"),
        [
            (
                ["mcp_sql_testapp.Widget"],
                {"mcp_sql_testapp.Widget": "mcp_sql_a19_" + "l" * 52},
                "63-byte identifier limit",
            ),
            (["mcp_sql.MCPQueryLog"], {}, "Refusing to grant on mcp_sql models"),
        ],
    )
    def test_the_profile_before_it_is_not_applied(
        self, two_profiles, b_models, b_tables, message
    ):
        two_profiles(b_models, b_tables)
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", "--apply", stdout=StringIO())
        assert message in str(exc.value)
        assert ("public", self._TABLE) not in grants.granted_tables(_ROLE)

    def test_both_profiles_apply_when_both_pass(self, two_profiles):
        two_profiles(["mcp_sql_testapp.Widget"], {})
        with connection.cursor() as cur:
            cur.execute("CREATE ROLE mcp_sql_a19_b NOLOGIN")
        call_command("mcp_sql_grants", "--apply", stdout=StringIO())
        assert ("public", self._TABLE) in grants.granted_tables(_ROLE)
