from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError


class TestVerifyDefaultAlias:
    """REVIEW.md H3: every grants helper that uses the implicit
    `from django.db import connection` must assert it is the 'default'
    alias before doing any work. Symmetric with `executor.run_query`'s
    assertion that it's NOT on default. Prevents a future router /
    `using=...` refactor from silently routing grants reconciliation
    through `mcp_readonly` (NOLOGIN read-only — would fail opaquely)
    or any other alias.
    """

    def test_each_entry_point_raises_when_alias_is_not_default(self, monkeypatch):
        from mcp_sql import grants

        monkeypatch.setattr(grants.connection, "alias", "mcp_readonly")

        for callable_ in (
            grants.granted_tables,
            grants.role_exists,
            grants.has_role_membership,
        ):
            with pytest.raises(grants.GrantsReconcileError, match="'default' DB alias"):
                callable_("mcp_readonly_role")

        with pytest.raises(grants.GrantsReconcileError, match="'default' DB alias"):
            grants.reconcile_grants(strict=True, apply=False)


class TestRefuseSelfReferentialWhitelist:
    def test_default_mode_refuses_mcp_sql_entry(self, settings):
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "PROFILES": {
                "default": {
                    "ROLE": "mcp_readonly_role",
                    "PERMISSION_CODENAME": "use_mcp_session",
                    "GROUP_NAME": "mcp_sql_users",
                    "ALLOWED_MODELS": ["mcp_sql.MCPQueryLog"],
                }
            },
        }
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", stdout=StringIO())
        assert "Refusing to grant on mcp_sql models" in str(exc.value)

    def test_apply_mode_refuses_mcp_sql_entry(self, settings):
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "PROFILES": {
                "default": {
                    "ROLE": "mcp_readonly_role",
                    "PERMISSION_CODENAME": "use_mcp_session",
                    "GROUP_NAME": "mcp_sql_users",
                    "ALLOWED_MODELS": ["mcp_sql.MCPQueryLog"],
                }
            },
        }
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", "--apply", stdout=StringIO())
        assert "Refusing to grant on mcp_sql models" in str(exc.value)


@pytest.fixture
def patched_grants():
    """Patch every grants preflight + DB read so tests stay DB-free."""
    with (
        patch("mcp_sql.grants.role_exists") as role_exists,
        patch("mcp_sql.grants.has_role_membership") as has_membership,
        patch("mcp_sql.grants.declared_tables") as declared_tables,
        patch("mcp_sql.grants.granted_tables") as granted_tables,
    ):
        role_exists.return_value = True
        has_membership.return_value = True
        yield {
            "role_exists": role_exists,
            "has_membership": has_membership,
            "declared_tables": declared_tables,
            "granted_tables": granted_tables,
        }


def _run() -> str:
    """Run the read-only (default) mode of mcp_sql_grants."""
    out = StringIO()
    call_command("mcp_sql_grants", stdout=out)
    return out.getvalue()


class TestGrantsCheck:
    """Read-only / drift-gate behaviour: `mcp_sql_grants` without --apply."""

    def test_clean_when_in_sync(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {("public", "auth_permission")}
        assert "Grants in sync" in _run()

    def test_fails_on_missing_grant(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = set()
        with pytest.raises(CommandError) as exc:
            _run()
        assert "declared but not granted: auth_permission" in str(exc.value)

    def test_fails_on_extra_grant(self, patched_grants):
        patched_grants["declared_tables"].return_value = {}
        patched_grants["granted_tables"].return_value = {("public", "orphaned_table")}
        with pytest.raises(CommandError) as exc:
            _run()
        assert "granted but not declared: orphaned_table" in str(exc.value)

    def test_fails_on_both_directions(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {("public", "orphaned_table")}
        with pytest.raises(CommandError) as exc:
            _run()
        message = str(exc.value)
        assert "declared but not granted: auth_permission" in message
        assert "granted but not declared: orphaned_table" in message

    def test_fails_when_role_missing(self, patched_grants):
        patched_grants["role_exists"].return_value = False
        with pytest.raises(CommandError) as exc:
            _run()
        assert "does not exist" in str(exc.value)

    def test_fails_when_membership_missing(self, patched_grants):
        # CCR #3 closed a bug: the original check command did not call
        # has_role_membership() at all, so a fresh env where role_setup.sql
        # created the role but skipped `GRANT mcp_readonly_role TO <app>`
        # returned "in sync" instead of surfacing the misconfiguration.
        # Now that mcp_sql_grants uses reconcile_grants(strict=True,
        # apply=False), the membership preflight fires.
        patched_grants["has_membership"].return_value = False
        with pytest.raises(CommandError) as exc:
            _run()
        assert "NOT a member" in str(exc.value)

    @pytest.mark.parametrize(
        "db_table",
        ["s" * 64 + '"."t', '"' + "s" * 64 + '"."t"', "t" * 64, "ü" * 32],
    )
    def test_fails_on_a_name_postgres_truncates(self, patched_grants, db_table):
        """Review round 18: a schema or table name over 63 bytes (UTF-8) is
        refused before the role checks, in either mode, and the post-migrate
        signal logs it (lenient mode raises it too)."""
        from mcp_sql import grants

        patched_grants["declared_tables"].return_value = {"auth.Permission": db_table}
        patched_grants["role_exists"].return_value = False
        with pytest.raises(CommandError) as exc:
            _run()
        assert "63-byte identifier limit" in str(exc.value)
        with pytest.raises(grants.GrantsReconcileError):
            grants.reconcile_grants(strict=False, apply=False)

    @pytest.mark.parametrize(
        "db_table", ["s" * 63 + '"."' + "t" * 63, "t" * 63, "ü" * 31 + "x"]
    )
    def test_63_bytes_is_not_refused(self, patched_grants, db_table):
        from mcp_sql.parser import relation_of

        patched_grants["declared_tables"].return_value = {"auth.Permission": db_table}
        patched_grants["granted_tables"].return_value = {relation_of(db_table)}
        assert "Grants in sync" in _run()


class TestRelationsOutsidePublic:
    """Review round 16: the inventory covers every non-system schema, so a
    grant on a relation outside `public` is drift (and `--apply` revokes it);
    GRANT / REVOKE name the relation schema-qualified."""

    def test_an_out_of_schema_grant_is_drift(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {
            ("public", "auth_permission"),
            ("analytics", "auth_permission"),
        }
        out = StringIO()
        with pytest.raises(CommandError) as exc:
            call_command("mcp_sql_grants", stdout=out)
        assert 'granted but not declared: "analytics"."auth_permission"' in str(
            exc.value
        )
        assert (
            'REVOKE SELECT ON "analytics"."auth_permission" FROM mcp_readonly_role;'
            in out.getvalue()
        )

    def test_a_missing_grant_names_the_public_relation(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = set()
        out = StringIO()
        with pytest.raises(CommandError):
            call_command("mcp_sql_grants", stdout=out)
        assert (
            'GRANT SELECT ON "public"."auth_permission" TO mcp_readonly_role;'
            in out.getvalue()
        )

    @pytest.mark.parametrize(
        ("db_table", "granted"),
        [
            ('"auth_permission"', ("public", "auth_permission")),
            ('analytics"."widget', ("analytics", "widget")),
            ('"analytics"."widget"', ("analytics", "widget")),
        ],
    )
    def test_each_db_table_spelling_is_its_relation(
        self, patched_grants, db_table, granted
    ):
        patched_grants["declared_tables"].return_value = {"auth.Permission": db_table}
        patched_grants["granted_tables"].return_value = {granted}
        assert "Grants in sync" in _run()

    @pytest.mark.parametrize(
        ("relation", "sql"),
        [
            (("public", "auth_permission"), '"public"."auth_permission"'),
            (("analytics", "widget"), '"analytics"."widget"'),
            (("public", 'x" FROM r; --'), '"public"."x"" FROM r; --"'),
            (('a"."b', "c"), '"a"".""b"."c"'),
            (
                ("public", "a\nb\\c\u200b"),
                '"public".U&"a\\+00000Ab\\+00005Cc\\+00200B"',
            ),
        ],
    )
    def test_relation_sql(self, relation, sql):
        from mcp_sql.grants import relation_sql

        assert relation_sql(relation) == sql
