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
        patched_grants["granted_tables"].return_value = {"auth_permission"}
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
        patched_grants["granted_tables"].return_value = {"orphaned_table"}
        with pytest.raises(CommandError) as exc:
            _run()
        assert "granted but not declared: orphaned_table" in str(exc.value)

    def test_fails_on_both_directions(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {"orphaned_table"}
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
