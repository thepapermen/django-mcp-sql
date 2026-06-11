"""Unit tests for the grants reconciler.

Single entry point: `reconcile_grants(*, strict, apply) -> DriftDiff`.

- `mcp_sql_grants --apply` calls `reconcile_grants(strict=True, apply=True)`
  as a deploy-pipeline step — strict raises on preflight failure, apply
  mutates grants.
- `mcp_sql_grants (read-only)` calls `reconcile_grants(strict=True, apply=False)`
  as a CI/deploy drift gate — strict same; apply=False is read-only.
- The `post_migrate` signal `audit_grants_drift_after_migrate` calls
  `reconcile_grants(strict=False, apply=False)`. Purely advisory: a
  WARNING is logged when drift exists; `mcp_sql_grants --apply` (the deploy
  pipeline step) is the only code path that mutates grants.
"""

import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from django.db.models.signals import post_migrate
from mcp_sql.grants import GrantsReconcileError
from mcp_sql.grants import reconcile_grants
from mcp_sql.signals import audit_grants_drift_after_migrate


@pytest.fixture
def patched_grants():
    """Patch the four grants preflights so tests do not touch a real DB."""
    with (
        patch("mcp_sql.grants.role_exists") as role_exists,
        patch("mcp_sql.grants.has_role_membership") as has_membership,
        patch("mcp_sql.grants.declared_tables") as declared_tables,
        patch("mcp_sql.grants.granted_tables") as granted_tables,
        patch("mcp_sql.grants.connection") as connection,
    ):
        role_exists.return_value = True
        has_membership.return_value = True
        declared_tables.return_value = {}
        granted_tables.return_value = set()
        # `_verify_default_alias()` reads `grants.connection.alias` at the top
        # of every public helper. Without an explicit override the mock returns
        # a MagicMock instance (not the string `"default"`) and the assertion
        # fires before any other preflight runs, masking what the test is
        # actually trying to exercise.
        connection.alias = "default"
        # `transaction.atomic()` + `connection.cursor()` both used inside
        # the GRANT/REVOKE execution path. Make them a no-op context manager.
        connection.cursor.return_value.__enter__.return_value = MagicMock()
        connection.cursor.return_value.__exit__.return_value = False
        with patch("mcp_sql.grants.transaction.atomic") as atomic:
            atomic.return_value.__enter__.return_value = None
            atomic.return_value.__exit__.return_value = False
            yield {
                "role_exists": role_exists,
                "has_membership": has_membership,
                "declared_tables": declared_tables,
                "granted_tables": granted_tables,
                "connection": connection,
                "atomic": atomic,
            }


class TestReconcileGrantsStrict:
    """Strict mode: every preflight failure raises."""

    def test_role_missing_raises(self, patched_grants):
        patched_grants["role_exists"].return_value = False
        with pytest.raises(GrantsReconcileError, match="does not exist"):
            reconcile_grants(strict=True, apply=True)

    def test_no_membership_raises(self, patched_grants):
        patched_grants["has_membership"].return_value = False
        with pytest.raises(GrantsReconcileError, match="NOT a member"):
            reconcile_grants(strict=True, apply=True)

    def test_self_referential_raises(self, patched_grants, settings):
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
        with pytest.raises(GrantsReconcileError, match="Refusing to grant"):
            reconcile_grants(strict=True, apply=True)

    def test_in_sync_returns_empty(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {"auth_permission"}
        result = reconcile_grants(strict=True, apply=True)
        assert result.granted == []
        assert result.revoked == []
        assert not result.changed

    def test_grants_added_and_removed(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = {"orphaned_table"}
        result = reconcile_grants(strict=True, apply=True)
        assert result.granted == ["auth_permission"]
        assert result.revoked == ["orphaned_table"]
        assert result.changed


class TestReconcileGrantsLenient:
    """Lenient mode: env-level preflight failures log + skip."""

    def test_role_missing_skips_with_reason(self, patched_grants, caplog):
        patched_grants["role_exists"].return_value = False
        with caplog.at_level(logging.WARNING, logger="mcp_sql.grants"):
            result = reconcile_grants(strict=False, apply=True)
        assert result.skipped_reason == "role_missing"
        assert not result.changed
        assert "does not exist" in caplog.text

    def test_no_membership_skips_with_reason(self, patched_grants, caplog):
        patched_grants["has_membership"].return_value = False
        with caplog.at_level(logging.WARNING, logger="mcp_sql.grants"):
            result = reconcile_grants(strict=False, apply=True)
        assert result.skipped_reason == "no_membership"
        assert not result.changed
        assert "NOT a member" in caplog.text

    def test_self_referential_still_raises_in_lenient(self, patched_grants, settings):
        """Code-level misconfig, not env-level — must raise even in lenient mode."""
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
        with pytest.raises(GrantsReconcileError, match="Refusing to grant"):
            reconcile_grants(strict=False, apply=True)

    def test_in_sync_returns_empty_silently(self, patched_grants, caplog):
        with caplog.at_level(logging.WARNING, logger="mcp_sql.grants"):
            result = reconcile_grants(strict=False, apply=True)
        assert not result.changed
        assert result.skipped_reason == ""
        assert caplog.text == ""

    def test_grants_applied_when_in_drift(self, patched_grants):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = set()
        result = reconcile_grants(strict=False, apply=True)
        assert result.granted == ["auth_permission"]
        assert not result.skipped_reason


class TestAuditGrantsDriftSignal:
    """`audit_grants_drift_after_migrate` is detect-only.

    It must NOT issue GRANT / REVOKE statements — `reconcile_grants(apply=True)` should
    never be reached on the signal path. The cursor mock would record
    any `.execute(GRANT ...)` calls if the signal accidentally mutated.
    """

    def test_fires_only_when_sender_is_mcp_sql(self, patched_grants, caplog):
        """Other apps' post_migrate must be a no-op for this receiver."""
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = set()

        other_app_sender = MagicMock(label="auth")
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(sender=other_app_sender, using="default")

        # `reconcile_grants` never ran.
        assert not patched_grants["declared_tables"].called
        assert "DRIFT" not in caplog.text

    def test_no_op_for_non_default_using(self, patched_grants, caplog):
        """The `mcp_readonly` alias has no migrations; skip it."""
        sender = MagicMock(label="mcp_sql")
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(sender=sender, using="mcp_readonly")
        assert not patched_grants["declared_tables"].called

    def test_no_op_for_none_sender(self, patched_grants):
        """Defensive: a synthetic post_migrate with sender=None must not crash."""
        audit_grants_drift_after_migrate(sender=None, using="default")
        assert not patched_grants["declared_tables"].called

    def test_warns_on_drift_without_applying(self, patched_grants, caplog):
        patched_grants["declared_tables"].return_value = {
            "auth.Permission": "auth_permission",
        }
        patched_grants["granted_tables"].return_value = set()
        sender = MagicMock(label="mcp_sql")

        with caplog.at_level(logging.WARNING, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(sender=sender, using="default")
        assert "DRIFT" in caplog.text
        assert "mcp_sql_grants --apply" in caplog.text
        # The cursor's `execute` MUST NOT have been called — drift
        # detection is read-only on the signal path. (The `granted_tables`
        # read uses a cursor too, but only `.execute()` issues
        # GRANT/REVOKE in `reconcile_grants(apply=True)`.) Inspect the
        # mock to confirm no `GRANT`/`REVOKE` statement was issued.
        cursor = patched_grants["connection"].cursor.return_value.__enter__.return_value
        executed_sql = [
            call.args[0] if call.args else "" for call in cursor.execute.call_args_list
        ]
        assert not any(
            "GRANT SELECT" in s or "REVOKE SELECT" in s for s in executed_sql
        )

    def test_silent_when_in_sync(self, patched_grants, caplog):
        sender = MagicMock(label="mcp_sql")
        with caplog.at_level(logging.WARNING, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(sender=sender, using="default")
        assert "DRIFT" not in caplog.text

    def test_skipped_profile_does_not_suppress_other_profiles_drift(
        self, patched_grants, settings, caplog
    ):
        """Phased rollout: profile A's role not yet created (skipped, logged
        per-profile inside reconcile_grants) while profile B has real drift —
        the aggregate DRIFT WARNING must still fire for B. Regression pin:
        an early-return on `DriftDiff.skipped_reason` used to silence it."""
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "PROFILES": {
                "pending": {
                    "ROLE": "mcp_ro_pending",
                    "PERMISSION_CODENAME": "use_mcp_session_pending",
                    "GROUP_NAME": "mcp_pending_users",
                    "ALLOWED_MODELS": ["auth.Group"],
                },
                "live": {
                    "ROLE": "mcp_readonly_role",
                    "PERMISSION_CODENAME": "use_mcp_session",
                    "GROUP_NAME": "mcp_sql_users",
                    "ALLOWED_MODELS": ["auth.Permission"],
                },
            },
        }
        patched_grants["role_exists"].side_effect = (
            lambda role: role == "mcp_readonly_role"
        )
        patched_grants["declared_tables"].side_effect = lambda profile: (
            {"auth.Permission": "auth_permission"}
            if profile.name == "live"
            else {"auth.Group": "auth_group"}
        )
        patched_grants["granted_tables"].return_value = set()
        sender = MagicMock(label="mcp_sql")

        with caplog.at_level(logging.WARNING):
            audit_grants_drift_after_migrate(sender=sender, using="default")

        assert "does not exist" in caplog.text  # the skip, still logged
        assert "DRIFT" in caplog.text  # the live profile's drift, not silenced
        assert "+1 to grant" in caplog.text

    def test_skipped_role_missing_does_not_crash_migrate(self, patched_grants, caplog):
        """A fresh env without role_setup.sql must still let `migrate` complete."""
        patched_grants["role_exists"].return_value = False
        sender = MagicMock(label="mcp_sql")
        with caplog.at_level(logging.WARNING, logger="mcp_sql.grants"):
            # Must not raise.
            audit_grants_drift_after_migrate(sender=sender, using="default")
        assert "does not exist" in caplog.text

    def test_self_referential_logged_at_error_does_not_crash_migrate(
        self, patched_grants, settings, caplog
    ):
        """`reconcile_grants` raises on self-referential whitelist even in
        lenient mode; the receiver catches and logs at ERROR rather than
        propagating into `migrate`'s exception chain."""
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
        sender = MagicMock(label="mcp_sql")
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            # Must not raise.
            audit_grants_drift_after_migrate(sender=sender, using="default")
        assert "Refusing to grant" in caplog.text


class TestSignalIsRegistered:
    """Verify the receiver is actually wired to `post_migrate`.

    A future refactor that removes the `@receiver` decorator would let
    every grants test still pass (we call the function directly above),
    but the drift-detect contract would silently break.
    """

    def test_receiver_in_post_migrate_dispatch_list(self):
        # Django's signal receivers list is `[(key, weakref_to_receiver,
        # captures_sender), ...]`; the second element is the weakref.
        live = [
            entry[1]() for entry in post_migrate.receivers if entry[1]() is not None
        ]
        assert audit_grants_drift_after_migrate in live
