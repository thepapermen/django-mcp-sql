"""Tests for `mcp_sql.conf` — the lazy settings accessor.

This commit lands the accessor only; call sites still read
`settings.MCP_SQL["X"]` directly. The R-item commits that follow migrate
call sites to `mcp_sql_settings.X`, so these tests pin the accessor's
contract independent of any consumer.
"""

from unittest.mock import MagicMock

import pytest
from django.test import override_settings
from mcp_sql.conf import DEFAULTS
from mcp_sql.conf import IMPORT_STRINGS
from mcp_sql.conf import MCPSQLSettings
from mcp_sql.conf import deny_unconfigured_mfa
from mcp_sql.conf import mcp_sql_settings


class TestDenyUnconfiguredMfa:
    """The in-package fail-closed MFA-checker default."""

    def test_returns_false_for_any_user(self):
        assert deny_unconfigured_mfa(MagicMock()) is False
        assert deny_unconfigured_mfa(None) is False


class TestMCPSQLSettingsDefaults:
    """Every defined key returns its in-package default when unset by consumer."""

    @pytest.fixture
    def empty(self):
        """Accessor instance reading from an empty MCP_SQL dict."""
        with override_settings(MCP_SQL={}):
            instance = MCPSQLSettings()
            yield instance

    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("RESOURCE_NAME", "MCP SQL"),
            ("APPLICATION_NAME", "mcp-sql"),
            ("APPLICATION_NAME_PREFIX", "mcp-sql-"),
            ("SCOPE", "mcp:sql"),
            ("DB_ALIAS", "mcp_readonly"),
            # ROLE / PERMISSION_CODENAME / GROUP_NAME are per-profile now
            # (MCP_SQL["PROFILES"]); the `default` profile's values are
            # asserted in TestDefaultProfile below.
        ],
    )
    def test_string_default_returned(self, empty, key, expected):
        assert getattr(empty, key) == expected

    def test_session_model_default_is_none(self, empty):
        # `None` is deliberate — see `mcp_sql/conf.py::DEFAULTS["SESSION_MODEL"]`
        # for the rationale (stock `django.contrib.sessions.Session` has no
        # `user` FK, so defaulting to it would crash the auth-class
        # session-existence gate; the gate is opt-in instead).
        assert empty.SESSION_MODEL is None

    def test_mfa_checker_default_resolves_to_deny_unconfigured_mfa(self, empty):
        # MFA_CHECKER is in IMPORT_STRINGS — the dotted-path default is
        # resolved to its callable on first read. The default is fail-closed.
        assert empty.MFA_CHECKER is deny_unconfigured_mfa
        assert empty.MFA_CHECKER(MagicMock()) is False


class TestDefaultProfile:
    """The in-package `default` profile reproduces the original flat behaviour."""

    def test_default_profile_shape(self):
        with override_settings(MCP_SQL={}):
            profiles = MCPSQLSettings().profiles()
        assert set(profiles) == {"default"}
        default = profiles["default"]
        assert default.role == "mcp_readonly_role"
        assert default.codename == "use_mcp_session"
        assert default.group_name == "mcp_sql_users"
        assert default.allowed_models == ()
        assert default.session_context is None


class TestMCPSQLSettingsOverrides:
    """Every key honors a consumer-provided override via settings.MCP_SQL."""

    def test_resource_name_override(self):
        with override_settings(MCP_SQL={"RESOURCE_NAME": "Custom MCP"}):
            assert MCPSQLSettings().RESOURCE_NAME == "Custom MCP"

    def test_session_model_override(self):
        with override_settings(MCP_SQL={"SESSION_MODEL": "user_sessions.Session"}):
            assert MCPSQLSettings().SESSION_MODEL == "user_sessions.Session"

    def test_mfa_checker_override_resolves_dotted_path(self):
        # Override with a real importable callable; the accessor resolves
        # the dotted path via `import_string`.
        with override_settings(
            MCP_SQL={"MFA_CHECKER": "django.utils.module_loading.import_string"}
        ):
            from django.utils.module_loading import import_string

            assert MCPSQLSettings().MFA_CHECKER is import_string

    def test_application_name_override(self):
        with override_settings(MCP_SQL={"APPLICATION_NAME": "custom-app"}):
            assert MCPSQLSettings().APPLICATION_NAME == "custom-app"

    def test_db_alias_override(self):
        with override_settings(MCP_SQL={"DB_ALIAS": "custom_readonly"}):
            assert MCPSQLSettings().DB_ALIAS == "custom_readonly"


class TestMCPSQLSettingsLookupErrors:
    """Unknown attributes raise with a clear message."""

    def test_unknown_attribute_raises(self):
        instance = MCPSQLSettings()
        with pytest.raises(AttributeError, match="Unknown MCP_SQL setting"):
            _ = instance.NONEXISTENT_SETTING


class TestMCPSQLSettingsReload:
    """Cached values flush on settings change via the `setting_changed` signal."""

    def test_cached_value_invalidated_on_settings_change(self):
        # First read primes the cache from the default.
        with override_settings(MCP_SQL={}):
            assert mcp_sql_settings.RESOURCE_NAME == "MCP SQL"
        # Override; the signal flushed the cache on enter AND exit, so the
        # nested context reads the new value.
        with override_settings(MCP_SQL={"RESOURCE_NAME": "Override Name"}):
            assert mcp_sql_settings.RESOURCE_NAME == "Override Name"
        # Outside both contexts: reverted to whatever the project's
        # settings.MCP_SQL says (or default if absent). The point of this
        # assertion is just that the value isn't stuck at "Override Name".
        assert mcp_sql_settings.RESOURCE_NAME != "Override Name"

    def test_explicit_reload_flushes_cache(self):
        instance = MCPSQLSettings()
        with override_settings(MCP_SQL={"RESOURCE_NAME": "First"}):
            assert instance.RESOURCE_NAME == "First"
            # Mutate the dict in-place (not via `override_settings`); the
            # accessor doesn't see it until reload() because the cached
            # value is sticky.
            from django.conf import settings as django_settings

            django_settings.MCP_SQL["RESOURCE_NAME"] = "Second"
            assert instance.RESOURCE_NAME == "First"  # still cached
            instance.reload()
            assert instance.RESOURCE_NAME == "Second"


class TestImportStringsCoverage:
    """Every key in `IMPORT_STRINGS` must also be in `DEFAULTS`.

    A typo'd `IMPORT_STRINGS` entry would silently no-op (the accessor's
    `if name in IMPORT_STRINGS` branch would never fire) and the dotted
    path would leak through as a literal string. Pin the invariant.
    """

    def test_every_import_string_has_a_default(self):
        assert set(DEFAULTS) >= IMPORT_STRINGS


class TestMfaUnconfiguredStartupWarning:
    """`McpSqlConfig.ready()` warns once when the fail-closed default MFA
    checker is still active, so the lock-out is explained not mysterious."""

    def test_warns_when_default_checker_active(self, caplog):
        import logging

        from mcp_sql.apps import McpSqlConfig

        with (
            override_settings(MCP_SQL={}),
            caplog.at_level(logging.WARNING, logger="mcp_sql"),
        ):
            McpSqlConfig.warn_if_mfa_unconfigured()
        assert any(
            "fail-closed default MFA checker" in r.message for r in caplog.records
        )

    def test_silent_when_checker_overridden(self, caplog):
        import logging

        from mcp_sql.apps import McpSqlConfig

        with (
            override_settings(
                MCP_SQL={"MFA_CHECKER": "django.utils.module_loading.import_string"}
            ),
            caplog.at_level(logging.WARNING, logger="mcp_sql"),
        ):
            McpSqlConfig.warn_if_mfa_unconfigured()
        assert not any(
            "fail-closed default MFA checker" in r.message for r in caplog.records
        )
