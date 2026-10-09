"""Tests for `mcp_sql.validation.validate_mcp_sql_settings`.

Pure dict-level startup validation: no DB, no app registry. The valid
baseline below mirrors the in-package shape; each test mutates one field to
assert the focused `ImproperlyConfigured` is raised.
"""

import copy

import pytest
from django.core.exceptions import ImproperlyConfigured
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.validation import validate_mcp_sql_settings
from mcp_sql.validation import validate_oauth2_validator_class

VALID = {
    "PROFILES": {
        "default": {
            "ROLE": "mcp_readonly_role",
            "PERMISSION_CODENAME": "use_mcp_session",
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": ["auth.Permission"],
        },
    },
    "BAN_SELECT_STAR": True,
    "LIMITS": {"DEFAULT_LIMIT": 10, "HARD_LIMIT": 100, "BYTES_LIMIT": 256 * 1024},
    "VOLUME_ALERT_THRESHOLDS": {
        "allowed": {3600: 50, 86400: 150},
        "rejected": {3600: 50, 86400: 150},
    },
    "BAD_TOKEN_IP_THRESHOLD": 100,
    "BAD_TOKEN_IP_WINDOW_SECONDS": 21600,
}


def _cfg(**profile_overrides):
    cfg = copy.deepcopy(VALID)
    cfg["PROFILES"]["default"].update(profile_overrides)
    return cfg


class TestValidBaseline:
    def test_valid_config_passes(self):
        validate_mcp_sql_settings(copy.deepcopy(VALID))


class TestProfileRoleIdentifier:
    """A profile ROLE is interpolated unquoted into `SET LOCAL ROLE`, so it
    must be a safe PG identifier."""

    @pytest.mark.parametrize(
        "role",
        [
            "mcp_readonly_role; DROP TABLE x",  # injection attempt
            "mcp-readonly-role",  # hyphens are not unquoted-identifier-safe
            "1role",  # leading digit
            "role name",  # whitespace
            "",  # empty (also caught by the non-empty check, but explicit)
        ],
    )
    def test_unsafe_role_rejected(self, role):
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(_cfg(ROLE=role))

    @pytest.mark.parametrize("role", ["mcp_readonly_role", "_priv", "Role2", "r"])
    def test_safe_role_accepted(self, role):
        validate_mcp_sql_settings(_cfg(ROLE=role))

    def test_role_with_trailing_newline_rejected(self):
        # `fullmatch`, not `match` — an anchored `$` alone still admits a
        # trailing newline into the SET LOCAL ROLE interpolation.
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(_cfg(ROLE="mcp_readonly_role\n"))


class TestProfileShape:
    """`_validate_profiles` structural gates: at-least-one profile, non-empty
    + cross-profile-unique ROLE / PERMISSION_CODENAME / GROUP_NAME."""

    def test_empty_profiles_rejected(self):
        cfg = copy.deepcopy(VALID)
        cfg["PROFILES"] = {}
        with pytest.raises(ImproperlyConfigured, match="at least one profile"):
            validate_mcp_sql_settings(cfg)

    @pytest.mark.parametrize("field", ["ROLE", "PERMISSION_CODENAME", "GROUP_NAME"])
    def test_empty_field_rejected(self, field):
        with pytest.raises(ImproperlyConfigured, match="non-empty string"):
            validate_mcp_sql_settings(_cfg(**{field: ""}))

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("ROLE", "mcp_readonly_role"),
            ("PERMISSION_CODENAME", "use_mcp_session"),
            ("GROUP_NAME", "mcp_sql_users"),
        ],
    )
    def test_cross_profile_duplicate_rejected(self, field, value):
        cfg = copy.deepcopy(VALID)
        cfg["PROFILES"]["second"] = {
            "ROLE": "mcp_ro_second",
            "PERMISSION_CODENAME": "use_mcp_session_second",
            "GROUP_NAME": "mcp_sql_second_users",
            "ALLOWED_MODELS": [],
            field: value,  # collide with the default profile
        }
        with pytest.raises(ImproperlyConfigured, match="unique across profiles"):
            validate_mcp_sql_settings(cfg)


class TestReservedCodenames:
    """A profile codename colliding with a Django default model permission on
    the mcpquerylog content type would make provisioning ADOPT the existing
    permission row — silently binding its current holders to the tier."""

    @pytest.mark.parametrize(
        "codename",
        [
            "add_mcpquerylog",
            "change_mcpquerylog",
            "delete_mcpquerylog",
            "view_mcpquerylog",
        ],
    )
    def test_reserved_codename_rejected(self, codename):
        with pytest.raises(ImproperlyConfigured, match="default model permission"):
            validate_mcp_sql_settings(_cfg(PERMISSION_CODENAME=codename))


class TestAllowedModelsShape:
    @pytest.mark.parametrize(
        "entry",
        [
            "auth.Permission\n",  # fullmatch: `$` alone admits the newline
            "auth",  # no model part
            "auth.permission.extra",  # too many dots
            "auth.Permission; DROP TABLE x",
        ],
    )
    def test_malformed_entry_rejected(self, entry):
        with pytest.raises(ImproperlyConfigured, match="app_label.ModelName"):
            validate_mcp_sql_settings(_cfg(ALLOWED_MODELS=[entry]))


class TestTopLevelInvariants:
    """The cross-field / numeric guards on the top-level settings dict, above
    the per-profile checks: TypedDict shape, LIMITS, VOLUME_ALERT_THRESHOLDS,
    and the BAD_TOKEN_IP_* tripwire knobs."""

    def test_omitted_key_falls_back_to_the_default(self):
        # Every key has an in-package default, so declaring a subset is valid —
        # that is the whole point of `conf.DEFAULTS`.
        cfg = copy.deepcopy(VALID)
        del cfg["BAN_SELECT_STAR"]
        validate_mcp_sql_settings(cfg)  # no raise

    def test_empty_settings_are_valid(self):
        validate_mcp_sql_settings({})  # no raise

    def test_wrong_type_rejected(self):
        # A declared key still has to be the right type; the pydantic
        # TypeAdapter catches it and `validate_mcp_sql_settings` wraps it.
        cfg = copy.deepcopy(VALID)
        cfg["LIMITS"] = "generous"
        with pytest.raises(ImproperlyConfigured, match="Invalid MCP_SQL settings"):
            validate_mcp_sql_settings(cfg)

    def test_unknown_key_rejected(self):
        # `extra="forbid"`: a typo'd key would otherwise be ignored and the
        # default used in its place, with nothing in the logs to explain why
        # the setting had no effect.
        cfg = copy.deepcopy(VALID)
        cfg["BAN_SELECT_STARS"] = True
        with pytest.raises(ImproperlyConfigured, match="Invalid MCP_SQL settings"):
            validate_mcp_sql_settings(cfg)

    @pytest.mark.parametrize("key", ["DEFAULT_LIMIT", "HARD_LIMIT", "BYTES_LIMIT"])
    def test_non_positive_limit_rejected(self, key):
        cfg = copy.deepcopy(VALID)
        cfg["LIMITS"][key] = 0
        with pytest.raises(ImproperlyConfigured, match="must be positive"):
            validate_mcp_sql_settings(cfg)

    def test_default_limit_exceeding_hard_limit_rejected(self):
        cfg = copy.deepcopy(VALID)
        cfg["LIMITS"]["DEFAULT_LIMIT"] = cfg["LIMITS"]["HARD_LIMIT"] + 1
        with pytest.raises(ImproperlyConfigured, match="must not exceed HARD_LIMIT"):
            validate_mcp_sql_settings(cfg)

    def test_unknown_volume_decision_rejected(self):
        cfg = copy.deepcopy(VALID)
        cfg["VOLUME_ALERT_THRESHOLDS"]["bogus"] = {3600: 50}
        with pytest.raises(ImproperlyConfigured, match="must be one of"):
            validate_mcp_sql_settings(cfg)

    def test_non_positive_volume_window_rejected(self):
        cfg = copy.deepcopy(VALID)
        cfg["VOLUME_ALERT_THRESHOLDS"]["allowed"] = {0: 50}
        with pytest.raises(ImproperlyConfigured, match="positive number of seconds"):
            validate_mcp_sql_settings(cfg)

    def test_non_positive_volume_threshold_rejected(self):
        cfg = copy.deepcopy(VALID)
        cfg["VOLUME_ALERT_THRESHOLDS"]["allowed"] = {3600: 0}
        with pytest.raises(ImproperlyConfigured, match="threshold 0 must be positive"):
            validate_mcp_sql_settings(cfg)

    @pytest.mark.parametrize(
        "key", ["BAD_TOKEN_IP_THRESHOLD", "BAD_TOKEN_IP_WINDOW_SECONDS"]
    )
    def test_non_positive_bad_token_knob_rejected(self, key):
        cfg = copy.deepcopy(VALID)
        cfg[key] = 0
        with pytest.raises(ImproperlyConfigured, match="must be positive"):
            validate_mcp_sql_settings(cfg)


class TestSessionContextImportCheck:
    """A typo'd SESSION_CONTEXT dotted path must fail every process at boot
    (`ready()`), not the first `profiles()` call (in practice: `migrate`) or
    — worse, for a web-only restart — the first MCP request."""

    def test_unimportable_path_rejected(self):
        with pytest.raises(ImproperlyConfigured, match="does not import"):
            validate_mcp_sql_settings(_cfg(SESSION_CONTEXT="no.such.module.hook"))

    def test_importable_path_accepted(self):
        # Any importable callable; fencing is Django-free so this never
        # depends on app loading.
        validate_mcp_sql_settings(
            _cfg(SESSION_CONTEXT="mcp_sql.fencing.fence_query_result")
        )

    def test_absent_and_none_accepted(self):
        validate_mcp_sql_settings(copy.deepcopy(VALID))
        validate_mcp_sql_settings(_cfg(SESSION_CONTEXT=None))


class TestOAuth2ValidatorClassBootCheck:
    """`apps.ready()` refuses an install whose DOT validator is not
    `MCPOAuth2Validator` (or a subclass): the package's OAuth server is
    built with that validator, which carries the client, scope, PKCE and
    redirect enforcement."""

    def _with_validator(self, settings, path):
        provider = {**settings.OAUTH2_PROVIDER}
        if path is None:
            provider.pop("OAUTH2_VALIDATOR_CLASS", None)
        else:
            provider["OAUTH2_VALIDATOR_CLASS"] = path
        settings.OAUTH2_PROVIDER = provider

    def test_package_validator_passes(self, settings):
        self._with_validator(settings, "mcp_sql.oauth.MCPOAuth2Validator")
        validate_oauth2_validator_class()

    def test_subclass_passes(self, settings):
        self._with_validator(
            settings, "mcp_sql.tests.test_validation._ConsumerValidator"
        )
        validate_oauth2_validator_class()

    @pytest.mark.parametrize(
        "path",
        [None, "oauth2_provider.oauth2_validators.OAuth2Validator"],
        ids=["dot-default", "dot-validator-explicit"],
    )
    def test_other_validators_refuse_to_boot(self, settings, path):
        self._with_validator(settings, path)
        with pytest.raises(ImproperlyConfigured, match="OAUTH2_VALIDATOR_CLASS"):
            validate_oauth2_validator_class()


class _ConsumerValidator(MCPOAuth2Validator):
    """A consumer's subclass of the package validator."""
