"""Startup validation for the `MCP_SQL` settings dict.

Called from `apps.py::McpSqlConfig.ready()` exactly once per process. The
TypedDict pins the structural shape; the function below adds the few
cross-field invariants Pydantic can't express on its own (positive
numerics, `DEFAULT_LIMIT <= HARD_LIMIT`, per-profile non-empty + unique
ROLE / PERMISSION_CODENAME / GROUP_NAME, and the `app_label.ModelName`
regex on each profile's `ALLOWED_MODELS` entry).

`ALLOWED_MODELS` entries are checked only for SHAPE here — the actual
model-existence resolution via `apps.get_model(entry)` is deferred to
runtime (`grants.declared_tables`, executor pipeline, etc.) so an
optional / not-yet-installed app does not crash boot.

The keys carrying in-package defaults in `mcp_sql.conf.DEFAULTS`
(RESOURCE_NAME, MFA_CHECKER, SESSION_MODEL, APPLICATION_NAME, etc.) are
marked `NotRequired`. Consumers may set any subset of them; the validator
does not require them.
"""

import re
import sys
from collections.abc import Mapping
from typing import Any

if sys.version_info >= (3, 12):
    from typing import NotRequired
    from typing import TypedDict
else:
    # Pydantic rejects `typing.TypedDict` on Python < 3.12 and requires the
    # `typing_extensions` backport (always installed — pydantic depends on it).
    from typing_extensions import NotRequired
    from typing_extensions import TypedDict

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from pydantic import TypeAdapter


class McpSqlLimits(TypedDict):
    DEFAULT_LIMIT: int
    HARD_LIMIT: int
    BYTES_LIMIT: int


class ProfileEntry(TypedDict):
    """One `MCP_SQL["PROFILES"]` entry — an access tier. See `conf.Profile`."""

    ROLE: str
    PERMISSION_CODENAME: str
    GROUP_NAME: str
    ALLOWED_MODELS: list[str]
    # Optional dormant per-row-context hook: dotted path to
    # `callable(user, profile) -> Mapping[str, str] | None`. Default None.
    SESSION_CONTEXT: NotRequired[str | None]


class McpSqlSettings(TypedDict):
    # Required: every consumer must declare these.
    # One entry per access tier; keys are profile names (e.g. "default").
    PROFILES: dict[str, ProfileEntry]
    BAN_SELECT_STAR: bool
    LIMITS: McpSqlLimits
    # `{decision: {window_seconds: threshold}}` — per-user volume tripwires.
    # `decision` keys mirror `MCPQueryLog.DECISION_*` ("allowed"/"rejected");
    # the value-level checks below enforce that closed set.
    VOLUME_ALERT_THRESHOLDS: dict[str, dict[int, int]]
    BAD_TOKEN_IP_THRESHOLD: int
    BAD_TOKEN_IP_WINDOW_SECONDS: int
    # Optional: have in-package defaults in `mcp_sql.conf.DEFAULTS`.
    # Consumers override any subset. (Per-profile ROLE / PERMISSION_CODENAME /
    # GROUP_NAME / ALLOWED_MODELS live inside PROFILES, not here.)
    RESOURCE_NAME: NotRequired[str]
    MFA_CHECKER: NotRequired[str]
    SESSION_MODEL: NotRequired[str]
    APPLICATION_NAME: NotRequired[str]
    APPLICATION_NAME_PREFIX: NotRequired[str]
    SCOPE: NotRequired[str]
    DB_ALIAS: NotRequired[str]


_MCP_SQL_MODEL_REF_RE = re.compile(r"^[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9_]+$")

# A profile's ROLE is interpolated UNQUOTED into `SET LOCAL ROLE <role>` by
# `session.enter_readonly_session` (the same reason `session.py` validates its
# GUC names/values at import — `SET LOCAL` takes no bound parameters). The role
# name comes from operator config, not an end user, so this is not an injection
# vector today; the check turns a would-be opaque runtime SQL error into a
# focused startup `ImproperlyConfigured`, and keeps the SET-LOCAL-ROLE site
# honest if the role ever became less trusted. The in-package defaults
# (`mcp_readonly_role`, ...) match.
_PG_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# `decision` keys mirror `MCPQueryLog.DECISION_*`; hardcoded so this validator
# stays model-free (it runs at `ready()` purely on the settings dict).
_VALID_VOLUME_DECISIONS = frozenset({"allowed", "rejected"})


def _validate_volume_alert_thresholds(
    thresholds: Mapping[str, Mapping[int, int]],
) -> None:
    """Each key is a `MCPQueryLog.decision`; each maps window-seconds → a
    positive threshold. Both window keys and thresholds must be positive."""
    for decision, windows in thresholds.items():
        if decision not in _VALID_VOLUME_DECISIONS:
            msg = (
                f"MCP_SQL.VOLUME_ALERT_THRESHOLDS key {decision!r} must be one "
                f"of {sorted(_VALID_VOLUME_DECISIONS)}"
            )
            raise ImproperlyConfigured(msg)
        for window, threshold in windows.items():
            if window <= 0:
                msg = (
                    f"MCP_SQL.VOLUME_ALERT_THRESHOLDS[{decision!r}] window "
                    f"{window} must be a positive number of seconds"
                )
                raise ImproperlyConfigured(msg)
            if threshold <= 0:
                msg = (
                    f"MCP_SQL.VOLUME_ALERT_THRESHOLDS[{decision!r}][{window}] "
                    f"threshold {threshold} must be positive"
                )
                raise ImproperlyConfigured(msg)


# Django auto-creates these on the same content type (`mcp_sql.mcpquerylog`)
# that `resolve_profile` filters on. A profile codename colliding with one
# would make `provision_mcp_profiles` ADOPT the existing default permission
# row — silently binding every user who already holds it (e.g. for admin
# audit-browsing) to the MCP tier, with no group assignment and no m2m alert.
# Derived from Django's stock `Meta.default_permissions` actions so the set
# cannot silently drift from what Django actually auto-creates (the validator
# stays model-free, so the action tuple is mirrored rather than read off
# `MCPQueryLog._meta`).
_RESERVED_CODENAMES = frozenset(
    f"{action}_mcpquerylog" for action in ("add", "change", "delete", "view")
)


def _validate_profile_entry(name: str, entry: Mapping[str, Any]) -> None:
    """Per-profile field checks (cross-profile uniqueness lives in the caller)."""
    # ROLE is interpolated unquoted into `SET LOCAL ROLE`; require it to be
    # a safe PG identifier (see `_PG_IDENTIFIER_RE`). `fullmatch` — the
    # anchored `$` alone would still admit a trailing newline.
    if not _PG_IDENTIFIER_RE.fullmatch(entry["ROLE"]):
        msg = (
            f"MCP_SQL.PROFILES[{name!r}].ROLE {entry['ROLE']!r} must be a "
            f"valid unquoted Postgres identifier (letters, digits, "
            f"underscores; not starting with a digit)"
        )
        raise ImproperlyConfigured(msg)
    if entry["PERMISSION_CODENAME"] in _RESERVED_CODENAMES:
        msg = (
            f"MCP_SQL.PROFILES[{name!r}].PERMISSION_CODENAME "
            f"{entry['PERMISSION_CODENAME']!r} collides with a Django "
            f"default model permission on the mcpquerylog content type — "
            f"provisioning would adopt the existing permission row and "
            f"silently bind its current holders to this MCP tier"
        )
        raise ImproperlyConfigured(msg)
    # SESSION_CONTEXT (optional) must IMPORT at boot: `profiles()`
    # resolves the hook eagerly at its first call — typically during
    # `migrate` — but a web-only process restart never calls it until
    # the first MCP request. Import-checking here makes a typo'd path
    # fail EVERY process at `ready()` instead.
    ctx_path = entry.get("SESSION_CONTEXT")
    if ctx_path:
        try:
            import_string(ctx_path)
        except ImportError as exc:
            msg = (
                f"MCP_SQL.PROFILES[{name!r}].SESSION_CONTEXT {ctx_path!r} "
                f"does not import: {exc}"
            )
            raise ImproperlyConfigured(msg) from exc
    for model_entry in entry["ALLOWED_MODELS"]:
        if not _MCP_SQL_MODEL_REF_RE.fullmatch(model_entry):
            msg = (
                f"MCP_SQL.PROFILES[{name!r}].ALLOWED_MODELS entry "
                f"{model_entry!r} must match 'app_label.ModelName'"
            )
            raise ImproperlyConfigured(msg)


def _validate_profiles(profiles: Mapping[str, Mapping[str, Any]]) -> None:
    """At least one profile; each with a non-empty ROLE / PERMISSION_CODENAME /
    GROUP_NAME, those three unique across profiles, and `app_label.ModelName`-
    shaped ALLOWED_MODELS. Codename uniqueness is load-bearing — `resolve_profile`
    maps a matched codename back to exactly one profile."""
    if not profiles:
        msg = "MCP_SQL.PROFILES must declare at least one profile"
        raise ImproperlyConfigured(msg)
    seen: dict[str, dict[str, str]] = {
        "ROLE": {},
        "PERMISSION_CODENAME": {},
        "GROUP_NAME": {},
    }
    for name, entry in profiles.items():
        for field, registry in seen.items():
            value = entry.get(field)
            if not value:
                msg = f"MCP_SQL.PROFILES[{name!r}].{field} must be a non-empty string"
                raise ImproperlyConfigured(msg)
            if value in registry:
                msg = (
                    f"MCP_SQL.PROFILES[{name!r}].{field} {value!r} is also used "
                    f"by profile {registry[value]!r}; {field} must be unique "
                    f"across profiles"
                )
                raise ImproperlyConfigured(msg)
            registry[value] = name
        _validate_profile_entry(name, entry)


def validate_mcp_sql_settings(cfg: Mapping[str, Any]) -> None:
    """Validate the `MCP_SQL` settings dict on startup.

    - Pydantic TypeAdapter enforces the TypedDict shape (required keys
      present and typed, optional keys typed when present).
    - Numeric values must be positive; `DEFAULT_LIMIT` must not exceed
      `HARD_LIMIT`.
    - Each profile in `PROFILES` has non-empty unique ROLE /
      PERMISSION_CODENAME / GROUP_NAME and `app_label.ModelName`-shaped
      `ALLOWED_MODELS`; model resolution is deferred to runtime.

    Raises `ImproperlyConfigured` on any violation so Django startup
    halts with a single, focused error rather than a cascade of
    AttributeErrors at first read.
    """
    try:
        TypeAdapter(McpSqlSettings).validate_python(cfg)
    except Exception as e:
        msg = "Invalid MCP_SQL settings"
        raise ImproperlyConfigured(msg) from e

    limits = cfg["LIMITS"]
    for key, val in limits.items():
        if val <= 0:
            msg = f"MCP_SQL.LIMITS.{key} must be positive (got {val})"
            raise ImproperlyConfigured(msg)
    if limits["DEFAULT_LIMIT"] > limits["HARD_LIMIT"]:
        msg = (
            f"MCP_SQL.LIMITS.DEFAULT_LIMIT ({limits['DEFAULT_LIMIT']}) "
            f"must not exceed HARD_LIMIT ({limits['HARD_LIMIT']})"
        )
        raise ImproperlyConfigured(msg)

    _validate_volume_alert_thresholds(cfg["VOLUME_ALERT_THRESHOLDS"])

    if cfg["BAD_TOKEN_IP_THRESHOLD"] <= 0:
        msg = (
            f"MCP_SQL.BAD_TOKEN_IP_THRESHOLD must be positive "
            f"(got {cfg['BAD_TOKEN_IP_THRESHOLD']})"
        )
        raise ImproperlyConfigured(msg)
    if cfg["BAD_TOKEN_IP_WINDOW_SECONDS"] <= 0:
        msg = (
            f"MCP_SQL.BAD_TOKEN_IP_WINDOW_SECONDS must be positive "
            f"(got {cfg['BAD_TOKEN_IP_WINDOW_SECONDS']})"
        )
        raise ImproperlyConfigured(msg)

    _validate_profiles(cfg["PROFILES"])
