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
from urllib.parse import unquote
from urllib.parse import urlparse

if sys.version_info >= (3, 12):
    from typing import NotRequired
    from typing import TypedDict
else:
    # Pydantic rejects `typing.TypedDict` on Python < 3.12 and requires the
    # `typing_extensions` backport (always installed — pydantic depends on it).
    from typing import NotRequired

    from typing_extensions import TypedDict

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from pydantic import ConfigDict
from pydantic import TypeAdapter

# `extra="forbid"` on the tool-surface shapes: a typo'd key (`CALL_LIMITS`,
# `INSTRUCTION`) would otherwise be ignored with nothing in the logs — for a
# call budget, a budget silently off.
_FORBID_EXTRA = ConfigDict(extra="forbid")


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


class CloudClientEntry(TypedDict):
    """One `MCP_SQL["CLOUD_CLIENTS"]` entry. See `conf.CloudClient`."""

    NAME: str
    # "exact" | "prefix" — value-checked in `_validate_cloud_clients`.
    REDIRECT_MATCH: str
    REDIRECT_URI: str


class CallLimitEntry(TypedDict):
    """A tool surface's `CALL_LIMIT`. See `conf.CallLimit`."""

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    CALLS: int
    WINDOW_SECONDS: int


class ToolSurfaceEntry(TypedDict):
    """One `MCP_SQL["TOOL_SURFACES"]` entry. See `conf.ToolSurface`."""

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    PATH: str
    SCOPE: str
    RESOURCE_NAME: str
    PERMISSION_CODENAME: str
    GROUP_NAME: str
    # Dotted path to `register(server, ctx)`; import-checked at boot.
    TOOLS: str
    INSTRUCTIONS: NotRequired[str]
    CALL_LIMIT: NotRequired[CallLimitEntry | None]


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
    # Opt-in cloud clients. Empty / absent = feature off.
    CLOUD_CLIENTS: NotRequired[list[CloudClientEntry]]
    # Opt-in tool surfaces, keyed by surface name. Empty / absent = off.
    TOOL_SURFACES: NotRequired[dict[str, ToolSurfaceEntry]]


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


# A cloud client NAME is a slug; its derived client_id is
# `<APPLICATION_NAME_PREFIX>cloud.<NAME>` (see `conf.MCPSQLSettings.cloud_clients`).
# The `.` after "cloud" keeps that id provably disjoint from the DCR
# `<prefix><22-urlsafe>` shape, so no NAME-length guard against the DCR shape
# is needed here.
_CLOUD_CLIENT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_VALID_REDIRECT_MATCHES = frozenset({"exact", "prefix"})


def _validate_cloud_redirect_uri(name: str, match: str, uri: str) -> None:
    """A cloud client's REDIRECT_URI must be safe to admit as a non-loopback
    OAuth callback. Rejects anything an attacker could weaponise if it reached
    DOT's exact matching or the prefix override: non-https, a userinfo
    component, a `*` wildcard, or a `..` traversal segment. A "prefix" entry
    must additionally carry a non-root path AND end with `/` — so the runtime
    match is anchored at a segment boundary and a sibling like `.../oauthEVIL`
    cannot slip past `.../oauth`. Mirrors the care in
    `views/registration.py::_is_loopback_redirect`."""
    parsed = urlparse(uri)
    problems: list[str] = []
    if parsed.scheme != "https":
        problems.append("use the https scheme")
    if parsed.username or parsed.password:
        problems.append("carry no userinfo component")
    if not parsed.hostname:
        problems.append("include a host")
    if "*" in uri:
        problems.append("contain no '*' wildcard")
    if ".." in unquote(parsed.path).split("/"):
        problems.append("contain no '..' path segment (literal or encoded)")
    if match == "prefix" and parsed.path.strip("/") == "":
        problems.append("include a non-root path for prefix matching")
    if match == "prefix" and not parsed.path.endswith("/"):
        problems.append("end with '/' for prefix matching (segment-anchored)")
    if problems:
        joined = "; ".join(problems)
        msg = (
            f"MCP_SQL.CLOUD_CLIENTS[{name!r}].REDIRECT_URI {uri!r} is invalid: "
            f"must {joined}"
        )
        raise ImproperlyConfigured(msg)


def _validate_cloud_clients(clients: list[Mapping[str, Any]]) -> None:
    """Each CLOUD_CLIENTS entry: a unique slug NAME, REDIRECT_MATCH in
    {"exact", "prefix"}, and a hardened https REDIRECT_URI. When CLOUD_CLIENTS is
    non-empty, https must also be in
    OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"] (see below). Empty list (the
    default) is a no-op — the feature is off. What the setting enables and how
    the cloud login works: `docs/oauth.md` → "Cloud clients"."""
    seen: set[str] = set()
    for entry in clients:
        name = entry["NAME"]
        if not _CLOUD_CLIENT_NAME_RE.fullmatch(name):
            msg = (
                f"MCP_SQL.CLOUD_CLIENTS NAME {name!r} must be a slug: a "
                f"lowercase letter followed by lowercase letters, digits, or "
                f"hyphens"
            )
            raise ImproperlyConfigured(msg)
        if name in seen:
            msg = f"MCP_SQL.CLOUD_CLIENTS NAME {name!r} is used more than once"
            raise ImproperlyConfigured(msg)
        seen.add(name)
        match = entry["REDIRECT_MATCH"]
        if match not in _VALID_REDIRECT_MATCHES:
            msg = (
                f"MCP_SQL.CLOUD_CLIENTS[{name!r}].REDIRECT_MATCH {match!r} must "
                f"be one of {sorted(_VALID_REDIRECT_MATCHES)}"
            )
            raise ImproperlyConfigured(msg)
        _validate_cloud_redirect_uri(name, match, entry["REDIRECT_URI"])

    # Every cloud client has an https callback, so if CLOUD_CLIENTS is non-empty
    # https MUST be in OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]. An
    # "exact" client would else fail opaquely at /o/authorize/ (it rides DOT's
    # stock redirect check, which enforces this list); a "prefix" client bypasses
    # that check via the _redirect_under_prefix override, but https is required
    # uniformly anyway so the config is self-consistent and a prefix-only setup
    # can't silently break the day an exact client is added. DOT's default is
    # ["http", "https"], so this only bites a consumer who narrowed it (e.g. to
    # ["http"] for loopback DCR) — fail loudly at startup.
    if clients:
        oauth_cfg = getattr(settings, "OAUTH2_PROVIDER", {})
        schemes = oauth_cfg.get("ALLOWED_REDIRECT_URI_SCHEMES", ["http", "https"])
        if "https" not in schemes:
            msg = (
                "MCP_SQL.CLOUD_CLIENTS is non-empty (cloud clients use https "
                "callbacks), but OAUTH2_PROVIDER['ALLOWED_REDIRECT_URI_SCHEMES'] "
                f"= {list(schemes)!r} does not include 'https'. Add 'https' to "
                "ALLOWED_REDIRECT_URI_SCHEMES."
            )
            raise ImproperlyConfigured(msg)


# A surface name is written to `MCPQueryLog.profile` (max_length=64) on every
# tool-call row and embedded in its URL names, hence a slug that fits.
_SURFACE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# One or more lowercase segments, each ending in `/`, no leading slash — the
# shape `path()` routes and `reverse()` returns (with a leading `/` added).
# A `.` cannot appear, so a surface can never claim a `.well-known/` path.
_SURFACE_PATH_RE = re.compile(r"^(?:[a-z0-9][a-z0-9_-]*/)+$")
# RFC 6749 §3.3 scope-token: printable ASCII except space, `"` and `\`.
_SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
# The SQL transport's path, and the authorization server's mount.
_SQL_PATH = "mcp/sql/"
_RESERVED_PATH_PREFIXES = ("o/",)


def _paths_overlap(first: str, second: str) -> bool:
    """True when one surface path is the other or nested under it.

    Disjoint paths keep every surface's RFC 9728 `resource` from being a URL
    prefix of another's: DOT (3.4+) audience-checks a resource-bound token
    with a URL-PREFIX match, so a token bound to `.../mcp/a` would otherwise
    pass the audience check at `.../mcp/a/b/` (the scope check still refuses
    it — this keeps the two layers from disagreeing)."""
    return first.startswith(second) or second.startswith(first)


def _validate_call_limit(name: str, limit: Mapping[str, Any] | None) -> None:
    """Both members positive ints, checked on the RAW values: pydantic's lax
    mode would take "60" or 60.0."""
    if limit is None:
        return
    for key in ("CALLS", "WINDOW_SECONDS"):
        value = limit[key]
        if type(value) is not int or value <= 0:
            msg = (
                f"MCP_SQL.TOOL_SURFACES[{name!r}].CALL_LIMIT.{key} must be a "
                f"positive int (got {value!r})"
            )
            raise ImproperlyConfigured(msg)


def _validate_surface_scope_registered(name: str, scope: str) -> None:
    """The surface's scope must be one DOT knows, or every authorization for
    it fails with an opaque `invalid_scope`: DOT's own `validate_scopes`
    (which `MCPOAuth2Validator` delegates to after its own check) admits only
    scopes its scopes backend lists. Checked for DOT's default backend (the
    `OAUTH2_PROVIDER["SCOPES"]` dict); a consumer with a custom
    `SCOPES_BACKEND_CLASS` owns that list themselves."""
    oauth_cfg = getattr(settings, "OAUTH2_PROVIDER", {})
    if "SCOPES_BACKEND_CLASS" in oauth_cfg:
        return
    if scope not in oauth_cfg.get("SCOPES", {}):
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].SCOPE {scope!r} is not listed in "
            "OAUTH2_PROVIDER['SCOPES']; add it (with a description — it is shown "
            "on the consent screen), or every authorization for this surface "
            "fails with invalid_scope."
        )
        raise ImproperlyConfigured(msg)


def _validate_surface_entry(name: str, entry: Mapping[str, Any]) -> None:
    """Per-surface field checks (cross-surface uniqueness lives in the caller)."""
    if not _SURFACE_NAME_RE.fullmatch(name):
        msg = (
            f"MCP_SQL.TOOL_SURFACES key {name!r} must be a slug: a lowercase "
            "letter followed by up to 63 lowercase letters, digits or underscores"
        )
        raise ImproperlyConfigured(msg)
    path = entry["PATH"]
    if (
        not _SURFACE_PATH_RE.fullmatch(path)
        or "//" in path
        or path.startswith(_RESERVED_PATH_PREFIXES)
    ):
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].PATH {path!r} must be lowercase "
            "path segments ending in '/', without a leading '/' and outside the "
            "authorization server's 'o/' (e.g. 'mcp/pricing/')"
        )
        raise ImproperlyConfigured(msg)
    if _paths_overlap(path, _SQL_PATH):
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].PATH {path!r} overlaps the read-only "
            f"SQL transport '{_SQL_PATH}'; a tool surface needs its own path"
        )
        raise ImproperlyConfigured(msg)
    scope = entry["SCOPE"]
    if not _SCOPE_TOKEN_RE.fullmatch(scope):
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].SCOPE {scope!r} must be one OAuth "
            "scope token (printable ASCII, no space, quote or backslash)"
        )
        raise ImproperlyConfigured(msg)
    if not entry["RESOURCE_NAME"].strip():
        msg = f"MCP_SQL.TOOL_SURFACES[{name!r}].RESOURCE_NAME must be non-empty"
        raise ImproperlyConfigured(msg)
    if entry["PERMISSION_CODENAME"] in _RESERVED_CODENAMES:
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].PERMISSION_CODENAME "
            f"{entry['PERMISSION_CODENAME']!r} collides with a Django default "
            "model permission on the mcpquerylog content type — provisioning "
            "would adopt it and silently grant this surface to its holders"
        )
        raise ImproperlyConfigured(msg)
    tools_path = entry["TOOLS"]
    try:
        register = import_string(tools_path)
    except ImportError as exc:
        msg = (
            f"MCP_SQL.TOOL_SURFACES[{name!r}].TOOLS {tools_path!r} does not "
            f"import: {exc}"
        )
        raise ImproperlyConfigured(msg) from exc
    if not callable(register):
        msg = f"MCP_SQL.TOOL_SURFACES[{name!r}].TOOLS {tools_path!r} is not callable"
        raise ImproperlyConfigured(msg)
    _validate_call_limit(name, entry.get("CALL_LIMIT"))
    _validate_surface_scope_registered(name, scope)


def _validate_tool_surfaces(cfg: Mapping[str, Any]) -> None:
    """Each TOOL_SURFACES entry is well-formed, and nothing a surface owns is
    shared with the SQL surface, a profile or another surface: its name (the
    audit row's `profile`), PATH (disjoint, never nested — `_paths_overlap`),
    SCOPE (one scope ↔ one surface is what keeps a token on its surface),
    PERMISSION_CODENAME and GROUP_NAME (a shared one would grant two things
    at once). Empty (the default) is a no-op — the feature is off."""
    surfaces = cfg.get("TOOL_SURFACES") or {}
    if not surfaces:
        return
    profiles = cfg["PROFILES"]
    sql_scope = cfg.get("SCOPE", "mcp:sql")
    codenames = {
        p["PERMISSION_CODENAME"]: f"profile {n!r}" for n, p in profiles.items()
    }
    groups = {p["GROUP_NAME"]: f"profile {n!r}" for n, p in profiles.items()}
    scopes = {sql_scope: "the SQL surface (MCP_SQL.SCOPE)"}
    paths: dict[str, str] = {}
    for name, entry in surfaces.items():
        _validate_surface_entry(name, entry)
        owner = f"tool surface {name!r}"
        if name in profiles:
            msg = (
                f"MCP_SQL.TOOL_SURFACES key {name!r} is also a profile name; audit "
                "rows record either in the same column, so they must differ"
            )
            raise ImproperlyConfigured(msg)
        for field, registry in (
            ("SCOPE", scopes),
            ("PERMISSION_CODENAME", codenames),
            ("GROUP_NAME", groups),
        ):
            value = entry[field]
            if value in registry:
                msg = (
                    f"MCP_SQL.TOOL_SURFACES[{name!r}].{field} {value!r} is also "
                    f"used by {registry[value]}; it must be unique"
                )
                raise ImproperlyConfigured(msg)
            registry[value] = owner
        for other_path, other in paths.items():
            if _paths_overlap(entry["PATH"], other_path):
                msg = (
                    f"MCP_SQL.TOOL_SURFACES[{name!r}].PATH {entry['PATH']!r} "
                    f"overlaps the PATH {other_path!r} of {other}"
                )
                raise ImproperlyConfigured(msg)
        paths[entry["PATH"]] = owner


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
    _validate_cloud_clients(cfg.get("CLOUD_CLIENTS", []))
    _validate_tool_surfaces(cfg)
