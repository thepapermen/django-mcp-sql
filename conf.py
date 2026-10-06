"""Single accessor for `MCP_SQL` settings with in-package defaults.

Mirrors the DRF (`rest_framework.settings.api_settings`) and
django-oauth-toolkit (`oauth2_provider.settings.oauth2_settings`) pattern:
a singleton object that reads `django.conf.settings.MCP_SQL` lazily on
attribute access, falls back to a `DEFAULTS` map of extract-ready values
when a key is missing, and resolves dotted-path entries listed in
`IMPORT_STRINGS` to their callable / class at first read.

Every `MCP_SQL[...]` key the package consumes flows through
`mcp_sql_settings.X` (or the `mcp_sql_config()` mapping view) instead of
`settings.MCP_SQL["X"]`, so the in-package default, dotted-path resolution,
and reload semantics live in one place.

**Every key carries a default** — `settings.MCP_SQL` may declare any subset,
or be absent entirely. In practice a real deployment sets two: `MFA_CHECKER`
(the default denies everyone, fail-closed) and each profile's
`ALLOWED_MODELS` (the default whitelist is empty, so no table is readable).
Both defaults are deliberately useless-but-safe: an unconfigured install
grants nothing rather than guessing.

One merge rule, applied identically by the accessor and by
`merged_config()`: a declared key replaces its default **wholesale**, never
member-by-member.

Cached values flush on `setting_changed` so `pytest-django`'s
`@override_settings` (and the `settings` fixture) re-read between tests.
"""

from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

from django.conf import settings
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.module_loading import import_string
from mcp_sql.clients import DeclaredClient
from mcp_sql.clients import build_clients

if TYPE_CHECKING:
    from mcp_sql.validation import McpSqlSettings


@dataclass(frozen=True)
class Profile:
    """One MCP access tier: a Postgres role + its whitelist + binding identifiers.

    Built by `MCPSQLSettings.profiles()` from each `MCP_SQL["PROFILES"]`
    entry. `session_context` is the optional per-profile dormant hook
    (`callable(user, profile) -> Mapping[str, str] | None`), already
    resolved from its dotted path (or `None`).
    """

    name: str
    role: str
    codename: str
    group_name: str
    allowed_models: tuple[str, ...]
    session_context: Callable[..., Mapping[str, str] | None] | None = None


class ResolutionOutcome(Enum):
    """Non-binding results of `resolve_profile` — fail-closed, never guess."""

    NO_PERM = "no_perm"
    AMBIGUOUS_PROFILE = "ambiguous_profile"


def deny_unconfigured_mfa(user: Any) -> bool:
    """Fail-closed default MFA checker — returns False for every user.

    An extracted `django-mcp-sql` cannot assume `django-allauth` (or any
    specific MFA library) is installed, so it ships no real MFA check. The
    default therefore fails **closed**: every MFA-gated decision is denied
    until the consumer wires a real checker via
    `MCP_SQL["MFA_CHECKER"] = "<dotted.path.to.checker>"` (django-allauth
    projects use `"allauth.mfa.utils.is_mfa_enabled"`). Failing open (a
    permissive `return True`) would silently grant MFA-gated MCP access to
    a consumer who never configured MFA — the worse failure for a security
    surface. `McpSqlConfig.ready()` emits a startup WARNING whenever this
    default is still active, so the lock-out is explained rather than
    mysterious.
    """
    return False


# In-package defaults. Each value is the extractable default — what
# `django-mcp-sql` would ship to a brand-new consumer with no `MCP_SQL`
# overrides. A consuming project that needs different identifiers wires
# them via `config/settings/*.py` `MCP_SQL[...]` keys; see the consumer's
# own integration notes for the override list in use today.
DEFAULTS: dict[str, Any] = {
    # === Identity / discovery ===
    #
    # Human-readable name of this MCP server. Surfaced via the RFC 9728
    # Protected Resource Metadata document at
    # `/.well-known/oauth-protected-resource/mcp/sql` as `resource_name`,
    # and (by convention) reused by developers as the slug-form `<name>`
    # passed to `claude mcp add --transport http <name> <URL>`. Default
    # is intentionally boring ("MCP SQL") so an extracted package works
    # out of the box. A consuming project running multiple envs typically
    # overrides this to an env-distinct value so developers connected to
    # more than one env at once see distinct names in `~/.claude.json`.
    "RESOURCE_NAME": "MCP SQL",
    # === Authn / authz plumbing ===
    #
    # Dotted path to a callable `is_mfa_enabled(user) -> bool` that gates
    # both OAuth issuance (`/o/authorize/`) and every per-request auth
    # decision in `MCPOAuth2Authentication.authenticate`. Default is
    # `deny_unconfigured_mfa` (defined above): FALSE for every user
    # (fail-closed), so an unconfigured consumer denies all MCP access
    # rather than silently granting it. Consumers using django-allauth
    # override to `"allauth.mfa.utils.is_mfa_enabled"`. Resolved via
    # `django.utils.module_loading.import_string` on first attribute
    # access and cached until the next `setting_changed` signal.
    "MFA_CHECKER": "mcp_sql.conf.deny_unconfigured_mfa",
    # `app_label.ModelName` of a Django session model carrying a `user`
    # FK column. When set, `MCPOAuth2Authentication` runs an additional
    # session-existence gate per request (the runtime half of "Option D
    # session-trust": token usefulness bounded by the consumer's
    # `SESSION_COOKIE_AGE` rather than just the 6h OAuth TTL). When
    # `None` (the default), the gate is skipped — the OAuth token's 6h
    # expiry plus the explicit logout-revocation signal become the only
    # token-lifetime bounds.
    #
    # Default is `None` rather than `"sessions.Session"` because stock
    # `django.contrib.sessions.Session` has no `user` FK — the gate's
    # `.filter(user=user, ...)` query would raise `FieldError` against
    # the stock model. Consumers wanting the runtime gate point this at
    # their own session-with-user model. The upstream `django-user-sessions`
    # package is unmaintained with a known unfixed security issue, so
    # vendoring a fork is the recommended path rather than pulling it
    # directly.
    "SESSION_MODEL": None,
    # === OAuth identifiers ===
    #
    # Canonical `Application.name` for the curated migration-0005 OAuth
    # client. `MCPOAuth2Validator` / `MCPOAuth2Authentication` / the
    # logout signal recognise it by exact equality. Use
    # `APPLICATION_NAME_PREFIX` below for the dynamically-registered
    # (Phase 3.6 RFC 7591) shape. Override only if you're running
    # multiple disjoint MCP surfaces in one Django project and need
    # name disambiguation; the canonical default works for every
    # single-surface deployment.
    "APPLICATION_NAME": "mcp-sql",
    # Prefix used to recognise every dynamically-registered
    # `Application` (Phase 3.6 RFC 7591), each named
    # `<APPLICATION_NAME>-<urlsafe16>`. The trailing dash is
    # **structural** — without it `startswith("mcp-sql")` would match
    # both the canonical row and every DCR-minted row, defeating the
    # consent-screen asymmetry between operator-provisioned and
    # anonymous-registered clients (see `docs/architecture.md` "Watch out: trailing
    # dash" for the full rationale).
    "APPLICATION_NAME_PREFIX": "mcp-sql-",
    # Single OAuth scope minted, validated, and re-checked on every MCP
    # request. The colon is OAuth scope convention (`category:resource`)
    # and is meaningful — `MCPOAuth2Validator.validate_scopes` rejects
    # any other scope set including the empty set. Change only if a
    # consumer needs to coexist with another OAuth client they are
    # already running on the same DOT install.
    "SCOPE": "mcp:sql",
    # === Postgres / DB alias ===
    #
    # Django DB alias name for the read-only connection. Must appear as a
    # key in `DATABASES` with `ATOMIC_REQUESTS=False`, `CONN_MAX_AGE=0`,
    # and an `application_name` distinguishing it from the default alias.
    # The executor asserts `connection.alias == DB_ALIAS` before issuing
    # any SELECT — a misconfigured `DATABASES` that omitted or remapped
    # this alias raises `ExecutorMisconfiguredError` loudly. Override if
    # your project has an alias collision; the `DATABASES["mcp_readonly"]`
    # key in `base.py` must change in lockstep. One alias serves every
    # profile; tiers are separated by role (`SET LOCAL ROLE`), not by alias.
    "DB_ALIAS": "mcp_readonly",
    # === Profiles (access tiers) ===
    #
    # Each profile is one access tier:
    #   ROLE                — NOLOGIN Postgres role granted SELECT on this
    #                         tier's tables; entered via `SET LOCAL ROLE`
    #                         (see `session.enter_readonly_session`) and
    #                         referenced by `grants.py` / `role_setup.sql`.
    #   PERMISSION_CODENAME — Django permission (content_type `mcpquerylog`)
    #                         whose EXPLICIT assignment binds a user to this
    #                         tier; dotted form `mcp_sql.<codename>`. Must be
    #                         unique across profiles (resolution counts
    #                         distinct codenames — see `resolve_profile`).
    #   GROUP_NAME          — Django Group carrying that permission; admins
    #                         add users to it to confer the tier.
    #   ALLOWED_MODELS      — this tier's `app_label.ModelName` whitelist.
    #   SESSION_CONTEXT     — OPTIONAL dotted path to
    #                         `callable(user, profile) -> Mapping[str, str]
    #                         | None`; default None (dormant). Import-
    #                         checked at startup (`validate_mcp_sql_settings`
    #                         runs `import_string` on it at `ready()`), so a
    #                         typo'd path fails EVERY process at boot — and
    #                         resolved eagerly at the first `profiles()` call
    #                         (NOT lazily like MFA_CHECKER). The per-row-
    #                         context escape hatch — see
    #                         `docs/architecture.md`.
    #
    # Per-profile groups/permissions are provisioned idempotently by the
    # `post_migrate` receiver in `signals.py`. A user must be assigned to
    # EXACTLY ONE profile (fail-closed: 0 → deny, >1 → deny).
    #
    # The in-package default ships a single `default` profile reproducing
    # the package's original flat behaviour (the consumer fills in
    # ALLOWED_MODELS). Multi-tier consumers add more profiles; each
    # profile's ROLE / PERMISSION_CODENAME / GROUP_NAME must be unique.
    "PROFILES": {
        "default": {
            "ROLE": "mcp_readonly_role",
            "PERMISSION_CODENAME": "use_mcp_session",
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": [],
        },
    },
    # === Declared clients ===
    #
    # MCP clients that authenticate against a FIXED callback rather than
    # registering themselves through RFC 7591 DCR. Each entry provisions a
    # public/PKCE `Application` at `migrate` whose derived client_id the
    # operator pastes into the provider's connector (secret blank) — the
    # `mcp_sql_clients` management command prints them.
    #
    # Keyed by slug. `LABEL` is the operator-authored name shown on the
    # consent screen; `REDIRECTS` is a list of {"MATCH": "exact"|"prefix",
    # "URI": ...} rules, so one provider means one client_id even when it
    # calls back from several shapes.
    #
    # The client_id namespace is DERIVED from the redirect scheme —
    # all-https yields "<PREFIX>cloud.<slug>", all-loopback yields
    # "<PREFIX>local.<slug>", and a mixed entry is a boot error. See
    # `clients.py` for why (short version: one client_id must never span a
    # provider-hosted and a machine-local surface, or the audit trail cannot
    # tell them apart).
    #
    # These ship ON. A declared key replaces its default wholesale, so
    # `"CLIENTS": {}` turns them all off and a smaller dict keeps only what
    # it names. OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"] must contain
    # "http" always (/o/register mints RFC 8252 loopback callbacks) and
    # "https" while any https client is declared; DOT's own default has both.
    # Runbook: docs/oauth.md → "Clients".
    "CLIENTS": {
        "claude": {
            "LABEL": "Claude.ai",
            "REDIRECTS": [
                {"MATCH": "exact", "URI": "https://claude.ai/api/mcp/auth_callback"},
            ],
        },
        "chatgpt": {
            "LABEL": "ChatGPT",
            # Per-instance callback (`/connector/oauth/{id}`) — prefix-matched
            # by `oauth._redirect_under_prefix`, anchored at the trailing `/`.
            "REDIRECTS": [
                {"MATCH": "prefix", "URI": "https://chatgpt.com/connector/oauth/"},
            ],
        },
        "cursor": {
            "LABEL": "Cursor",
            # Cursor's hosted surface (web + Cursor Agents) only. Its desktop
            # app and CLI register through DCR against a fixed loopback port
            # and so get their own `mcp-sql-<token>` identity — deliberately
            # NOT a second URI here, which would merge two trust surfaces
            # under one client_id. docs/oauth.md covers the static-config
            # fallback for operators who need it.
            "REDIRECTS": [
                {
                    "MATCH": "exact",
                    "URI": "https://www.cursor.com/agents/mcp/oauth/callback",
                },
            ],
        },
    },
    # === Query limits ===
    #
    # DEFAULT_LIMIT applies when neither the caller nor the SQL sets one;
    # HARD_LIMIT caps every query regardless (the executor clamps to
    # `min(kwarg, SQL LIMIT, HARD_LIMIT)`); BYTES_LIMIT caps the serialized
    # result payload. Deliberately conservative — an agent that needs more
    # rows can ask for them explicitly up to HARD_LIMIT, whereas a generous
    # default silently ships large result sets to a model context.
    "LIMITS": {
        "DEFAULT_LIMIT": 10,
        "HARD_LIMIT": 100,
        "BYTES_LIMIT": 256 * 1024,
    },
    # Reject `SELECT *` (`parser.parse_and_validate`), forcing explicit
    # column lists: bounds what a broad query can surface, and keeps a later
    # column addition from silently widening every existing agent query.
    "BAN_SELECT_STAR": True,
    # === Observability ===
    #
    # `{decision: {window_seconds: threshold}}` per-user query-volume
    # tripwires (`observability.record_query_volume`). One `logger.error` —
    # i.e. one Sentry event — per (user, decision, window) crossing. ALERT
    # ONLY: crossing a threshold never blocks a query.
    "VOLUME_ALERT_THRESHOLDS": {
        "allowed": {3600: 50, 86400: 150},
        "rejected": {3600: 50, 86400: 150},
    },
    # Silent per-IP block shared by the bad-bearer path on `/mcp/sql/` and
    # anonymous DCR at `/o/register` (`throttle`). Once an IP crosses
    # THRESHOLD within WINDOW_SECONDS it keeps getting normal-looking
    # responses that do nothing — a visible 429 would let an attacker pace
    # just under the limit.
    "BAD_TOKEN_IP_THRESHOLD": 100,
    "BAD_TOKEN_IP_WINDOW_SECONDS": 21600,
}


# Keys whose value is a dotted import path to be resolved to the actual
# Python object on first access (and re-resolved when the setting
# changes). Mirrors DRF's `IMPORT_STRINGS` set.
IMPORT_STRINGS: frozenset[str] = frozenset({"MFA_CHECKER"})


class MCPSQLSettings:
    """Lazy accessor for `settings.MCP_SQL` with in-package defaults.

    Attribute access reads from `django.conf.settings.MCP_SQL[name]`,
    falls back to `DEFAULTS[name]`, and resolves dotted paths listed in
    `IMPORT_STRINGS` to their referent. Resolved values are cached on
    the instance until `reload()` flushes them (called automatically on
    `setting_changed`).

    The accessor is the single canonical surface for every `MCP_SQL`
    key — call sites use `mcp_sql_settings.X` instead of
    `settings.MCP_SQL["X"]` so the in-package default, dotted-path
    resolution, and reload semantics happen in one place.
    """

    def __init__(self) -> None:
        self._cached: dict[str, Any] = {}
        self._profiles: dict[str, Profile] | None = None
        self._clients: dict[str, DeclaredClient] | None = None

    def __getattr__(self, name: str) -> Any:
        # `__getattr__` is only called when the attribute is NOT already
        # set on the instance — so the `_cached` instance dict, which IS
        # set in `__init__`, never re-enters here. Recursion-safe.
        if name not in DEFAULTS:
            msg = f"Unknown MCP_SQL setting: {name!r}"
            raise AttributeError(msg)
        cached = self._cached
        if name in cached:
            return cached[name]
        user_cfg = getattr(settings, "MCP_SQL", {})
        raw = user_cfg.get(name, DEFAULTS[name])
        value = import_string(raw) if name in IMPORT_STRINGS else raw
        cached[name] = value
        return value

    def reload(self) -> None:
        """Discard cached values; next access re-reads from settings.

        Called automatically by the `setting_changed` receiver below
        when `settings.MCP_SQL` changes — i.e. on every
        `@override_settings(MCP_SQL=...)` enter/exit, on every
        `settings` fixture mutation, and on every direct
        `settings.MCP_SQL = ...` assignment.
        """
        self._cached.clear()
        self._profiles = None
        self._clients = None

    def profiles(self) -> dict[str, Profile]:
        """Resolve `MCP_SQL["PROFILES"]` into `{name: Profile}`.

        Each entry's optional `SESSION_CONTEXT` dotted path is resolved to
        its callable (or `None`). Cached until `reload()`, so
        `@override_settings(MCP_SQL=...)` re-reads between tests.
        """
        if self._profiles is not None:
            return self._profiles
        user_cfg = getattr(settings, "MCP_SQL", {})
        raw = user_cfg.get("PROFILES", DEFAULTS["PROFILES"])
        built: dict[str, Profile] = {}
        for name, entry in raw.items():
            ctx = entry.get("SESSION_CONTEXT")
            built[name] = Profile(
                name=name,
                role=entry["ROLE"],
                codename=entry["PERMISSION_CODENAME"],
                group_name=entry["GROUP_NAME"],
                allowed_models=tuple(entry["ALLOWED_MODELS"]),
                session_context=import_string(ctx) if ctx else None,
            )
        self._profiles = built
        return built

    def clients(self) -> dict[str, DeclaredClient]:
        """Resolve `MCP_SQL["CLIENTS"]` into `{client_id: DeclaredClient}`.

        Keyed by the derived `client_id` so recognition
        (`consts.is_mcp_application_name`) and the redirect validator
        (`oauth.MCPOAuth2Validator.validate_redirect_uri`) can look it up by
        the client_id DOT presents. Cached until `reload()`, so
        `@override_settings(MCP_SQL=...)` re-reads between tests.

        Normalisation lives in `clients.build_clients`, which boot validation
        calls on the same input — so what the validator blessed at startup and
        what the runtime uses can never drift. A malformed entry raises
        `ValueError` here; in a validated process that is unreachable, and in
        a test that overrode settings past the validator it is the intended
        loud failure.
        """
        if self._clients is not None:
            return self._clients
        user_cfg = getattr(settings, "MCP_SQL", {})
        raw = user_cfg.get("CLIENTS", DEFAULTS["CLIENTS"])
        built = build_clients(raw, self.APPLICATION_NAME_PREFIX)
        self._clients = built
        return built

    def resolve_profile(self, user: Any) -> Profile | ResolutionOutcome:
        """Bind `user` to exactly one profile by EXPLICIT permission assignment.

        Queries the assignment rows directly (group-held OR directly
        granted) rather than `has_perm`, so it is blind to `is_superuser`:
        Django returns every permission for an active superuser, which would
        make superusers ambiguous and confer access they were never
        explicitly assigned. Fail-closed: no match → `NO_PERM`; more than
        one distinct profile codename → `AMBIGUOUS_PROFILE` (never guess).
        A codename held via BOTH a group and a direct grant collapses to one
        (distinct), so it is not falsely flagged ambiguous.
        """
        from django.contrib.auth.models import Permission
        from django.db.models import Q

        by_codename = {p.codename: p for p in self.profiles().values()}
        matched = set(
            Permission.objects.filter(
                Q(group__user=user) | Q(user=user),
                # Pin to the exact content type the provisioning signal
                # (`signals.provision_mcp_profiles`) creates these perms on, so
                # a profile codename can never collide with a default
                # add/change/delete/view permission on another mcp_sql model.
                content_type__app_label="mcp_sql",
                content_type__model="mcpquerylog",
                codename__in=list(by_codename),
            ).values_list("codename", flat=True)
        )
        if not matched:
            return ResolutionOutcome.NO_PERM
        if len(matched) > 1:
            return ResolutionOutcome.AMBIGUOUS_PROFILE
        return by_codename[next(iter(matched))]


mcp_sql_settings = MCPSQLSettings()


def merge_config(cfg: Mapping[str, Any]) -> dict[str, Any]:
    """`DEFAULTS` overlaid with `cfg`. See `merged_config` for the rule.

    Shallow by construction: a value that came from `DEFAULTS` is the SAME
    object every caller gets. Never mutate what this returns — poking
    `mcp_sql_config()["LIMITS"]["HARD_LIMIT"]` would rewrite the module-level
    default for the whole process. Rebind the key instead.
    """
    return {**DEFAULTS, **cfg}


def merged_config() -> dict[str, Any]:
    """`DEFAULTS` overlaid with the consumer's `settings.MCP_SQL`.

    ONE merge rule, no exceptions: a declared key replaces its default
    **wholesale**. Declaring `LIMITS` means declaring all three of its
    members — a per-member merge would let a consumer end up running a value
    they never wrote and cannot find in their settings file, which is a worse
    failure than a `KeyError` at boot (and boot validation raises exactly
    that, by name). This is the same rule `MCPSQLSettings.__getattr__`
    applies per attribute; keeping the two identical is why the accessor and
    this function can be used interchangeably.

    `settings.MCP_SQL` may be absent entirely — the package boots on
    defaults.
    """
    return merge_config(getattr(settings, "MCP_SQL", {}))


def mcp_sql_config() -> "McpSqlSettings":
    """Typed view of the merged `MCP_SQL` config.

    `validate_mcp_sql_settings` has already pinned the merged mapping's shape
    to `McpSqlSettings` at startup, so this casts it to that validated
    TypedDict for typed key access at the consuming call sites (executor
    LIMITS / BAN_SELECT_STAR, observability thresholds, throttle knobs).
    """
    return cast("McpSqlSettings", merged_config())


@receiver(setting_changed)
def _reload_on_setting_changed(sender, setting, **kwargs):
    if setting == "MCP_SQL":
        mcp_sql_settings.reload()
