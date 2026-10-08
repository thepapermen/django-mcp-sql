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
import socket
import sys
from collections.abc import Iterable
from collections.abc import Mapping
from typing import Any
from urllib.parse import ParseResult
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

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from mcp_sql.clients import DCR_SUFFIX_LENGTH
from mcp_sql.clients import LOOPBACK_HOST
from mcp_sql.clients import MATCH_EXACT
from mcp_sql.clients import MATCH_PREFIX
from mcp_sql.clients import VALID_MATCHES
from mcp_sql.clients import ClientKind
from mcp_sql.clients import build_clients
from mcp_sql.clients import redirect_kind
from mcp_sql.conf import merge_config
from pydantic import ConfigDict
from pydantic import TypeAdapter

# `extra="forbid"` on every one of these shapes. A typo'd key would otherwise
# be silently ignored and the default used in its place — the consumer sees
# their setting having no effect, with nothing in the logs. It is also what
# makes a removed/renamed key (see `_REMOVED_KEYS`) a loud boot failure
# rather than a silent revert to the default.
_FORBID_EXTRA = ConfigDict(extra="forbid")


class McpSqlLimits(TypedDict):
    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    DEFAULT_LIMIT: int
    HARD_LIMIT: int
    BYTES_LIMIT: int


class ProfileEntry(TypedDict):
    """One `MCP_SQL["PROFILES"]` entry — an access tier. See `conf.Profile`."""

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    ROLE: str
    PERMISSION_CODENAME: str
    GROUP_NAME: str
    ALLOWED_MODELS: list[str]
    # Optional dormant per-row-context hook: dotted path to
    # `callable(user, profile) -> Mapping[str, str] | None`. Default None.
    SESSION_CONTEXT: NotRequired[str | None]


class RedirectRuleEntry(TypedDict):
    """One rule in a client's `REDIRECTS`. See `clients.RedirectRule`."""

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    # "exact" | "prefix" — value-checked in `_validate_clients`.
    MATCH: str
    URI: str


class ClientEntry(TypedDict):
    """One `MCP_SQL["CLIENTS"]` entry. See `clients.DeclaredClient`."""

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    REDIRECTS: list[RedirectRuleEntry]
    # Consent-screen display name. Operator-authored — never taken from the
    # client itself. Defaults to the entry's slug.
    LABEL: NotRequired[str]


class McpSqlSettings(TypedDict):
    """The `MCP_SQL` dict, AFTER `conf.merge_config` overlays the defaults.

    Every key is `NotRequired` because every key has an in-package default
    (`conf.DEFAULTS`) — a consumer declares the subset they want to change,
    or omits `MCP_SQL` entirely. The merged mapping validated here always
    carries all of them.
    """

    __pydantic_config__ = _FORBID_EXTRA  # type: ignore[misc]  # pydantic's TypedDict config hook; mypy only expects field declarations here.

    # One entry per access tier; keys are profile names (e.g. "default").
    PROFILES: NotRequired[dict[str, ProfileEntry]]
    BAN_SELECT_STAR: NotRequired[bool]
    LIMITS: NotRequired[McpSqlLimits]
    # `{decision: {window_seconds: threshold}}` — per-user volume tripwires.
    # `decision` keys mirror `MCPQueryLog.DECISION_*` ("allowed"/"rejected");
    # the value-level checks below enforce that closed set.
    VOLUME_ALERT_THRESHOLDS: NotRequired[dict[str, dict[int, int]]]
    BAD_TOKEN_IP_THRESHOLD: NotRequired[int]
    BAD_TOKEN_IP_WINDOW_SECONDS: NotRequired[int]
    RESOURCE_NAME: NotRequired[str]
    MFA_CHECKER: NotRequired[str]
    # `None` (the default) disables the runtime session-existence gate.
    SESSION_MODEL: NotRequired[str | None]
    APPLICATION_NAME: NotRequired[str]
    APPLICATION_NAME_PREFIX: NotRequired[str]
    SCOPE: NotRequired[str]
    DB_ALIAS: NotRequired[str]
    # Declared (non-DCR) clients, keyed by slug. `{}` turns them all off.
    CLIENTS: NotRequired[dict[str, ClientEntry]]


# Keys that existed in an earlier release and are gone. Checked by name so the
# upgrade error says what to do, instead of pydantic's generic "extra inputs
# are not permitted". Worth the special case: silently ignoring a stale
# CLOUD_CLIENTS would empty CLIENTS, de-recognise that consumer's cloud
# clients, and start rejecting their live tokens at the next request.
_REMOVED_KEYS = {
    "CLOUD_CLIENTS": (
        "renamed to CLIENTS and reshaped: a dict keyed by slug, each entry "
        "carrying a REDIRECTS list of {'MATCH': 'exact'|'prefix', 'URI': ...} "
        "rules instead of the singular REDIRECT_MATCH/REDIRECT_URI pair. "
        "CLIENTS now ships ON by default (claude, chatgpt, cursor) — set "
        "CLIENTS to {} to run loopback-only. See docs/oauth.md → 'Clients'."
    ),
}


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


# A client slug; its derived client_id is
# `<APPLICATION_NAME_PREFIX><kind>.<slug>` (see `clients.build_clients`). The
# `.` after the kind keeps that id provably disjoint from the DCR
# `<prefix><22-urlsafe>` shape, so no slug-length guard against the DCR shape
# is needed here. Its length IS bounded, by the installed DOT `Application`
# columns the id is written to (`_validate_client_id_lengths`).
_CLIENT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def _validate_redirect_uri(name: str, match: str, uri: str) -> None:
    """A declared client's redirect URI must be safe to admit as a fixed,
    non-DCR OAuth callback.

    Two admissible shapes, and `clients.redirect_kind` decides which one this
    is (that classification also picks the client's namespace, so the checks
    below are what keeps each namespace's promise):

    * **https** — the provider-hosted shape. Rejects anything an attacker
      could weaponise if it reached DOT's exact matching or the prefix
      override: a userinfo component, a `*` wildcard, a `..` traversal
      segment, embedded whitespace — and any host that is not a plain ASCII
      DNS name or that names the user's own machine (`_https_host_problems`),
      since the derived `cloud` kind is a claim about where the code goes.
      A "prefix" entry must additionally carry a non-root path AND
      end with `/`, so the runtime match is anchored at a segment boundary and
      a sibling like `.../oauthEVIL` cannot slip past `.../oauth`.
    * **http on `localhost`** — the machine-local shape, for a client that
      pins a fixed loopback port and cannot use DCR (Cursor's static
      `mcp.json` path). "exact" only: prefix-matching a loopback URI would
      admit ANY path on that port. The port must be explicit, because
      `http://localhost/cb` silently means port 80 and an operator writing
      this always has a specific port in mind. `127.0.0.1` / `::1` are
      refused by `redirect_kind` itself — DOT port-wildcards those two
      literals, which would quietly widen an exact rule into "any port on the
      user's machine".

    Mirrors the care in `views/registration.py::_is_loopback_redirect`.
    """
    kind = redirect_kind(uri)
    if kind is None:
        msg = (
            f"MCP_SQL.CLIENTS[{name!r}] redirect URI {uri!r} is invalid: must be "
            f"either an https callback or an "
            f"http://{LOOPBACK_HOST}:<port>/<path> loopback one. A custom "
            f"scheme (e.g. 'cursor://') is not supported — admitting one would "
            f"require widening OAUTH2_PROVIDER['ALLOWED_REDIRECT_URI_SCHEMES'], "
            f"which relaxes redirect handling for every OAuth client in the "
            f"project, not just this one"
        )
        raise ImproperlyConfigured(msg)

    parsed = urlparse(uri)
    problems = [
        *_universal_redirect_problems(uri, parsed),
        *(_https_host_problems(parsed) if kind is ClientKind.CLOUD else ()),
        *(_prefix_problems(kind, parsed) if match == MATCH_PREFIX else ()),
        *(_loopback_problems(parsed) if kind is ClientKind.LOCAL else ()),
    ]
    if problems:
        joined = "; ".join(problems)
        msg = (
            f"MCP_SQL.CLIENTS[{name!r}] redirect URI {uri!r} is invalid: must {joined}"
        )
        raise ImproperlyConfigured(msg)


# The shape an https declared callback's host must have: a DNS name in its
# ASCII form — LDH labels (letters, digits, inner hyphens) joined by dots, with
# an optional root dot. `urlparse` has already lowercased it. An
# internationalised name is admitted in its punycode (`xn--`) A-label form,
# which is also how every browser puts it on the wire.
_DNS_HOSTNAME_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.?"
)

# Special-use suffixes that never resolve in public DNS — only on the user's
# own machine or network — so no provider's callback can live under one: the
# RFC 6761 reserved `localhost`, RFC 6762 mDNS `local` (which includes the
# machine's own `<hostname>.local`), RFC 8375 `home.arpa`, ICANN's private-use
# `internal`, and the `localdomain*` pseudo-TLDs of the stock `/etc/hosts`
# loopback aliases (`localhost.localdomain`, `localhost4.localdomain4`, …).
# The single-label aliases (`localhost4`, `ip6-localhost`, the machine's own
# hostname) are caught by the fully-qualified-name rule instead.
_LOCAL_SCOPE_SUFFIXES = (
    "localhost",
    "local",
    "home.arpa",
    "internal",
    "localdomain",
    "localdomain4",
    "localdomain6",
)


def _is_ipv4_literal(host: str) -> bool:
    """Does the resolver read `host` as an IPv4 address?

    Asked of `socket.inet_aton` rather than `ipaddress`, which demands four
    dotted-decimal octets: the resolver (and the WHATWG URL parser every
    browser uses) also takes the abbreviated, octal, hex and integer forms —
    `0`, `127.1`, `0x7f.1`, `0177.0.0.1`, `2130706433`. Only ever called on a
    string that already passed `_DNS_HOSTNAME_RE`, so it is ASCII with no NUL
    and `inet_aton` can only raise `OSError`.
    """
    try:
        socket.inet_aton(host)
    except OSError:
        return False
    return True


def _https_host_problems(parsed: ParseResult) -> list[str]:
    """Extra checks for an https (`cloud`-kind) rule's host.

    `clients.redirect_kind` derives kind from the SCHEME, so any https
    callback becomes `cloud`: namespaced `mcp-sql-cloud.<slug>`, exempt from
    the loopback hardening in `_loopback_problems` (exact-match only, explicit
    port, non-root path), and written as `client_kind="cloud"` on every audit
    row. If its host is really loopback, the browser that follows the
    redirect delivers the code to the END USER's own machine while the audit
    trail says "provider-hosted" — exactly the disagreement the derivation
    exists to rule out.

    So this is an allow-shape, not a loopback detector. Enumerating loopback
    spellings lost every time it was tried: percent-encoding, fullwidth and
    ideographic-dot forms, `0` / `0.0.0.0`, `*.localhost`, and IPv4-mapped
    IPv6 (which `ipaddress` on older Pythons, 3.12.3 among them, does not
    even call loopback) all slipped a detector that caught `127.0.0.0/8` and
    `::1`. A provider's
    callback is always a fully-qualified ASCII DNS name, so require exactly
    that: refuse every IP literal outright, loopback or not; refuse the
    special-use suffixes that only resolve locally (`*.localhost`, `*.local`,
    `*.home.arpa`, `*.internal`, `*.localdomain`, …); and refuse every
    single-label name, which can only resolve somewhere local —
    that one rule covers `localhost4`, `ip6-localhost` and the machine's own
    hostname, where a list of distro aliases kept missing entries. What a
    syntactic check cannot see is a public DNS name that happens to resolve
    to loopback (`127.0.0.1.nip.io`) — this is operator-authored config, and
    that residue is the operator's to avoid.
    """
    # Never empty here: `redirect_kind` only classifies a URI that has a
    # hostname as cloud.
    hostname = parsed.hostname or ""
    if not _DNS_HOSTNAME_RE.fullmatch(hostname):
        return [
            "name its host as an ASCII DNS name — letters, digits, hyphens "
            "and dots, an internationalised domain in its punycode ('xn--') "
            "form. Percent-encoded, non-ASCII and IPv6-literal hosts are "
            "refused outright: each can spell a loopback host past this check"
        ]
    host = hostname.removesuffix(".")
    if _is_ipv4_literal(host):
        return [
            "not use an IP-literal host — a provider-hosted callback is a DNS "
            "name, and a literal (including shorthand such as '127.1' or '0') "
            "is how a loopback address is disguised"
        ]
    if any(host == sfx or host.endswith(f".{sfx}") for sfx in _LOCAL_SCOPE_SUFFIXES):
        return [
            "not point https at a local-scope name (under "
            + ", ".join(f"'.{sfx}'" for sfx in _LOCAL_SCOPE_SUFFIXES)
            + ") — those never resolve in public DNS, and kind is derived from "
            "the scheme, so this would be namespaced and audited as a hosted "
            f"'{ClientKind.CLOUD}' client while the browser following the "
            "redirect delivers the code to the end user's own machine or "
            f"network; use an http://{LOOPBACK_HOST}:<port>/<path> loopback "
            "entry (or let the client self-register via /o/register) instead"
        ]
    if "." not in host:
        return [
            "use a fully-qualified host name — a single-label name (such as "
            "'localhost4', 'ip6-localhost' or a machine's own hostname) only "
            "resolves through /etc/hosts or a search domain, i.e. somewhere "
            "local, never at a provider"
        ]
    return []


def _universal_redirect_problems(uri: str, parsed: ParseResult) -> list[str]:
    """Checks that hold for every declared redirect URI, whatever its kind."""
    problems: list[str] = []
    if "@" in parsed.netloc:
        # Any `@` in the authority, not just a non-empty user or password:
        # `https://@claude.ai/cb` parses with username "" and so passed a
        # `username or password` test, yet it is still a userinfo component —
        # and DOT >= 3.4's matcher refuses a registered URI carrying one, so
        # the entry would boot clean and then never match. No real callback
        # has one; refuse the whole class.
        problems.append(
            "carry no userinfo component (no '@' in the authority, not even "
            "an empty one)"
        )
    if "*" in uri:
        problems.append("contain no '*' wildcard")
    if uri.split() != [uri]:
        # `signals.provision_mcp_clients` stores these as `" ".join(...)` and
        # DOT matches with `.split()`, so embedded whitespace would register a
        # second, unvalidated URI. Operator-authored rather than attacker-
        # supplied here, but the same storage contract applies, and the
        # matching guard on the anonymous DCR path is
        # `registration._is_loopback_redirect`.
        problems.append("contain no whitespace")
    if ".." in unquote(parsed.path).split("/"):
        problems.append("contain no '..' path segment (literal or encoded)")
    return problems


def _prefix_problems(kind: ClientKind, parsed: ParseResult) -> list[str]:
    """Extra checks for a `MATCH: "prefix"` rule."""
    problems: list[str] = []
    if kind is ClientKind.LOCAL:
        problems.append(
            f"use MATCH '{MATCH_EXACT}' — prefix matching a loopback URI would "
            f"admit any path on that port"
        )
    if parsed.path.strip("/") == "":
        problems.append("include a non-root path for prefix matching")
    elif not parsed.path.endswith("/"):
        problems.append("end with '/' for prefix matching (segment-anchored)")
    return problems


def _loopback_problems(parsed: ParseResult) -> list[str]:
    """Extra checks for a loopback (`local`-kind) rule."""
    problems: list[str] = []
    if parsed.port is None:
        problems.append("state an explicit port")
    if parsed.path.strip("/") == "":
        problems.append("include a non-root path")
    return problems


def _validate_redirect_schemes(kinds: set[ClientKind]) -> None:
    """Whatever schemes the declared clients need must be allowed by DOT.

    `ALLOWED_REDIRECT_URI_SCHEMES` is enforced by DOT when it issues the 302,
    so a mismatch fails opaquely at `/o/authorize/` — long after the operator
    could connect it to their config. Check it at boot instead. (A "prefix"
    client bypasses DOT's stock check via the `_redirect_under_prefix`
    override, but the requirement is applied uniformly anyway, so a
    prefix-only setup can't silently break the day an exact client is added.)

    Read through DOT's OWN accessor rather than off `settings.OAUTH2_PROVIDER`
    with a hardcoded fallback. `oauth2_settings` applies DOT's defaults, so
    this checks the value DOT will actually enforce — and it stays right if
    DOT ever changes that default, where a re-declared fallback here would
    silently start disagreeing with the code doing the enforcing.

    DOT's default is `["http", "https"]`, which already covers every shape
    this package admits, so a consumer never needs to declare the setting at
    all. This only bites one who narrowed it.
    """
    from oauth2_provider.settings import oauth2_settings

    required = {
        "https": ClientKind.CLOUD in kinds,
        # Unconditional, not `ClientKind.LOCAL in kinds`. `/o/register` is
        # mounted unconditionally and only ever mints `http://` loopback
        # callbacks, so the DCR surface always needs `http` — and DOT enforces
        # the scheme list at the authorization redirect (`http.py`
        # `OAuth2ResponseRedirect`), not at boot. A consumer who narrowed the
        # list to `["https"]` (plausible now the shipped clients are all
        # cloud) would boot clean and then have every DCR client — Claude
        # Code, Cursor desktop and CLI — fail opaquely at `/o/authorize/`,
        # which is the exact failure this guard exists to turn into a boot
        # error. "Feature on -> require the safe setting", and DCR is
        # always on.
        "http": True,
    }
    schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
    for scheme, needed in required.items():
        if needed and scheme not in schemes:
            reason = (
                f"MCP_SQL.CLIENTS declares a {scheme} callback"
                if scheme == "https"
                else "the RFC 7591 registration endpoint at /o/register mints "
                "http loopback callbacks for self-registering clients "
                "(Claude Code, Cursor desktop/CLI)"
            )
            msg = (
                f"{reason}, but "
                f"OAUTH2_PROVIDER['ALLOWED_REDIRECT_URI_SCHEMES'] = "
                f"{list(schemes)!r} does not include {scheme!r}. Add it"
                + (
                    " (the registration endpoint is always mounted, so this "
                    "one cannot be resolved by dropping clients)"
                    if scheme == "http"
                    else ", or drop those clients from MCP_SQL.CLIENTS"
                )
                + f". Note that this "
                f"setting is install-global: it relaxes redirect handling for "
                f"every OAuth application in the project. DOT's own default "
                f"({['http', 'https']!r}) already covers both, so the simplest "
                f"fix is usually to stop declaring the key."
            )
            raise ImproperlyConfigured(msg)


def _validate_localhost_loopback(kinds: set[ClientKind]) -> None:
    """A declared `local` client's exact rule must stay exact.

    DOT >= 3.4's `ALLOW_LOCALHOST_LOOPBACK=True` extends the RFC 8252 any-port
    treatment DOT already gives `127.0.0.1` / `::1` to `localhost`
    (`oauth2_provider.models.check_redirect_to_uri_allowed`). `localhost` is
    the ONLY host a `local` entry may use precisely because DOT did not
    port-wildcard it (`clients.LOOPBACK_HOST`), so with the flag on, a declared
    `http://localhost:8787/callback` silently admits every port on the user's
    machine — the widening the `local` rules exist to forbid, with nothing at
    boot or in the logs to say so.

    "Feature on -> require the safe setting": refused whenever a `local` client
    is declared, and only then. The flag is install-global, and it changes
    nothing else this package promises — DCR clients and the curated
    Application already live with any-port loopback through `127.0.0.1` /
    `::1`, and with the flag on a DCR `localhost` callback merely joins them —
    so refusing it unconditionally would veto a consumer's unrelated OAuth
    config for no gain. `getattr` with a default because the setting does not
    exist before DOT 3.4, whose settings object raises `AttributeError` for an
    unknown name.
    """
    from oauth2_provider.settings import oauth2_settings

    if ClientKind.LOCAL in kinds and getattr(
        oauth2_settings, "ALLOW_LOCALHOST_LOOPBACK", False
    ):
        msg = (
            f"MCP_SQL.CLIENTS declares a '{ClientKind.LOCAL}' (loopback) client, "
            f"but OAUTH2_PROVIDER['ALLOW_LOCALHOST_LOOPBACK'] is True. DOT then "
            f"matches a registered http://{LOOPBACK_HOST} callback on ANY port, "
            f"silently widening the declared client's exact "
            f"http://{LOOPBACK_HOST}:<port>/<path> rule into 'any port on the "
            f"user's machine'. Set ALLOW_LOCALHOST_LOOPBACK to False, or drop "
            f"the '{ClientKind.LOCAL}' entries from MCP_SQL.CLIENTS (clients that "
            f"can self-register via /o/register need no entry)."
        )
        raise ImproperlyConfigured(msg)


def _application_id_width() -> int | None:
    """The longest client_id this package may write: the smaller of the
    installed (possibly swapped) `Application` model's `client_id` (DOT 3.2 /
    3.3: `max_length=100`; 3.4: 255) and `name` (255) columns, because every
    row the package writes carries one string in both (migration 0005,
    `/o/register`, `signals.provision_mcp_clients`) and recognition reads the
    name back. A column without a `max_length` (a swapped model's
    `TextField`) imposes none; `None` when neither does.
    """
    from oauth2_provider.models import get_application_model

    meta = get_application_model()._meta
    widths = [
        width
        for width in (
            meta.get_field("client_id").max_length,
            meta.get_field("name").max_length,
        )
        if width is not None
    ]
    return min(widths) if widths else None


def _validate_application_name_lengths(application_name: str, prefix: str) -> None:
    """The curated and DCR client_ids must fit the `Application` columns.

    Migration 0005 writes `APPLICATION_NAME` verbatim to both columns, and
    `/o/register` writes `<APPLICATION_NAME_PREFIX><22-char token>`
    (`clients.DCR_SUFFIX_LENGTH`). An over-long value passed boot and then
    failed the write with a `DataError` — `migrate` for the curated row, and
    a 500 from the anonymous `/o/register` for every DCR client. Refused at
    boot instead, against `_application_id_width()`.
    """
    width = _application_id_width()
    if width is None:
        return
    if len(application_name) > width:
        msg = (
            f"MCP_SQL.APPLICATION_NAME is {len(application_name)} characters; "
            f"it is written as the curated client's client_id and name, which "
            f"must fit the installed OAuth Application's client_id and name "
            f"columns, so it may be at most {width} characters"
        )
        raise ImproperlyConfigured(msg)
    max_prefix = width - DCR_SUFFIX_LENGTH
    if len(prefix) > max_prefix:
        msg = (
            f"MCP_SQL.APPLICATION_NAME_PREFIX is {len(prefix)} characters; a "
            f"dynamically-registered client_id is the prefix plus a "
            f"{DCR_SUFFIX_LENGTH}-character token, which must fit the installed "
            f"OAuth Application's client_id and name columns ({width} "
            f"characters), so the prefix may be at most {max(max_prefix, 0)} "
            f"characters"
        )
        raise ImproperlyConfigured(msg)


def _validate_client_id_lengths(names: Iterable[str], prefix: str) -> None:
    """Every derived client_id must fit the `Application` columns it is
    written to.

    Provisioning writes the derived `<prefix><kind>.<slug>` to both
    `Application.client_id` and `Application.name` — so a longer id passed
    boot and then failed `migrate` with a `DataError` inside
    `signals.provision_mcp_clients`. The limit is `_application_id_width()`
    minus the longest derived prefix — so a slug that fits as `local` also
    fits as `cloud` and the bound does not depend on the redirect scheme.
    """
    width = _application_id_width()
    if width is None:
        return
    longest_prefix = max(
        len(f"{prefix}{kind.value}.") for kind in (ClientKind.CLOUD, ClientKind.LOCAL)
    )
    max_slug = width - longest_prefix
    for name in names:
        if len(name) > max_slug:
            msg = (
                f"MCP_SQL.CLIENTS key {name!r} is {len(name)} characters; its "
                f"derived client_id ({prefix}<kind>.{name}) must fit the "
                f"installed OAuth Application's client_id and name columns "
                f"({width} characters), so a slug may be at most "
                f"{max(max_slug, 0)} characters with APPLICATION_NAME_PREFIX "
                f"{prefix!r}"
            )
            raise ImproperlyConfigured(msg)


def _validate_clients(clients: Mapping[str, Mapping[str, Any]], prefix: str) -> None:
    """Each CLIENTS entry: a slug key (short enough for its derived client_id
    to fit the `Application` columns), MATCH in {"exact", "prefix"}, a
    hardened redirect URI per rule, and a single consistent redirect scheme
    across the entry (enforced by `clients.build_clients`, which derives the
    kind). Then the two DOT-settings guards above. `{}` is a no-op — DCR and
    the curated Application still work, the surface is just loopback-only.
    What this setting enables end-to-end: `docs/oauth.md` → "Clients"."""
    for name, entry in clients.items():
        if not _CLIENT_NAME_RE.fullmatch(name):
            msg = (
                f"MCP_SQL.CLIENTS key {name!r} must be a slug: a lowercase "
                f"letter followed by lowercase letters, digits, or hyphens"
            )
            raise ImproperlyConfigured(msg)
        for rule in entry.get("REDIRECTS") or ():
            match = rule["MATCH"]
            if match not in VALID_MATCHES:
                msg = (
                    f"MCP_SQL.CLIENTS[{name!r}] MATCH {match!r} must be one of "
                    f"{sorted(VALID_MATCHES)}"
                )
                raise ImproperlyConfigured(msg)
            _validate_redirect_uri(name, match, rule["URI"])

    # Runs the SAME normaliser the accessor uses at runtime, so a shape the
    # validator blesses is exactly the shape `conf.MCPSQLSettings.clients()`
    # will build. Also where the missing/empty-REDIRECTS and mixed-scheme
    # rejections happen.
    try:
        built = build_clients(clients, prefix)
    except ValueError as exc:
        msg = f"Invalid MCP_SQL.CLIENTS: {exc}"
        raise ImproperlyConfigured(msg) from exc

    _validate_client_id_lengths(clients, prefix)

    kinds = {client.kind for client in built.values()}
    _validate_redirect_schemes(kinds)
    _validate_localhost_loopback(kinds)


def validate_mcp_sql_settings(declared: Mapping[str, Any]) -> None:
    """Validate the consumer's `MCP_SQL` dict on startup.

    `declared` is what the consumer actually wrote — any subset of the keys,
    or `{}`. It is merged over `conf.DEFAULTS` first, so what gets validated
    is the config the package will really run, and the shipped defaults are
    themselves checked on every boot.

    - Removed keys are named explicitly, then the Pydantic TypeAdapter
      enforces the TypedDict shape (types, and no unknown keys anywhere).
    - Numeric values must be positive; `DEFAULT_LIMIT` must not exceed
      `HARD_LIMIT`.
    - Each profile in `PROFILES` has non-empty unique ROLE /
      PERMISSION_CODENAME / GROUP_NAME and `app_label.ModelName`-shaped
      `ALLOWED_MODELS`; model resolution is deferred to runtime.
    - `APPLICATION_NAME`, a DCR client_id (`APPLICATION_NAME_PREFIX` plus
      its 22-character token) and every derived declared client_id fit the
      installed `Application` model's `client_id` and `name` columns.
    - Each entry in `CLIENTS` normalises through the same builder the
      runtime accessor uses, and the redirect schemes it needs are allowed.

    Raises `ImproperlyConfigured` on any violation so Django startup
    halts with a single, focused error rather than a cascade of
    AttributeErrors at first read.
    """
    for key, guidance in _REMOVED_KEYS.items():
        if key in declared:
            msg = f"MCP_SQL.{key} is no longer supported — {guidance}"
            raise ImproperlyConfigured(msg)

    cfg = merge_config(declared)
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
    _validate_application_name_lengths(
        cfg["APPLICATION_NAME"], cfg["APPLICATION_NAME_PREFIX"]
    )
    _validate_clients(cfg["CLIENTS"], cfg["APPLICATION_NAME_PREFIX"])
