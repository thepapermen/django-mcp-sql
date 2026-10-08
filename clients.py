"""The MCP client taxonomy: every shape of OAuth client this surface admits.

Four kinds, distinguished by how the client was registered and where its
authorization code is delivered:

    curated  `mcp-sql`                — operator-provisioned (migration 0005)
    dcr      `mcp-sql-<22 urlsafe>`   — anonymous RFC 7591 self-registration
    cloud    `mcp-sql-cloud.<slug>`   — settings-declared, https callback
    local    `mcp-sql-local.<slug>`   — settings-declared, loopback callback

**The load-bearing invariant: a declared client's namespace is DERIVED from
its redirect scheme, and an entry mixing schemes is a configuration error.**
All-https yields `cloud`, all-loopback yields `local`; there is no third
option and no way to declare the kind by hand. Two consequences worth the
rule: `client_kind` on an audit row can never drift from what the client
actually is, and a single client_id can never serve both a provider-hosted
and a machine-local surface — the case that would make "which surface was
this?" unanswerable in the audit trail. Cursor is the concrete motivator:
its hosted agents call back to `https://www.cursor.com/...` while its
desktop app and CLI use a fixed loopback port, and those are different trust
surfaces that must not collapse into one identity.

Both declared namespaces carry a `.` after the kind, which keeps them
provably disjoint from the DCR suffix shape (`.` is not in the urlsafe-base64
alphabet) and from the curated name — so recognition can never leak across
kinds, and removing an entry from settings de-recognises it absolutely.

This module is deliberately **settings-free**: it turns raw config into
objects and classifies URIs, taking the `APPLICATION_NAME_PREFIX` as an
argument rather than reading it. `conf.py` (the accessor), `validation.py`
(boot checks), and `consts.py` (settings-bound recognition) all import it,
and none of them can form a cycle with it. The safety rules for a redirect
URI — what makes an https callback admissible, what makes a loopback one
admissible — live in `validation.py`, which owns the operator-facing error
messages; this module only answers "which kind is this URI".

Runbook (provider onboarding, per-client callbacks, the consent flow):
`docs/oauth.md` → "Clients".
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

# Redirect-matching strategies for one rule. "exact" is DOT's stock matcher
# (`oauth2_provider.models.redirect_to_uri_allowed`) run against the declared
# exact URIs; "prefix" is admitted by `oauth._redirect_under_prefix` for
# providers whose callback is per-instance (ChatGPT's `/connector/oauth/{id}`).
# Both read SETTINGS, never the provisioned row (`oauth.MCPOAuth2Validator`).
MATCH_EXACT = "exact"
MATCH_PREFIX = "prefix"
VALID_MATCHES = frozenset({MATCH_EXACT, MATCH_PREFIX})

# The only hostname a declared `local` client may use. `127.0.0.1` and `::1`
# are rejected BY NAME: DOT's `redirect_to_uri_allowed()` treats those two
# literals as port-wildcarded (any port matches a registered one), which would
# silently widen a declared exact rule into "any port on the user's machine".
# `localhost` gets no such treatment, so an exact rule stays exact — unless
# DOT >= 3.4's `ALLOW_LOCALHOST_LOOPBACK` is on, which is why boot validation
# refuses that flag while a `local` client is declared.
LOOPBACK_HOST = "localhost"

# Mirrors `MCPQueryLog.client_redirect` / `MCPAuthRejectionLog.client_redirect`
# `max_length`. `ClientIdentity` truncates to it so an Application with many
# registered URIs cannot overflow the column — an overflow raises `DataError`
# inside the best-effort audit writers, which swallow it and lose the row
# entirely. Pinned to the model in `tests/test_clients.py`.
REDIRECT_MAX_LENGTH = 1024


class ClientKind(StrEnum):
    """Closed vocabulary written to `MCPQueryLog.client_kind`.

    `curated` and `dcr` are recognised from the Application name's shape;
    `cloud` and `local` are derived from a declared entry's redirect scheme
    (see the module docstring). A `StrEnum` so the value goes straight into
    a `CharField` and compares equal to its plain-string form in queries.
    """

    CURATED = "curated"
    DCR = "dcr"
    CLOUD = "cloud"
    LOCAL = "local"


@dataclass(frozen=True)
class RedirectRule:
    """One redirect rule inside a `DeclaredClient`.

    `match` is `MATCH_EXACT` (a fixed callback, e.g. Claude.ai's) or
    `MATCH_PREFIX` (per-instance callbacks under a fixed host+path, e.g.
    ChatGPT's `/connector/oauth/{id}`); `uri` is that exact URL or that
    host+path prefix. A client carries a LIST of these because a provider may
    call back from more than one shape, and one provider should mean one
    pasteable client_id.
    """

    match: str
    uri: str


@dataclass(frozen=True)
class DeclaredClient:
    """One `MCP_SQL["CLIENTS"]` entry, normalised.

    `client_id` doubles as the DOT `Application.name` — provisioning
    (`signals.provision_mcp_clients`) writes the same string to both columns,
    and recognition (`consts.classify_application`) accepts a row only while
    the two agree.
    `label` is the operator-authored display name shown on the consent screen;
    it defaults to the slug and is never sourced from the client itself.
    """

    name: str
    kind: ClientKind
    client_id: str
    label: str
    redirects: tuple[RedirectRule, ...]

    @property
    def redirect_uris(self) -> tuple[str, ...]:
        """Every rule's URI — space-joined onto the `Application` by
        provisioning, for the admin and the audit trail. Redirect decisions
        never read that copy (it is refreshed only on `migrate`)."""
        return tuple(r.uri for r in self.redirects)

    @property
    def exact_uris(self) -> tuple[str, ...]:
        """Just the `MATCH_EXACT` rules' URIs — what
        `oauth.MCPOAuth2Validator.validate_redirect_uri` hands DOT's stock
        exact matcher."""
        return tuple(r.uri for r in self.redirects if r.match == MATCH_EXACT)

    @property
    def prefixes(self) -> tuple[str, ...]:
        """Just the `MATCH_PREFIX` rules' URIs — what
        `oauth.MCPOAuth2Validator.validate_redirect_uri` admits through
        `oauth._redirect_under_prefix`."""
        return tuple(r.uri for r in self.redirects if r.match == MATCH_PREFIX)


@dataclass(frozen=True)
class ClientIdentity:
    """Which client presented the token, as recorded on every audit row.

    Threaded from the authenticated request down through the executor in
    place of the bare redirect string it replaces, so adding a future
    attribution field costs one dataclass member instead of a signature
    change at ~20 call sites. Built exclusively by
    `consts.identify_application` (the single construction point, and
    therefore the single place `redirect` is truncated).

    `redirect` is the Application's REGISTERED `redirect_uris` value — the
    space-joined set the client may use, not the single URI a particular
    authorization actually delivered to. DOT does not persist the used
    redirect on `AccessToken`, so the registered set is the strongest
    attribution available at request time.

    The empty default is the "no token in hand" case (e.g. the logout-driven
    revocation rows), which matches the models' blank defaults.
    """

    name: str = ""
    kind: str = ""
    redirect: str = ""

    @classmethod
    def build(cls, *, name: str, kind: str, redirect_uris: str) -> "ClientIdentity":
        return cls(
            name=name,
            kind=kind,
            redirect=(redirect_uris or "")[:REDIRECT_MAX_LENGTH],
        )


# The "no token in hand" identity. A named module-level constant rather than
# a `ClientIdentity()` default expression at each call site: the dataclass is
# frozen, so one shared instance is safe, and a named default reads as
# deliberate rather than as an oversight.
NO_CLIENT = ClientIdentity()


def redirect_kind(uri: str) -> ClientKind | None:
    """Classify one redirect URI as `cloud`, `local`, or neither.

    Deliberately coarse — it answers "which namespace does this belong to",
    NOT "is this safe to admit". The safety rules (no userinfo, no wildcard,
    no traversal, prefix anchoring, explicit loopback port) live in
    `validation._validate_redirect_uri`, which runs first and owns the
    operator-facing error messages.

    Returns `None` for anything else — a custom scheme like Cursor's legacy
    `cursor://anysphere.cursor-mcp/oauth/callback`, an `http` URL pointing
    somewhere other than `localhost`, an unparseable authority. Supporting a
    custom scheme would additionally require the consumer to widen
    `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]`, which is install-global
    and would relax redirect handling for every other OAuth client in their
    project — the wrong trade, so those URIs are simply not expressible here.
    """
    try:
        parsed = urlparse(uri)
        hostname = parsed.hostname
        parsed.port  # noqa: B018 — touched so a malformed authority raises HERE.
    except ValueError:
        # Malformed authority (e.g. a non-numeric port). Reading `.port` is
        # what raises, and the loopback checks downstream read it — classifying
        # to None turns that into a focused `ImproperlyConfigured` naming the
        # URI instead of a bare `ValueError` escaping `ready()`.
        return None
    if not hostname:
        # A hostless `https:///cb` would otherwise classify as `cloud` and be
        # provisioned verbatim onto the Application.
        return None
    if parsed.scheme == "https":
        return ClientKind.CLOUD
    if parsed.scheme == "http" and hostname == LOOPBACK_HOST:
        return ClientKind.LOCAL
    return None


def derive_kind(name: str, redirects: tuple[RedirectRule, ...]) -> ClientKind:
    """Derive a declared client's kind from its rules' schemes.

    Every rule must classify, and they must all agree. A mixed entry is
    refused rather than resolved to one side: it is exactly the "one
    client_id, two trust surfaces" shape the module docstring rules out, and
    an operator who wants both surfaces declares two entries and gets two
    audit identities.

    Raises `ValueError`; the caller turns it into `ImproperlyConfigured`.
    """
    kinds = {redirect_kind(r.uri) for r in redirects}
    if None in kinds:
        msg = (
            f"client {name!r} declares a REDIRECTS URI that is neither an https "
            f"callback nor an http://{LOOPBACK_HOST}:<port>/<path> loopback one"
        )
        raise ValueError(msg)
    if len(kinds) > 1:
        msg = (
            f"client {name!r} mixes https and loopback REDIRECTS. One client_id "
            f"must not serve both a provider-hosted and a machine-local surface "
            f"— declare two entries so each gets its own client_id and its own "
            f"audit identity"
        )
        raise ValueError(msg)
    return kinds.pop()  # type: ignore[return-value]  # `None` excluded above


def redirect_rules(name: str, entry: Mapping[str, Any]) -> tuple[RedirectRule, ...]:
    """Normalise one entry's `REDIRECTS` declaration.

    Raises `ValueError`; the caller turns it into `ImproperlyConfigured`.
    """
    raw = entry.get("REDIRECTS")
    if not raw:
        msg = (
            f"client {name!r} must declare a non-empty REDIRECTS list of "
            f"{{'MATCH': 'exact'|'prefix', 'URI': ...}} rules"
        )
        raise ValueError(msg)
    try:
        return tuple(RedirectRule(match=r["MATCH"], uri=r["URI"]) for r in raw)
    except (KeyError, TypeError) as exc:
        msg = f"client {name!r}: each REDIRECTS entry needs a MATCH and a URI ({exc})"
        raise ValueError(msg) from exc


def build_clients(
    raw: Mapping[str, Mapping[str, Any]], prefix: str
) -> dict[str, DeclaredClient]:
    """Turn `MCP_SQL["CLIENTS"]` into `{client_id: DeclaredClient}`.

    The single normaliser: `conf.MCPSQLSettings.clients()` and
    `validation._validate_clients` both call it, so the shape the validator
    blesses at boot is byte-for-byte the shape the runtime uses. Keyed by the
    derived client_id because that is what DOT hands the recognition
    predicate and the redirect validator.

    Raises `ValueError`; boot validation turns it into `ImproperlyConfigured`.
    """
    built: dict[str, DeclaredClient] = {}
    for name, entry in raw.items():
        rules = redirect_rules(name, entry)
        kind = derive_kind(name, rules)
        client_id = f"{prefix}{kind.value}.{name}"
        built[client_id] = DeclaredClient(
            name=name,
            kind=kind,
            client_id=client_id,
            label=entry.get("LABEL") or name,
            redirects=rules,
        )
    return built
