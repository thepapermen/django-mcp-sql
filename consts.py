"""Cross-module logic helpers for the MCP read-only SQL surface.

The settings-bound half of the client taxonomy: `classify_application_name`
maps a DOT `Application.name` to its `ClientKind`, `classify_application`
applies it to a row (only while the row's `client_id` equals its `name`),
`is_mcp_application` is that read as a yes/no recognition predicate, and
`identify_application` packages the result for the audit trail. The
taxonomy's pure half — the kinds themselves, the declared-client dataclasses,
the namespace derivation — lives in `clients.py`; the identifier strings live
on the settings accessor (`mcp_sql_settings.APPLICATION_NAME` /
`.APPLICATION_NAME_PREFIX` / `.SCOPE`).

Also `absolute_url`, the one place an absolute URL on the OAuth surface is
composed (discovery documents, the 401 challenge, `/o/register`'s response),
with `canonical_authority`, the host spelling it and the RFC 8707 check share.
(An audit row's `client_ip` is derived by `models.audit_client_ip`.)
"""

import re
from typing import Any

from django.conf import settings
from django.http import HttpRequest
from mcp_sql.clients import DCR_SUFFIX_LENGTH
from mcp_sql.clients import ClientIdentity
from mcp_sql.clients import ClientKind
from mcp_sql.conf import mcp_sql_settings


def absolute_url(request: HttpRequest, path: str) -> str:
    """Absolute URL for `path` on this host, with the scheme hardened.

    Django's `build_absolute_uri` trusts `request.scheme`, which is only
    honest when the TLS-terminating proxy sets `X-Forwarded-Proto` *and* the
    project wires `SECURE_PROXY_SSL_HEADER`. Where either is missing, a
    document fetched over https came back advertising `http://…` URLs —
    mixing an `https` issuer with `http` endpoints inside one payload, and,
    for `resource`, failing the RFC 9728 §3.3 identity check against the
    `https` identifier the client built its request from. That is the same
    break the trailing-slash handling in `views/discovery.py`
    (`_resource_identifier`) exists to fix, on the other half of the
    identifier, so both halves are hardened the same way. Every absolute URL
    in either discovery document, the 401 challenge's `resource_metadata`
    pointer (`auth.py`) and `/o/register`'s `registration_client_uri` are
    composed here, so the whole surface agrees on one origin.

    `DEBUG` off means the project is unambiguously a non-loopback deploy, so
    https is forced; local dev (`DEBUG=True`) keeps `request.scheme` and stays
    honest about http on loopback.

    The host is `request.get_host()` in canonical form (`canonical_authority`):
    lowercased, without the scheme's default port. A proxy that forwards
    `Host: <name>:443` (nginx `proxy_set_header Host $host:$server_port`, or
    an `X-Forwarded-Host` carrying the port under `USE_X_FORWARDED_HOST`) or
    an uppercase name otherwise made discovery advertise
    `https://<name>:443/mcp/sql/`, which every client that parses the URL
    sends back as `https://<name>/mcp/sql/` (the TypeScript SDK's
    `URL.href`, the Python SDK's pydantic URL) — a different string for the
    same resource.
    """
    # `request.scheme` is typed optional; Django's own default is `http`.
    scheme = (request.scheme or "http") if settings.DEBUG else "https"
    return f"{scheme}://{canonical_authority(scheme, request.get_host())}{path}"


DEFAULT_PORTS = {"http": "80", "https": "443"}


def canonical_authority(scheme: str, authority: str) -> str:
    """`authority` (`host[:port]`) as URL parsers serialise it for `scheme`.

    The host lowercased (RFC 3986 §6.2.2.1: scheme and host are
    case-insensitive), a port's leading zeros dropped, and a port equal to the
    scheme's default left out (§6.2.3; WHATWG URL serialisation does the
    same). Anything that does not end in `:<ASCII digits>` (including a
    bracketed IPv6 literal without a port, or an empty port) keeps its
    spelling apart from the case, and so does one whose part before that
    port still holds a colon outside a bracketed IPv6 literal: `name:P:443`
    has two ports, is no `host[:port]` at all, and splitting it at the last
    colon made it equal `name:P`. Pure string work, no `int()`: a Host
    header's port is unbounded digits (`audience.foreign_resource` refuses a
    port the package does not take).

    Used by `absolute_url` on `request.get_host()` and by
    `audience.foreign_resource` on a client's `resource`, so both sides of
    the RFC 8707 comparison spell the authority the same way.
    """
    authority = authority.lower()
    host, colon, port = authority.rpartition(":")
    if not (colon and port.isascii() and port.isdigit()):
        return authority
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return authority
    port = port.lstrip("0") or "0"
    return host if port == DEFAULT_PORTS.get(scheme) else f"{host}:{port}"


# DCR mints Application names as
# `f"{APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(DCR_TOKEN_BYTES)}"`, and
# that is always `DCR_SUFFIX_LENGTH` (22) URL-safe-base64 chars. Validating the
# suffix *shape* (not just the prefix) means only the canonical name and
# genuinely DCR-minted names are recognised as MCP-purpose: a hand-created
# `mcp-sql-superuser` or a path-traversal-shaped `mcp-sql-../../x` does not
# match, where a bare `startswith` would accept them. Tracks
# registration's token size.
_DCR_SUFFIX_RE = re.compile(rf"[A-Za-z0-9_-]{{{DCR_SUFFIX_LENGTH}}}")


def classify_application_name(name: str) -> ClientKind | None:
    """Map a DOT `Application.name` to its `ClientKind`, or None if it is not
    part of the MCP surface at all.

    Three recognition branches, in order:

    * the exact `mcp_sql_settings.APPLICATION_NAME` — the operator-
      provisioned client from migration 0005 → `CURATED`;
    * a key of `mcp_sql_settings.clients()` → that entry's derived kind
      (`CLOUD` or `LOCAL`). Recognition is **settings-gated**: a declared
      client is recognised only while its entry is present in
      `MCP_SQL["CLIENTS"]`, so removing the entry de-recognises its
      outstanding tokens at the very next request (fail-closed). The derived
      client_id carries a `.` after the kind, so it can never match the DCR
      suffix shape below — the namespaces stay disjoint and removal is
      absolute (a removed id can't leak back in via the DCR branch);
    * `APPLICATION_NAME_PREFIX` followed by a DCR token suffix → `DCR`. The
      prefix carries a trailing dash, so `startswith` matches ONLY
      dynamically-registered clients (`mcp-sql-<urlsafe16>`), never the
      canonical name. The suffix must also match the DCR token *shape*
      (`_DCR_SUFFIX_RE`) — `startswith` alone would accept a hand-crafted
      `mcp-sql-<anything>` Application.

    See `docs/architecture.md` ("Watch out: trailing dash on
    APPLICATION_NAME_PREFIX") for the rationale and the deliberately-looser
    logout-signal match.
    """
    if name == mcp_sql_settings.APPLICATION_NAME:
        return ClientKind.CURATED
    declared = mcp_sql_settings.clients().get(name)
    if declared is not None:
        return declared.kind
    prefix = mcp_sql_settings.APPLICATION_NAME_PREFIX
    if name.startswith(prefix) and _DCR_SUFFIX_RE.fullmatch(name[len(prefix) :]):
        return ClientKind.DCR
    return None


def classify_application(application: Any) -> ClientKind | None:
    """`classify_application_name` for a DOT `Application` row, or None.

    Recognition and the consent label key on the name, but provisioning and
    the redirect checks key on the `client_id` — and every row this package
    writes carries one string in both (migration 0005, `/o/register`,
    `signals.provision_mcp_clients`). Nothing in DOT enforces that, so a row
    whose `client_id` differs from its `name` is recognised as nothing,
    whatever the name: otherwise a row NAMED `mcp-sql-cloud.claude` under
    another client_id (an admin-UI or shell edit) would be accepted as the
    declared client while every client_id-keyed check looked at something
    else. Applies to every branch (curated, declared and DCR rows alike).
    A `None` application is not recognised either.
    """
    if application is None or application.client_id != application.name:
        return None
    return classify_application_name(application.name)


def is_mcp_application(application: Any) -> bool:
    """Is this DOT Application part of the MCP surface?

    The yes/no reading of `classify_application` — one predicate so
    `MCPOAuth2Validator` and `MCPOAuth2Authentication` can never drift from
    each other, or from what the audit trail records.
    """
    return classify_application(application) is not None


def identify_application(application: Any) -> ClientIdentity:
    """Package an `Application` into the `ClientIdentity` carried on audit rows.

    The single construction point — and therefore the single place the
    redirect list is truncated to the audit column's width. A
    `None` application (no token in hand, e.g. logout-driven revocation)
    yields the blank identity, matching the models' blank defaults.

    `kind` is empty for an Application that classifies as nothing
    (`classify_application`): DOT resolved the token, but the client is not
    (or is no longer) part of the MCP surface. That is a rejection path, and
    recording it blank is the honest answer — "we don't recognise this
    client" — rather than inventing a kind for it.

    The redirect set follows what decides the client's redirects. For a
    recognised settings-declared client that is its `CLIENTS` entry
    (`oauth._declared_redirect_allowed` never reads the row), joined the way
    provisioning joins it — not the row's `redirect_uris`, which is
    refreshed only by `post_migrate` and so would name a callback changed in
    settings until the next `migrate`. Every other row (curated, DCR, and a
    declared client no longer in settings, whose entry is gone) records the
    row's stored value: for the first two it is what DOT matches; for the
    last it is the only record left.
    """
    if application is None:
        return ClientIdentity()
    kind = classify_application(application)
    declared = (
        mcp_sql_settings.clients().get(application.name)
        if kind in (ClientKind.CLOUD, ClientKind.LOCAL)
        else None
    )
    return ClientIdentity.build(
        name=application.name,
        kind=kind.value if kind is not None else "",
        redirect_uris=(
            " ".join(declared.redirect_uris)
            if declared is not None
            else application.redirect_uris
        ),
    )
