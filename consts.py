"""Cross-module logic helpers for the MCP read-only SQL surface.

The settings-bound half of the client taxonomy: `classify_application_name`
maps a DOT `Application.name` to its `ClientKind`, `is_mcp_application_name`
is that classifier read as a yes/no recognition predicate, and
`identify_application` packages the result for the audit trail. The
taxonomy's pure half — the kinds themselves, the declared-client dataclasses,
the namespace derivation — lives in `clients.py`; the identifier strings live
on the settings accessor (`mcp_sql_settings.APPLICATION_NAME` /
`.APPLICATION_NAME_PREFIX` / `.SCOPE`).
"""

import re
from typing import Any

from mcp_sql.clients import ClientIdentity
from mcp_sql.clients import ClientKind
from mcp_sql.conf import mcp_sql_settings

# DCR mints Application names as
# `f"{APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(16)}"`, and
# `token_urlsafe(16)` is always 22 URL-safe-base64 chars. Validating the
# suffix *shape* (not just the prefix) means only the canonical name and
# genuinely DCR-minted names are recognised as MCP-purpose: a hand-created
# `mcp-sql-superuser` or a path-traversal-shaped `mcp-sql-../../x` does not
# match, where a bare `startswith` would accept them. Tracks
# registration's token size.
_DCR_SUFFIX_RE = re.compile(r"[A-Za-z0-9_-]{22}")


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


def is_mcp_application_name(name: str) -> bool:
    """Is this DOT Application part of the MCP surface?

    The yes/no reading of `classify_application_name` — one predicate so
    `MCPOAuth2Validator` and `MCPOAuth2Authentication` can never drift from
    each other, or from what the audit trail records.
    """
    return classify_application_name(name) is not None


def identify_application(application: Any) -> ClientIdentity:
    """Package an `Application` into the `ClientIdentity` carried on audit rows.

    The single construction point — and therefore the single place the
    registered redirect list is truncated to the audit column's width. A
    `None` application (no token in hand, e.g. logout-driven revocation)
    yields the blank identity, matching the models' blank defaults.

    `kind` is empty for an Application that classifies as nothing: DOT
    resolved the token, but the client is not (or is no longer) part of the
    MCP surface. That is a rejection path, and recording it blank is the
    honest answer — "we don't recognise this client" — rather than inventing
    a kind for it.
    """
    if application is None:
        return ClientIdentity()
    kind = classify_application_name(application.name)
    return ClientIdentity.build(
        name=application.name,
        kind=kind.value if kind is not None else "",
        redirect_uris=application.redirect_uris,
    )
