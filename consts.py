"""Cross-module logic helpers for the MCP read-only SQL surface.

Holds `is_mcp_application_name`, the single predicate that recognises an
MCP-purpose DOT Application from its name. It is logic — combining the
canonical-name and DCR-prefix shapes — rather than a constant; the
identifier strings themselves live on the settings accessor
(`mcp_sql_settings.APPLICATION_NAME` / `.APPLICATION_NAME_PREFIX` / `.SCOPE`).
"""

import re

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


def is_mcp_application_name(name: str) -> bool:
    """Return True for the canonical MCP Application or a DCR-minted one.

    The recognition predicate for "is this DOT Application part of the MCP
    surface". Two accepted shapes:

    * the exact `mcp_sql_settings.APPLICATION_NAME` — the operator-
      provisioned client from migration 0005; and
    * `APPLICATION_NAME_PREFIX` followed by a DCR token suffix. The prefix
      carries a trailing dash, so `startswith` matches ONLY dynamically-
      registered clients (`mcp-sql-<urlsafe16>`), never the canonical name.

    The prefix branch additionally requires the suffix to match the DCR
    token shape (`_DCR_SUFFIX_RE`): `startswith` alone would also accept a
    hand-crafted `mcp-sql-<anything>` Application, so the shape check keeps
    recognition to the canonical name and genuinely DCR-minted names only.
    See `docs/architecture.md` ("Watch out: trailing dash on APPLICATION_NAME_PREFIX")
    for the rationale and the deliberately-looser logout-signal match.

    `MCPOAuth2Validator` and `MCPOAuth2Authentication` call this; centralising
    the comparison keeps those two call sites in sync.
    """
    if name == mcp_sql_settings.APPLICATION_NAME:
        return True
    # Operator-declared cloud clients (opt-in Category-B). Recognition is
    # SETTINGS-GATED: a cloud client is recognised only while its entry is
    # present in MCP_SQL["CLOUD_CLIENTS"], so removing the entry de-recognises
    # its outstanding tokens at the very next request (fail-closed). The
    # derived client_id carries a "." after "cloud", so it can never match the
    # DCR suffix shape below — the two namespaces stay disjoint and removal is
    # absolute (a removed cloud id can't leak back in via the DCR branch).
    # How cloud logins work: docs/oauth.md → "Cloud clients (opt-in Category-B)".
    if name in mcp_sql_settings.cloud_clients():
        return True
    prefix = mcp_sql_settings.APPLICATION_NAME_PREFIX
    return name.startswith(prefix) and bool(
        _DCR_SUFFIX_RE.fullmatch(name[len(prefix) :])
    )
