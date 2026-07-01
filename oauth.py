"""Custom DOT validator pinned to mcp-sql Applications + the single
`mcp:sql` scope. S256-only PKCE enforcement lives here too. See
`docs/architecture.md` "OAuth surface" for the full picture
(consent-screen asymmetry, audience-binding policy, prefix semantics)."""

from urllib.parse import unquote
from urllib.parse import urlparse

from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from oauth2_provider.models import Application
from oauth2_provider.oauth2_validators import OAuth2Validator


def _redirect_under_prefix(redirect_uri: str, prefix: str) -> bool:
    """True iff `redirect_uri` is a safe https URL sitting under `prefix`.

    Used only for "prefix" cloud clients (ChatGPT / Codex-cloud), whose
    callback is per-instance — `https://chatgpt.com/connector/oauth/{id}` —
    and so cannot be pre-registered as an exact URI. The match is deliberately
    strict, hardened against the classic redirect-allowlist bypasses so the
    relaxation stays bounded to the provider's own origin:

    - scheme MUST be https (no downgrade),
    - no userinfo component (`https://chatgpt.com@evil.com/...`),
    - host must EXACTLY equal the prefix host (not `endswith`, so
      `chatgpt.com.evil.com` is rejected), and port must match with only a
      MISSING port normalised to the https default (an explicit `:443` equals
      an implicit one; an explicit `:0` stays distinct),
    - no `..` path segment — literal or single/multi-level percent-encoded
      (`%2e%2e`, `%252e%252e`, ...) — above the prefix path,
    - path must start with the prefix path, anchored at a `/` segment boundary
      so a sibling like `.../oauthEVIL` cannot slip past a bare prefix (also
      enforced at config time by `validation._validate_cloud_redirect_uri`).

    Mirrors the care in `views/registration.py::_is_loopback_redirect`.
    """
    try:
        got = urlparse(redirect_uri)
        want = urlparse(prefix)
        got_port, want_port = got.port, want.port
    except ValueError:
        # Malformed authority (e.g. a non-numeric port) — reject, fail-closed.
        return False
    # Anchor the prefix to a segment boundary. Validation already requires a
    # trailing slash on a "prefix" REDIRECT_URI; this keeps the predicate
    # correct on its own even if handed a bare prefix.
    want_path = want.path if want.path.endswith("/") else want.path + "/"
    # Fully percent-decode the path (bounded) before the traversal check, so a
    # single- OR multi-encoded `..` (`%2e%2e`, `%252e%252e`, ...) can't slip
    # past. `unquote` is idempotent-converging; 5 layers is far more than any
    # real callback needs. Only the traversal check sees the decoded form —
    # `startswith` stays on the raw path, matched against the raw prefix.
    decoded_path = got.path
    for _ in range(5):
        step = unquote(decoded_path)
        if step == decoded_path:
            break
        decoded_path = step
    # Normalise only a MISSING port to the https default — an explicit `:0` is
    # falsy but not None, so keep it distinct rather than aliasing the default.
    got_port = 443 if got_port is None else got_port
    want_port = 443 if want_port is None else want_port
    return (
        got.scheme == "https"  # no downgrade
        and not got.username  # no userinfo smuggling ...
        and not got.password  # ... in either field
        and bool(got.hostname)
        and got.hostname == want.hostname  # exact host, never `endswith`
        and got_port == want_port  # exact port (:443 == implicit https)
        and ".." not in decoded_path.split("/")  # no traversal (literal/encoded)
        and got.path.startswith(want_path)  # under the allowlisted path
    )


class MCPOAuth2Validator(OAuth2Validator):
    """Validator pinned to the mcp-sql Application surface + the single scope."""

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Accept the request only if `client_id` resolves to an mcp-sql Application.

        DOT's default looks up by `client_id` and binds the Application onto
        `request.client`. We let it do that, then verify the resulting
        Application is a recognised mcp-sql shape via `is_mcp_application_name`:
        the curated `mcp-sql` row, a dynamically-registered `mcp-sql-<token>`
        row, OR a settings-declared `mcp-sql-cloud.<name>` cloud client. An
        Application whose name matches none of these (e.g. some unrelated OAuth
        client added later) is rejected here.
        """
        if not super().validate_client_id(client_id, request, *args, **kwargs):
            return False
        app = (
            getattr(request, "client", None)
            or Application.objects.filter(client_id=client_id).first()
        )
        return app is not None and is_mcp_application_name(app.name)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Admit a "prefix" cloud client's per-instance callback.

        For a settings-declared cloud client whose `REDIRECT_MATCH` is
        "prefix" (ChatGPT / Codex-cloud), accept any redirect under the
        allowlisted host+path prefix via `_redirect_under_prefix`. EVERY other
        client — "exact" cloud clients, the canonical `mcp-sql` row, and every
        loopback DCR client — falls through to DOT's stock exact matching
        against the Application's stored `redirect_uris`, so this override
        neither widens nor weakens the loopback/exact paths.

        Why cloud clients need this + the exact-vs-prefix rationale:
        `docs/oauth.md` → "Cloud clients".
        """
        cloud = mcp_sql_settings.cloud_clients().get(client_id)
        if cloud is not None and cloud.redirect_match == "prefix":
            return _redirect_under_prefix(redirect_uri, cloud.redirect_uri)
        return super().validate_redirect_uri(
            client_id, redirect_uri, request, *args, **kwargs
        )

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Reject any token request that asks for scopes other than `mcp:sql`."""
        if not scopes:
            return False
        # Reject anything with extra or different scopes. `scopes` is a list of strings.
        if set(scopes) != {mcp_sql_settings.SCOPE}:
            return False
        return super().validate_scopes(
            client_id, scopes, client, request, *args, **kwargs
        )

    def validate_code_challenge_method(self, request, code_challenge_method):
        """Accept only `S256`; reject `plain` (and any other method).

        oauthlib accepts both `S256` and `plain` at runtime by default. The
        OAUTH2_PROVIDER comment in `settings/base.py` flags this as a known
        gap — `plain` PKCE is equivalent to no PKCE if the verifier ever
        leaks, which gives a weaker guarantee than `S256` for negligible
        client-side cost. The RFC 8414 discovery doc advertises only
        `S256`; this validator ensures the server actually enforces what
        the discovery doc promises.
        """
        return code_challenge_method == "S256"
