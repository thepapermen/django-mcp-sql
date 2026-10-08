"""Custom DOT validator pinned to mcp-sql Applications + the single
`mcp:sql` scope. S256-only PKCE enforcement lives here too. See
`docs/architecture.md` "OAuth surface" for the full picture
(consent-screen asymmetry, audience-binding policy, prefix semantics)."""

from urllib.parse import unquote
from urllib.parse import urlparse

from mcp_sql.clients import DeclaredClient
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application
from oauth2_provider.models import Application
from oauth2_provider.models import redirect_to_uri_allowed
from oauth2_provider.oauth2_validators import OAuth2Validator


def _redirect_under_prefix(redirect_uri: str, prefix: str) -> bool:
    """True iff `redirect_uri` is a safe https URL sitting under `prefix`.

    Used only for `MATCH: "prefix"` rules (ChatGPT / Codex-cloud), whose
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
      enforced at config time by `validation._validate_redirect_uri`).

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
        # ...and no backslash, which a browser's WHATWG parser treats as `/`
        # in an https URL, so `..\` would be traversal by another spelling.
        # oauthlib's absolute-URI check and Django's `iri_to_uri` (`\` ->
        # `%5C`) each already stop it upstream; refused here as well so the
        # path anchor does not depend on either.
        and "\\" not in decoded_path
        and got.path.startswith(want_path)  # under the allowlisted path
    )


def _declared_redirect_allowed(declared: DeclaredClient, redirect_uri: str) -> bool:
    """A declared client's redirect, decided from SETTINGS alone.

    Prefix rules through `_redirect_under_prefix`; exact rules through DOT's
    own matcher (`redirect_to_uri_allowed`, the function behind
    `Application.redirect_uri_allowed`) run on the declared exact URIs, so an
    exact rule means exactly what DOT's matching of a stored `redirect_uris`
    means on the installed DOT version — only the list comes from
    `MCP_SQL["CLIENTS"]` instead of the provisioned row. That row is
    refreshed only by `post_migrate` (`signals.provision_mcp_clients`), so
    reading it let a callback changed or removed in settings keep working,
    and refused the new one, until the next `migrate`.

    A `ValueError` from DOT's parsing (a request port no parser takes, e.g.
    `:99999`, on a declared host) is a refusal, not a 500.
    """
    if any(_redirect_under_prefix(redirect_uri, p) for p in declared.prefixes):
        return True
    try:
        return bool(redirect_to_uri_allowed(redirect_uri, list(declared.exact_uris)))
    except ValueError:
        return False


class MCPOAuth2Validator(OAuth2Validator):
    """Validator pinned to the mcp-sql Application surface + the single scope."""

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Accept the request only if `client_id` resolves to an mcp-sql Application.

        DOT's default looks up by `client_id` and binds the Application onto
        `request.client`. We let it do that, then verify the resulting
        Application is a recognised mcp-sql client via `is_mcp_application`:
        the curated `mcp-sql` row, a dynamically-registered `mcp-sql-<token>`
        row, OR a settings-declared `mcp-sql-{cloud,local}.<slug>` client,
        each only while its `client_id` equals its `name`. An Application that
        matches none of these (e.g. some unrelated OAuth client added later,
        or a row named like an MCP client under another client_id) is
        rejected here.
        """
        if not super().validate_client_id(client_id, request, *args, **kwargs):
            return False
        app = (
            getattr(request, "client", None)
            or Application.objects.filter(client_id=client_id).first()
        )
        return is_mcp_application(app)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """A declared client's redirect is decided by settings; every other
        client's by DOT against its row.

        For a settings-declared client (`mcp_sql_settings.clients()`), only
        `_declared_redirect_allowed` decides: its prefix rules
        (`_redirect_under_prefix`, for ChatGPT / Codex-cloud's per-instance
        callbacks) and its exact rules (DOT's matcher on the declared exact
        URIs). There is no fall-through to `super()`: the provisioned row's
        `redirect_uris` is a copy refreshed only on `migrate`, and recognition
        is already settings-gated per request — so are redirects. A callback
        changed in settings takes effect at the next request (old refused, new
        accepted), and a removed rule stops being admissible at once.

        EVERY other client — the canonical `mcp-sql` row and every loopback
        DCR client — gets DOT's stock matching against its own row, untouched.

        Why declared clients need this + the exact-vs-prefix rationale:
        `docs/oauth.md` → "Clients".
        """
        declared = mcp_sql_settings.clients().get(client_id)
        if declared is not None:
            return _declared_redirect_allowed(declared, redirect_uri)
        return super().validate_redirect_uri(
            client_id, redirect_uri, request, *args, **kwargs
        )

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """A declared client's default redirect comes from settings too.

        oauthlib asks for it only when an authorization request omits
        `redirect_uri`, and uses it WITHOUT calling `validate_redirect_uri`
        (a later non-fatal error is 302'd to it too). DOT's default reads the
        provisioned row, which would bring back a callback since changed or
        removed in settings. A declared client has a default only when it
        declares exactly one rule and that rule is exact — as DOT gives one
        only for a single stored URI; a prefix is not a callback. Otherwise
        `None`, and oauthlib raises its fatal `MissingRedirectURIError` (error
        page, no redirect). Every other client keeps DOT's default.
        """
        declared = mcp_sql_settings.clients().get(client_id)
        if declared is None:
            return super().get_default_redirect_uri(client_id, request, *args, **kwargs)
        if len(declared.redirects) == 1 and declared.exact_uris:
            return declared.exact_uris[0]
        return None

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
