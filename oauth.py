"""Custom DOT validator pinned to mcp-sql Applications + the single
`mcp:sql` scope. Mandatory S256-only PKCE and the no-refresh-token policy
are enforced here too. See `docs/architecture.md` "OAuth surface" for the
full picture (consent-screen asymmetry, audience-binding policy, prefix
semantics)."""

from urllib.parse import unquote
from urllib.parse import urlparse

from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from mcp_sql.views.registration import _is_loopback_redirect
from oauth2_provider.models import Application
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError


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
        """Admit a "prefix" cloud client's per-instance callback; hold every
        non-cloud client to a loopback redirect.

        For a settings-declared cloud client whose `REDIRECT_MATCH` is
        "prefix" (ChatGPT / Codex-cloud), accept any redirect under the
        allowlisted host+path prefix via `_redirect_under_prefix`. "Exact"
        cloud clients fall through to DOT's stock exact matching against the
        Application's stored `redirect_uris`.

        EVERY other client — the canonical `mcp-sql` row and every DCR client
        — must ALSO pass `_is_loopback_redirect` (the `/o/register` predicate)
        on the requested URI before DOT's matching runs. Only declared cloud
        clients may redirect off-machine; DOT's matching alone trusts whatever
        the row stores, and a DCR row minted by <= 0.1.0b5 can store an
        off-machine redirect smuggled through whitespace (see
        `_is_loopback_redirect`). This re-check refuses such an entry here
        without needing the operator to find and delete the row first (its
        loopback entries keep working, like any DCR client's).

        A ValueError from DOT's matching is a refusal, not a 500: such a row
        can also store an unparseable port (`http://localhost:99999/cb`), and
        DOT parses a stored `localhost` candidate's port while matching a
        request for a different, valid one. (It port-wildcards loopback IPs,
        so it never reads the port of a stored `127.0.0.1` / `[::1]`
        candidate: a valid request on the same path matches, staying
        loopback.)

        The stored default used when a request omits `redirect_uri` never
        reaches this method — `get_default_redirect_uri` below holds it to the
        same rule.

        Why cloud clients need this + the exact-vs-prefix rationale:
        `docs/oauth.md` → "Cloud clients".
        """
        cloud = mcp_sql_settings.cloud_clients().get(client_id)
        if cloud is not None and cloud.redirect_match == "prefix":
            return _redirect_under_prefix(redirect_uri, cloud.redirect_uri)
        if cloud is None and not _is_loopback_redirect(redirect_uri):
            return False
        try:
            return super().validate_redirect_uri(
                client_id, redirect_uri, request, *args, **kwargs
            )
        except ValueError:
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Hold a non-cloud client's stored default redirect to loopback.

        When a request omits `redirect_uri`, oauthlib resolves the stored
        default WITHOUT calling `validate_redirect_uri`, and a later non-fatal
        error (missing `response_type`, a bad scope, ...) is then 302'd to it.
        So a non-cloud row whose single stored redirect fails the loopback
        predicate (e.g. a canonical row hand-edited to an off-machine URI)
        would still send an error redirect there. Dropping such a default
        makes oauthlib raise its fatal `MissingRedirectURIError` instead —
        error page, no redirect. Declared cloud clients keep DOT's default.
        """
        uri = super().get_default_redirect_uri(client_id, request, *args, **kwargs)
        if (
            uri
            and mcp_sql_settings.cloud_clients().get(client_id) is None
            and not _is_loopback_redirect(uri)
        ):
            return None
        return uri

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

    def is_pkce_required(self, client_id, request):
        """Require PKCE on every authorization, with `S256` as its method.

        Two jobs, both here because this is the hook that fits:

        - Return `True` whatever `OAUTH2_PROVIDER["PKCE_REQUIRED"]` says.
          Every MCP client is public (no secret), so PKCE is the only thing
          binding an authorization code to the client that asked for it; a
          consumer setting must not be able to switch it off. (oauthlib
          compares the result with `is True`, so it must be the literal.)
        - Refuse any method but `S256`. oauthlib calls no "validate the
          method" hook: it defaults an omitted `code_challenge_method` to
          `plain` and accepts `plain` (RFC 7636 §4.3), and DOT's own refusal
          of `plain` is off by default. oauthlib's
          `validate_authorization_request` calls this AFTER the fatal
          client_id / redirect_uri checks — so the `InvalidRequestError`
          raised here goes back as a normal error redirect to an
          already-validated URI — and BEFORE it applies that default, so an
          omitted method is still visible as `None`. (The other hook in that
          window, `validate_response_type`, can only answer
          `unauthorized_client`.) It runs on the authorize GET and again when
          the consent POST (or `skip_authorization`) creates the response.

        oauthlib also calls this at `/o/token/`, but only for a grant with no
        stored challenge, which is refused either way. This returns `True`
        there (a token request carries no `code_challenge`), and oauthlib
        answers `invalid_request` ("Code verifier required.") when the request
        has no `code_verifier`, else `invalid_grant` ("Challenge not found").
        Only a stray non-S256 `code_challenge` on the token request makes this
        raise instead — still `invalid_request`.
        """
        if (
            request.code_challenge is not None
            and request.code_challenge_method != "S256"
        ):
            raise InvalidRequestError(
                # No `"` here: RFC 6749 §4.1.2.1 bars it from error_description.
                description="code_challenge_method must be S256",
                request=request,
            )
        return True

    def get_code_challenge_method(self, code, request):
        """Token-time backstop: only an `S256` grant can be exchanged.

        A Grant stored with any other method — `plain`, explicit or
        defaulted from an omitted method, as every release up to and
        including 0.1.0b5 minted on request — must not be redeemable even
        though `is_pkce_required` now stops new ones. Returning `None` makes
        oauthlib refuse the exchange with `invalid_grant` ("Challenge method
        not found").
        """
        method = super().get_code_challenge_method(code, request)
        return method if method == "S256" else None

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Refuse every refresh grant (`invalid_grant`), whatever the token.

        `ACCESS_TOKEN_EXPIRE_SECONDS` is meant to be the re-consent interval.
        DOT does not give that on its own: with the documented
        `REFRESH_TOKEN_EXPIRE_SECONDS=0` a refresh token has no age limit
        (DOT 3.4 measures only an idle window from the access token's expiry,
        which `0` disables; DOT 3.2/3.3 check nothing), so a refresh token
        minted by any release up to and including 0.1.0b5 renewed access
        indefinitely without the user. This is the hook oauthlib's refresh
        grant calls after client authentication, so returning `False` also
        covers refresh tokens already stored. `save_bearer_token` stops new
        ones from being minted.

        Install-wide, like `validate_scopes` (which already refuses every
        scope but `mcp:sql`): this class is the install's
        `OAUTH2_VALIDATOR_CLASS`, so no client of this DOT install can refresh.
        """
        return False

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Never mint a refresh token.

        oauthlib builds the token dict, hands it to `save_token` (whose
        oauthlib default calls this method), then serialises that SAME dict
        as the `/o/token/` body.
        Dropping `refresh_token` before DOT stores the token therefore removes
        both the `RefreshToken` row (DOT creates one only when the key is
        present) and the response field. Clients then re-authorize when the
        access token expires instead of trying a refresh that
        `validate_refresh_token` refuses. A custom `OAUTH2_SERVER_CLASS` could
        stop oauthlib generating it in the first place, but that setting
        belongs to the consumer.
        """
        token.pop("refresh_token", None)
        return super().save_bearer_token(token, request, *args, **kwargs)
