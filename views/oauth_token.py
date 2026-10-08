"""DOT's `TokenView` / `RevokeTokenView` on the narrow `MCPServer`, plus the
token-endpoint guard and the RFC 8707 `resource` check at `/o/token/`. See
`oauth_server.py` for what the server admits and why, and `audience.py` for
why a `resource` must name this server's MCP endpoint."""

from django.http import HttpResponse
from mcp_sql.audience import foreign_resource
from mcp_sql.audience import invalid_target_error
from mcp_sql.conf import refresh_tokens_enabled
from mcp_sql.oauth import has_control_character
from mcp_sql.oauth_server import MCPServerViewMixin
from oauth2_provider.views import RevokeTokenView
from oauth2_provider.views import TokenView
from oauthlib.oauth2.rfc6749 import errors


def _error_response(error: errors.OAuth2Error) -> HttpResponse:
    """`error` as oauthlib would answer it at the token endpoint (RFC 6749
    §5.2 body; §5.1 `no-store` caching headers)."""
    response = HttpResponse(
        error.json, status=error.status_code, content_type="application/json"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


class MCPTokenView(MCPServerViewMixin, TokenView):
    """`/o/token/`: the authorization-code exchange and nothing else, with a
    foreign `resource` refused.

    `MCPServerViewMixin` pins the oauthlib backend to DOT's form-body
    `OAuthLibCore`, built per call, so the parameters DOT reads are the ones
    `post`'s checks read (`request.POST`): a consumer's `OAUTH2_BACKEND_CLASS`
    (e.g. DOT's deprecated `JSONOAuthLibCore`) would otherwise parse a JSON
    body the checks never saw, and its `resource` would reach the token.
    """

    def post(self, request, *args, **kwargs):
        """Refuse anything but one `grant_type=authorization_code` (or, when
        refresh is enabled, `refresh_token`) up front, then a control
        character in any parameter, then a foreign `resource`.

        `MCPServer` already handles only that grant, but DOT's `TokenView.post`
        sends `grant_type=urn:ietf:params:oauth:grant-type:device_code` to its
        own device-flow handler before any server runs (a request without a
        `device_code` raised an uncaught `KeyError`), and oauthlib's
        authorization-code grant also accepts `grant_type=openid`. So this
        check runs first, on the form body DOT reads (`request.POST`), and
        answers `unsupported_grant_type` for every other value, a missing one
        or a repeated one — the same response whether a password grant's
        credentials are right or wrong.

        With refresh enabled (`MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]`),
        `grant_type=refresh_token` goes to the server's refresh grant. With it
        off (the default) a refresh grant gets a constant `invalid_grant`,
        with no token lookup. That is the answer that makes
        an MCP client drop its refresh token and re-authorize (the MCP
        TypeScript SDK re-authorizes on `invalid_grant`, not on
        `unsupported_grant_type`); clients still holding a refresh token
        from 0.1.0b5 or earlier would otherwise be stuck.

        A control character in any other parameter (query or body) is an
        `invalid_request`: a NUL in `code` or `client_id` otherwise reached a
        Postgres lookup and raised an uncaught 500. A NUL in `resource` gets
        this answer too.

        Then `invalid_target` unless every `resource` (query or form body,
        repeated or not — oauthlib reads both) is this server's MCP endpoint
        as discovery advertises it. From DOT 3.4 a `resource` sent here is
        stored on the access token when the grant carries none (DOT checks
        it only against a grant's own `resource`), and DOT then refuses that
        token at `/mcp/sql/` unless it names that endpoint. The check runs
        before DOT, so the authorization code is not consumed and the client
        can retry.

        The check accepts any equivalent spelling (`foreign_resource`); when
        the grant carries a `resource`, DOT then also requires each value to
        be one of the grant's, as a string, and answers its own
        `invalid_target` (naming the value) otherwise.
        """
        grant_types = request.POST.getlist("grant_type")
        refresh = refresh_tokens_enabled()
        if grant_types == ["refresh_token"] and not refresh:
            return _error_response(
                errors.InvalidGrantError(
                    description="Refresh tokens are not accepted; re-authorize."
                )
            )
        allowed = (["authorization_code"], ["refresh_token"] if refresh else None)
        if grant_types not in allowed:
            return _error_response(errors.UnsupportedGrantTypeError())
        if has_control_character(request.GET, request.POST):
            return _error_response(
                errors.InvalidRequestError(
                    description="Control character in a request parameter."
                )
            )
        resources = request.GET.getlist("resource") + request.POST.getlist("resource")
        if foreign_resource(request, resources) is not None:
            return _error_response(invalid_target_error(request))
        return super().post(request, *args, **kwargs)


class MCPRevokeTokenView(MCPServerViewMixin, RevokeTokenView):
    """`/o/revoke_token/` (RFC 7009) on `MCPServer`."""
