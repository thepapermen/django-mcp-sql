"""DOT's `TokenView` / `RevokeTokenView` on the narrow `MCPServer`, plus the
token-endpoint guard. See `oauth_server.py` for what the server admits and why."""

from django.http import HttpResponse
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
    """`/o/token/`: the authorization-code exchange and nothing else."""

    def post(self, request, *args, **kwargs):
        """Refuse anything but one `grant_type=authorization_code` up front.

        `MCPServer` already handles only that grant, but DOT's `TokenView.post`
        sends `grant_type=urn:ietf:params:oauth:grant-type:device_code` to its
        own device-flow handler before any server runs (a request without a
        `device_code` raised an uncaught `KeyError`), and oauthlib's
        authorization-code grant also accepts `grant_type=openid`. So this
        check runs first, on the form body DOT reads (`request.POST`), and
        answers `unsupported_grant_type` for every other value, a missing one
        or a repeated one — the same response whether a password grant's
        credentials are right or wrong.

        `grant_type=refresh_token` is the exception: it gets a constant
        `invalid_grant`, with no token lookup. That is the answer that makes
        an MCP client drop its refresh token and re-authorize (the MCP
        TypeScript SDK re-authorizes on `invalid_grant`, not on
        `unsupported_grant_type`); clients still holding a refresh token
        from 0.1.0b5 or earlier would otherwise be stuck.

        A control character in any other parameter (query or body) is an
        `invalid_request`: a NUL in `code` or `client_id` otherwise reached a
        Postgres lookup and raised an uncaught 500.
        """
        grant_types = request.POST.getlist("grant_type")
        if grant_types == ["refresh_token"]:
            return _error_response(
                errors.InvalidGrantError(
                    description="Refresh tokens are not accepted; re-authorize."
                )
            )
        if grant_types != ["authorization_code"]:
            return _error_response(errors.UnsupportedGrantTypeError())
        if has_control_character(request.GET, request.POST):
            return _error_response(
                errors.InvalidRequestError(
                    description="Control character in a request parameter."
                )
            )
        return super().post(request, *args, **kwargs)


class MCPRevokeTokenView(MCPServerViewMixin, RevokeTokenView):
    """`/o/revoke_token/` (RFC 7009) on `MCPServer`."""
