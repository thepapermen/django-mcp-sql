"""DOT's `TokenView` plus the RFC 8707 `resource` check at `/o/token/`.
See `audience.py` for why a `resource` must name this server's MCP endpoint."""

from typing import Any

from django.http import HttpResponse
from mcp_sql.audience import foreign_resource
from mcp_sql.audience import invalid_target_error
from oauth2_provider.oauth2_backends import OAuthLibCore
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


class MCPTokenView(TokenView):
    """`/o/token/`: DOT's token endpoint, refusing a foreign `resource`.

    The oauthlib backend is pinned to DOT's form-body `OAuthLibCore`, which
    reads the parameters from `request.POST` — what `post`'s check reads. A
    consumer's `OAUTH2_BACKEND_CLASS` (e.g. DOT's deprecated
    `JSONOAuthLibCore`) would otherwise parse a JSON body the check never
    saw, and its `resource` would reach the token. The core is built per
    call: DOT caches it on the view class behind `hasattr(cls,
    "_oauthlib_core")`, which a core cached on the stock `TokenView` (a
    consumer may mount DOT's URLs too) also satisfies, so setting
    `oauthlib_backend_class` alone would not be enough. The server and
    validator are still the configured `OAUTH2_SERVER_CLASS` /
    `OAUTH2_VALIDATOR_CLASS`.
    """

    oauthlib_backend_class = OAuthLibCore

    @classmethod
    def get_oauthlib_core(cls) -> Any:
        return cls.get_oauthlib_backend_class()(cls.get_server())

    def post(self, request, *args, **kwargs):
        """Answer `invalid_target` unless every `resource` (query or form
        body, repeated or not — oauthlib reads both) is this server's MCP
        endpoint as discovery advertises it.

        From DOT 3.4 a `resource` sent here is stored on the access token
        when the grant carries none (DOT checks it only against a grant's
        own `resource`), and DOT then refuses that token at `/mcp/sql/`
        unless it names that endpoint. The check runs before DOT, on every
        DOT version (below 3.4 `resource` is otherwise ignored), so the
        authorization code is not consumed and the client can retry.

        The check accepts any equivalent spelling (`foreign_resource`); when
        the grant carries a `resource` (DOT 3.4+), DOT then also requires each
        value to be one of the grant's, as a string, and answers its own
        `invalid_target` (naming the value) otherwise.
        """
        resources = request.GET.getlist("resource") + request.POST.getlist("resource")
        if foreign_resource(request, resources) is not None:
            return _error_response(invalid_target_error(request))
        return super().post(request, *args, **kwargs)
