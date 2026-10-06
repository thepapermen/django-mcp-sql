"""The OAuth server behind the package's own OAuth endpoints and `/mcp/sql/`.

DOT runs every endpoint on `OAUTH2_PROVIDER["OAUTH2_SERVER_CLASS"]`, by
default oauthlib's all-grants `Server`: behind `/o/token/` that is the
password, client-credentials, refresh-token and device-code grants as well as
the authorization code, and behind `/o/authorize/` the implicit grant. None of
them is part of this package's surface, and leaving them reachable is not
inert — the password grant answered a correct and a wrong password
differently (an anonymous password oracle), and the device-code and `openid`
paths raised uncaught 500s. `MCPServer` is the narrow alternative, built from
the same oauthlib endpoints, and enforces by its shape exactly what the
discovery documents advertise (`views/discovery.py`):

- one grant, `authorization_code` (`response_types_supported: ["code"]`,
  `grant_types_supported: ["authorization_code"]`), which never issues a
  refresh token and accepts only `S256` PKCE (`MCPAuthorizationCodeGrant`);
- a bearer token read from the `Authorization` header only
  (`bearer_methods_supported: ["header"]`, `HeaderOnlyBearer`);
- token revocation.

The package's views and `MCPOAuth2Authentication` use it whatever the consumer
sets `OAUTH2_SERVER_CLASS` to (`MCPServerViewMixin`, `get_mcp_oauthlib_core`).
DOT routes the device-code grant in `TokenView.post` before any server sees
the request, so `views/oauth_token.py::MCPTokenView` also refuses every other
`grant_type` itself.
"""

from typing import Any

from oauth2_provider.oauth2_backends import OAuthLibCore
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.oauth2.rfc6749.endpoints import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints import ResourceEndpoint
from oauthlib.oauth2.rfc6749.endpoints import RevocationEndpoint
from oauthlib.oauth2.rfc6749.endpoints import TokenEndpoint
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import (
    code_challenge_method_s256,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.tokens import get_token_from_header


class MCPAuthorizationCodeGrant(AuthorizationCodeGrant):
    """The authorization-code grant: no refresh token, `S256` PKCE only.

    `refresh_token = False` is the flag oauthlib passes to the token handler,
    so the `/o/token/` response carries no `refresh_token` and DOT stores no
    `RefreshToken` row (it creates one only when the key is present). The
    access token's lifetime (`ACCESS_TOKEN_EXPIRE_SECONDS`) is then the
    re-consent interval, as documented.

    `_code_challenge_methods` is the table oauthlib checks a challenge method
    against. At `/o/authorize/` it applies only after the fatal client_id /
    redirect_uri checks and after it has defaulted an omitted method to
    `plain` (RFC 7636 §4.3), so `plain` and an omitted method alike are
    refused with `invalid_request`, redirected to the already-validated URI
    — on the authorize GET and again when the consent POST creates the
    response. (oauthlib checks the method only when a `code_challenge` is
    present, which `MCPOAuth2Validator.is_pkce_required` makes mandatory.)
    At `/o/token/`, a grant stored with another method would hit the same
    table as a 400 `server_error`;
    `MCPOAuth2Validator.get_code_challenge_method` refuses it one step
    earlier with `invalid_grant`.
    """

    refresh_token = False
    _code_challenge_methods = {"S256": code_challenge_method_s256}


class HeaderOnlyBearer(BearerToken):
    """A bearer token taken from `Authorization: Bearer <token>` only.

    oauthlib's `BearerToken` falls back to an `access_token` request
    parameter — the URI query (RFC 6750 §2.3) or a form body (§2.2) — when no
    `Authorization` header is present, which put tokens in URLs, and so in
    proxy and access logs and `Referer` headers; the MCP authorization spec
    forbids it. Here such a parameter is simply not a credential: the request
    is validated as carrying no token, so DOT's validator returns before any
    token lookup.
    """

    __slots__ = ()

    def validate_request(self, request):
        # oauthlib's own header parsing, minus its parameter fallback (which
        # it takes only when the header is absent).
        token = (
            get_token_from_header(request)
            if "Authorization" in request.headers
            else None
        )
        return self.request_validator.validate_bearer_token(
            token, request.scopes, request
        )


class MCPServer(
    AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint, RevocationEndpoint
):
    """oauthlib's pre-configured `Server`, cut down to the MCP surface.

    No implicit, password, client-credentials, refresh-token or device-code
    grant and no introspection endpoint. oauthlib still hands an unknown
    `response_type` / `grant_type` to the default (authorization-code)
    handler, which answers `unsupported_response_type` /
    `unsupported_grant_type` — except `grant_type=openid`, which that grant
    accepts as an alias; `MCPTokenView` refuses it, with every other value,
    before the server runs.

    The signature is DOT's: it constructs the server with
    `oauth2_settings.server_kwargs` (`token_expires_in`, `token_generator`,
    `refresh_token_generator`, plus device-flow, `pre_token` and
    `EXTRA_SERVER_KWARGS` entries for grants this server does not have, which
    `**kwargs` absorbs and ignores).
    """

    def __init__(
        self,
        request_validator,
        token_expires_in=None,
        token_generator=None,
        refresh_token_generator=None,
        **kwargs,
    ):
        self.auth_grant = MCPAuthorizationCodeGrant(request_validator)
        self.bearer = HeaderOnlyBearer(
            request_validator,
            token_generator,
            token_expires_in,
            refresh_token_generator,
        )
        AuthorizationEndpoint.__init__(
            self,
            default_response_type="code",
            response_types={"code": self.auth_grant},
            default_token_type=self.bearer,
        )
        TokenEndpoint.__init__(
            self,
            default_grant_type="authorization_code",
            grant_types={"authorization_code": self.auth_grant},
            default_token_type=self.bearer,
        )
        ResourceEndpoint.__init__(
            self,
            default_token="Bearer",  # noqa: S106 — the token TYPE, not a credential.
            token_types={"Bearer": self.bearer},
        )
        RevocationEndpoint.__init__(self, request_validator)


def get_mcp_oauthlib_core() -> Any:
    """DOT's `get_oauthlib_core()`, on `MCPServer` instead of the consumer's
    `OAUTH2_SERVER_CLASS`, and always with DOT's form-body `OAuthLibCore`
    (same validator and server kwargs). Built per call, as DOT's own DRF
    authentication class does."""
    server = MCPServer(
        oauth2_settings.OAUTH2_VALIDATOR_CLASS(), **oauth2_settings.server_kwargs
    )
    return OAuthLibCore(server)


class MCPServerViewMixin(OAuthLibMixin):
    """Run a DOT `OAuthLibMixin` view on `MCPServer` with `OAuthLibCore`.

    Setting `server_class` is DOT's own hook, but overriding
    `get_oauthlib_core` is not optional. DOT caches the core on the view
    class behind `hasattr(cls, "_oauthlib_core")`, which an attribute
    INHERITED from the stock parent view also satisfies: once any stock
    `TokenView` / `AuthorizationView` / `RevokeTokenView` in the process has
    served a request (a consumer may mount DOT's URLs too), a subclass would
    reuse that core — built on the consumer's `OAUTH2_SERVER_CLASS` — and
    `server_class` would never be read. This mixin builds the core per call
    instead (a few small objects): no cache to inherit, and the server's
    shape follows the current settings.

    The backend is pinned to `OAuthLibCore`, which reads form bodies
    (`request.POST`) — what `MCPTokenView`'s guard reads. A consumer's
    `OAUTH2_BACKEND_CLASS` (e.g. DOT's deprecated `JSONOAuthLibCore`) could
    otherwise parse a body the guard never saw.
    """

    server_class = MCPServer
    oauthlib_backend_class = OAuthLibCore

    @classmethod
    def get_oauthlib_core(cls) -> Any:
        return cls.get_oauthlib_backend_class()(cls.get_server())
