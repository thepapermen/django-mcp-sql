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
"""

from typing import Any

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
    response. (oauthlib reaches this check only when PKCE is required, which
    `MCPOAuth2Validator.is_pkce_required` always answers.) At `/o/token/`,
    a grant stored with another method would hit the same table as a 500
    `server_error`; `MCPOAuth2Validator.get_code_challenge_method` refuses it
    one step earlier with `invalid_grant`.
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
    `unsupported_grant_type`.

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
    """DOT's `get_oauthlib_core()`, on `MCPServer` instead of the
    consumer's `OAUTH2_SERVER_CLASS` (same validator, server kwargs and
    `OAUTH2_BACKEND_CLASS`)."""
    server = MCPServer(
        oauth2_settings.OAUTH2_VALIDATOR_CLASS(), **oauth2_settings.server_kwargs
    )
    return oauth2_settings.OAUTH2_BACKEND_CLASS(server)


class MCPServerViewMixin(OAuthLibMixin):
    """Run a DOT `OAuthLibMixin` view on `MCPServer`.

    Setting `server_class` is DOT's own hook; overriding `get_oauthlib_core`
    is not optional. DOT caches the core on the view class behind
    `hasattr(cls, "_oauthlib_core")`, which an attribute INHERITED from the
    stock parent view also satisfies: once any stock `TokenView` /
    `AuthorizationView` / `RevokeTokenView` in the process has served a
    request (a consumer may mount DOT's URLs too), a subclass would reuse
    that core — the all-grants server — and `server_class` would never be
    read. This cache is looked up in the class's own `__dict__` only.
    """

    server_class = MCPServer

    @classmethod
    def get_oauthlib_core(cls) -> Any:
        core = cls.__dict__.get("_oauthlib_core")
        if core is None or oauth2_settings.ALWAYS_RELOAD_OAUTHLIB_CORE:
            core = cls.get_oauthlib_backend_class()(cls.get_server())
            cls._oauthlib_core = core
        return core
