"""Tests for the OAuth 2.0 discovery layer (Phase 3.5 of TIC-554).

Three things are pinned here:

1. The RFC 9728 Protected Resource Metadata view emits the shape MCP
   clients expect: `resource`, `resource_name`, `authorization_servers`,
   `scopes_supported`, `bearer_methods_supported`.
2. The RFC 8414 Authorization Server Metadata view emits the shape an
   OAuth client needs to drive `/o/authorize/` + `/o/token/` without
   out-of-band knowledge: `issuer`, the three endpoint URLs, scopes,
   response/grant types, PKCE methods, token-endpoint auth methods.
3. `MCPOAuth2Authentication.authenticate_header()` augments the default
   bearer challenge with `resource_metadata="<absolute URL of the RFC
   9728 view>"`. Without this, a 401 from `/mcp/sql/` is a dead end —
   the client receives the challenge but has nowhere to start discovery.

Both `.well-known/...` endpoints are publicly readable (per RFC). A
negative test pins that they don't accidentally inherit any auth gate.
"""

from http import HTTPStatus

import pytest
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestProtectedResourceMetadata:
    """RFC 9728 metadata for the MCP SQL resource."""

    def _get(self, client=None):
        client = client or APIClient()
        return client.get(reverse("mcp_sql_protected_resource_metadata"))

    def test_returns_200_and_json(self):
        response = self._get()
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"].startswith("application/json")

    def test_resource_field_points_at_mcp_endpoint(self):
        response = self._get()
        body = response.json()
        # Hard-coded host expectation: APIClient's default Host header is
        # `testserver`. Building the expected URL from the view's own helper
        # would be a tautology — the assertion has to use a value composed
        # *independently* of the view's URL-construction code path.
        assert body["resource"] == f"http://testserver{reverse('mcp_sql_endpoint')}"

    def test_resource_name_honors_mcp_sql_override(self, settings):
        # Package contract: the discovery document surfaces whatever the
        # consumer wires into `MCP_SQL["RESOURCE_NAME"]` (read through the
        # accessor — consumers commonly derive it from another setting, e.g.
        # a TOTP issuer, so the MCP name matches the authenticator label).
        # Pinned via an explicit override rather than by comparing the
        # response against the accessor (which would be a tautology — the
        # view reads the same accessor). The default value itself is pinned
        # by `test_conf.py`.
        settings.MCP_SQL = {**settings.MCP_SQL, "RESOURCE_NAME": "Custom Resource"}
        response = self._get()
        body = response.json()
        assert body["resource_name"] == "Custom Resource"

    def test_authorization_servers_lists_issuer(self):
        response = self._get()
        body = response.json()
        assert isinstance(body["authorization_servers"], list)
        assert len(body["authorization_servers"]) == 1
        # The single AS is scoped under `/o` (RFC 8414 §3.1 supports
        # path-component issuers). Matches what the AS metadata view
        # emits as `issuer`. No trailing slash.
        as_url = body["authorization_servers"][0]
        assert as_url.startswith(("http://", "https://"))
        assert as_url.endswith("/o")

    def test_authorization_servers_force_https_when_debug_off(self, settings):
        # `_issuer()`'s https-forcing branch is exercised here from the PRM
        # side (the AS metadata view tests it from the other side). Both
        # call paths use the same helper but the assertion must run from
        # each entry point so a partial regression — e.g. PRM's call lost
        # the helper while AS kept it — would fail loudly.
        settings.DEBUG = False
        response = self._get()
        body = response.json()
        assert body["authorization_servers"][0].startswith("https://")

    def test_scopes_and_bearer_methods(self):
        response = self._get()
        body = response.json()
        assert body["scopes_supported"] == ["mcp:sql"]
        # DOT 3.2.0 only accepts header bearers by default.
        assert body["bearer_methods_supported"] == ["header"]

    def test_no_auth_required(self):
        # The endpoint is part of the public discovery surface — gating it
        # would be a chicken-and-egg problem for clients trying to learn
        # how to authenticate.
        response = self._get()
        assert response.status_code == HTTPStatus.OK

    def test_cors_headers_match_actual_method_support(self):
        response = self._get()
        # Public discovery metadata — browser-side `fetch()` clients need
        # CORS to read the document. Wildcard origin is appropriate because
        # the payload carries no per-origin secret.
        assert response["Access-Control-Allow-Origin"] == "*"
        # Advertise only what `@require_safe` actually accepts. OPTIONS
        # is NOT advertised because the view returns 405 on OPTIONS; a
        # CORS preflight following an "Allow-Methods: OPTIONS" hint would
        # be tricked into a request the server then rejects.
        allow = response["Access-Control-Allow-Methods"]
        assert "GET" in allow
        assert "HEAD" in allow
        assert "OPTIONS" not in allow

    def test_head_request_is_supported(self):
        # `require_safe` accepts both GET and HEAD per RFC 7231 §4.1
        # (HEAD == GET without body). Infra probes (uptime checkers, CDN
        # edge probes) commonly HEAD before GET; refusing HEAD with 405
        # is a needless interop pain.
        client = APIClient()
        response = client.head(reverse("mcp_sql_protected_resource_metadata"))
        assert response.status_code == HTTPStatus.OK

    def test_405_on_non_safe_methods(self):
        client = APIClient()
        url = reverse("mcp_sql_protected_resource_metadata")
        # `@require_safe` refuses anything beyond GET/HEAD — including
        # OPTIONS, matching the Allow-Methods advertisement above.
        assert client.post(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.put(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.delete(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.options(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED


@pytest.mark.django_db
class TestAuthorizationServerMetadata:
    """RFC 8414 metadata for the DOT-backed AS."""

    def _get(self, client=None):
        client = client or APIClient()
        return client.get(reverse("oauth_authorization_server_metadata"))

    def test_returns_200_and_json(self):
        response = self._get()
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"].startswith("application/json")

    def test_issuer_is_scoped_under_o_no_trailing_slash(self):
        response = self._get()
        body = response.json()
        # Per RFC 8414 §2: issuer is the AS's canonical identifier URL,
        # no trailing slash, no query/fragment. RFC 8414 §3.1 allows a
        # path component — we use `/o` (DOT's mount) for honesty about
        # what the AS actually is.
        assert body["issuer"].startswith(("http://", "https://"))
        assert body["issuer"].endswith("/o")
        assert "?" not in body["issuer"]
        assert "#" not in body["issuer"]

    def test_issuer_forces_https_when_debug_off(self, settings):
        # RFC 8414 §2 requires https outside loopback / development. Stage
        # and prod trust traefik's X-Forwarded-Proto via SECURE_PROXY_SSL_HEADER,
        # so request.scheme is correctly https. Defense in depth: the view
        # forces `https` whenever DEBUG is off, regardless of request.scheme,
        # so a misbehaving reverse proxy that ever stripped the header
        # cannot get us to advertise `http://...` in non-dev envs.
        settings.DEBUG = False
        response = self._get()
        body = response.json()
        assert body["issuer"].startswith("https://")

    def test_issuer_uses_request_scheme_when_debug_on(self, settings):
        # Local dev (DEBUG=True) keeps `request.scheme` so http is honest
        # on the loopback host. The companion to the DEBUG=False test pins
        # the other branch of `_issuer()`'s conditional.
        settings.DEBUG = True
        response = self._get()
        body = response.json()
        # APIClient defaults to http on `testserver`; the issuer should
        # reflect that scheme rather than the https override.
        assert body["issuer"].startswith("http://")
        assert not body["issuer"].startswith("https://")

    def test_endpoint_urls_match_registered_routes(self):
        response = self._get()
        body = response.json()
        # Hard-coded `http://testserver` is APIClient's default Host. The
        # expected URLs are composed independently of the view's
        # `build_absolute_uri` call so the assertion catches a regression
        # in URL composition (rather than verifying the view's helper
        # equals itself).
        assert (
            body["authorization_endpoint"] == f"http://testserver{reverse('authorize')}"
        )
        assert body["token_endpoint"] == f"http://testserver{reverse('token')}"
        assert (
            body["revocation_endpoint"] == f"http://testserver{reverse('revoke-token')}"
        )
        # RFC 7591 §3 dynamic client registration. Claude Code's MCP SDK
        # refuses to complete OAuth without this advertised — pinned here
        # so a regression that dropped the field would fail loudly.
        assert (
            body["registration_endpoint"]
            == f"http://testserver{reverse('oauth_dynamic_client_registration')}"
        )

    def test_advertised_capabilities(self):
        response = self._get()
        body = response.json()
        assert body["scopes_supported"] == ["mcp:sql"]
        assert body["response_types_supported"] == ["code"]
        assert body["grant_types_supported"] == ["authorization_code"]
        # S256 only — `MCPOAuth2Validator.validate_code_challenge_method`
        # rejects `plain` at the validator layer; the advertised list must
        # match the enforced list.
        assert body["code_challenge_methods_supported"] == ["S256"]
        # Public client — PKCE is the client-auth proxy, no secret.
        assert body["token_endpoint_auth_methods_supported"] == ["none"]
        # RFC 8414 §2: when revocation_endpoint is advertised,
        # revocation_endpoint_auth_methods_supported SHOULD be too.
        assert body["revocation_endpoint_auth_methods_supported"] == ["none"]

    def test_no_auth_required(self):
        response = self._get()
        assert response.status_code == HTTPStatus.OK

    def test_cors_headers_match_actual_method_support(self):
        response = self._get()
        assert response["Access-Control-Allow-Origin"] == "*"
        allow = response["Access-Control-Allow-Methods"]
        assert "GET" in allow
        assert "HEAD" in allow
        assert "OPTIONS" not in allow

    def test_head_request_is_supported(self):
        client = APIClient()
        response = client.head(reverse("oauth_authorization_server_metadata"))
        assert response.status_code == HTTPStatus.OK

    def test_405_on_non_safe_methods(self):
        client = APIClient()
        url = reverse("oauth_authorization_server_metadata")
        assert client.post(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.put(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.delete(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert client.options(url).status_code == HTTPStatus.METHOD_NOT_ALLOWED


# `TestWWWAuthenticateAdvertisesDiscovery` (the 401-challenge content
# assertion) lives in `tests/test_auth_class.py` where the auth class is
# the unit under test; this file scopes to the discovery views proper.
