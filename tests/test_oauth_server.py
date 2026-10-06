"""End-to-end tests for the narrow OAuth surface: `oauth_server.MCPServer` on
the package's views, `MCPTokenView`'s guard, and the validator's backstops."""

import base64
import hashlib
import secrets
from datetime import timedelta
from http import HTTPStatus
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.oauth_server import HeaderOnlyBearer
from mcp_sql.oauth_server import MCPAuthorizationCodeGrant
from mcp_sql.oauth_server import MCPServer
from mcp_sql.views.oauth_authorize import MCPAuthorizationView
from mcp_sql.views.oauth_token import MCPRevokeTokenView
from mcp_sql.views.oauth_token import MCPTokenView
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Grant
from oauth2_provider.models import RefreshToken
from oauth2_provider.oauth2_backends import OAuthLibCore
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views import AuthorizationView
from oauth2_provider.views import RevokeTokenView
from oauth2_provider.views import TokenView
from oauthlib.oauth2 import Server

_LOOPBACK = "http://127.0.0.1:9999"
_PASSWORD = "CorrectHorse9!"


def _basic(credentials: bytes) -> str:
    """An HTTP Basic `Authorization` header value for raw `id:secret` bytes."""
    return "Basic " + base64.b64encode(credentials).decode("ascii")


def _s256_pair() -> tuple[str, str]:
    """A fresh PKCE (code_verifier, S256 code_challenge) pair."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _grant(user, app, *, challenge: str, method: str) -> Grant:
    """An authorization code for the canonical client, as /o/authorize/ stores it."""
    return Grant.objects.create(
        user=user,
        code=secrets.token_urlsafe(32),
        application=app,
        expires=timezone.now() + timedelta(minutes=1),
        redirect_uri=_LOOPBACK,
        scope="mcp:sql",
        code_challenge=challenge,
        code_challenge_method=method,
    )


def _authorize_query(response) -> dict:
    """The query of an /o/authorize/ redirect back to the loopback callback."""
    assert response.status_code == HTTPStatus.FOUND, response.content
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == _LOOPBACK
    assert not location.fragment  # no implicit-grant token in a fragment
    return parse_qs(location.query)


@pytest.fixture
def password_user(db):
    """A user whose password a password-grant probe could guess."""
    return get_user_model().objects.create_user(
        "victim", "victim@example.com", _PASSWORD
    )


@pytest.fixture
def no_authenticate(monkeypatch) -> list:
    """Record every call DOT's `validate_user` would make to `authenticate`."""
    calls: list = []
    monkeypatch.setattr(
        "oauth2_provider.oauth2_validators.authenticate",
        lambda *_a, **k: calls.append(k),
    )
    return calls


@pytest.mark.django_db
class TestTokenEndpointGrantTypes:
    """`/o/token/` answers every grant but `authorization_code` with 400
    `unsupported_grant_type`, before DOT's device-flow branch or any server."""

    @pytest.mark.parametrize(
        "data",
        [
            {"grant_type": "client_credentials", "client_id": "mcp-sql"},
            {
                "grant_type": "refresh_token",
                "refresh_token": "x",
                "client_id": "mcp-sql",
            },
            {"grant_type": "implicit", "client_id": "mcp-sql"},
            {"grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": "x",
                "client_id": "mcp-sql",
            },
            {"grant_type": "openid", "code": "x", "client_id": "mcp-sql"},
            {"grant_type": "no-such-grant", "client_id": "mcp-sql"},
            {"code": "x", "client_id": "mcp-sql"},
            {"grant_type": ["authorization_code", "password"], "code": "x"},
            {"grant_type": ["authorization_code", "authorization_code"], "code": "x"},
        ],
        ids=[
            "client_credentials",
            "refresh_token",
            "implicit",
            "device_code-without-device_code",
            "device_code",
            "openid",
            "unknown",
            "missing",
            "repeated-mixed",
            "repeated-same",
        ],
    )
    def test_refused(self, client, mcp_app, data):
        response = client.post(reverse("token"), data)
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json() == {"error": "unsupported_grant_type"}
        assert response["Cache-Control"] == "no-store"
        assert not AccessToken.objects.exists()

    def test_password_grant_is_no_password_oracle(
        self, client, mcp_app, password_user, no_authenticate
    ):
        """A correct and a wrong password get byte-identical answers, and the
        password is never checked (DOT's `authenticate` is not reached)."""
        responses = [
            client.post(
                reverse("token"),
                {
                    "grant_type": "password",
                    "client_id": "mcp-sql",
                    "username": password_user.get_username(),
                    "password": password,
                },
            )
            for password in (_PASSWORD, "wrong")
        ]
        assert [(r.status_code, r.content) for r in responses] == [
            (HTTPStatus.BAD_REQUEST, b'{"error": "unsupported_grant_type"}')
        ] * 2
        assert no_authenticate == []

    def test_query_string_grant_type_does_not_count(self, client, mcp_app):
        # DOT reads the form body; a grant_type only in the URL is missing.
        response = client.post(
            reverse("token") + "?grant_type=authorization_code",
            {"code": "x", "client_id": "mcp-sql"},
        )
        assert response.json() == {"error": "unsupported_grant_type"}

    def test_authorization_code_still_reaches_the_server(self, client, mcp_app):
        response = client.post(
            reverse("token"),
            {"grant_type": "authorization_code", "code": "x", "client_id": "mcp-sql"},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_grant"  # unknown code


@pytest.mark.django_db
class TestAuthorizeEndpointResponseTypes:
    """`/o/authorize/` serves the `code` response type only."""

    @pytest.mark.parametrize("response_type", ["token", "id_token", "bogus"])
    def test_non_code_response_type_is_refused(
        self, client, mcp_app, mcp_user, mcp_mfa_on, response_type
    ):
        client.force_login(mcp_user)
        _verifier, challenge = _s256_pair()
        params = {
            "client_id": "mcp-sql",
            "response_type": response_type,
            "redirect_uri": _LOOPBACK,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query = _authorize_query(
            client.get(reverse("authorize") + "?" + urlencode(params))
        )
        assert query["error"] == ["unsupported_response_type"]
        assert "code" not in query
        assert not AccessToken.objects.exists()
        assert not Grant.objects.exists()

    def test_code_flow_issues_a_token_without_a_refresh_token(
        self, client, mcp_app, mcp_user, mcp_mfa_on
    ):
        client.force_login(mcp_user)
        verifier, challenge = _s256_pair()
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "redirect_uri": _LOOPBACK,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query = _authorize_query(
            client.get(reverse("authorize") + "?" + urlencode(params))
        )
        response = client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": _LOOPBACK,
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == HTTPStatus.OK, response.content
        assert set(response.json()) == {
            "access_token",
            "expires_in",
            "token_type",
            "scope",
        }
        assert not RefreshToken.objects.exists()


@pytest.mark.django_db
class TestRevokeEndpoint:
    """`/o/revoke_token/` (RFC 7009) still works on `MCPServer`."""

    def test_revokes_an_access_token(self, client, mcp_app, mcp_access_token):
        response = client.post(
            reverse("revoke-token"),
            {"token": mcp_access_token.token, "client_id": "mcp-sql"},
        )
        assert response.status_code == HTTPStatus.OK, response.content
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()


class TestServerShape:
    """`MCPServer` exposes exactly the advertised surface, on every view."""

    @pytest.mark.parametrize(
        "view", [MCPAuthorizationView, MCPTokenView, MCPRevokeTokenView]
    )
    def test_package_views_run_on_mcp_server(self, view, settings):
        # Even with the consumer's server set to oauthlib's all-grants one.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "OAUTH2_SERVER_CLASS": "oauthlib.oauth2.Server",
            "ALWAYS_RELOAD_OAUTHLIB_CORE": True,
        }
        server = view.get_oauthlib_core().server
        assert type(server) is MCPServer
        assert set(server.response_types) == {"code"}
        assert set(server.grant_types) == {"authorization_code"}
        assert set(server.tokens) == {"Bearer"}
        grant = server.grant_types["authorization_code"]
        assert isinstance(grant, MCPAuthorizationCodeGrant)
        assert grant.refresh_token is False
        assert set(grant._code_challenge_methods) == {"S256"}
        assert isinstance(server.tokens["Bearer"], HeaderOnlyBearer)

    def test_server_kwargs_from_dot_are_honoured(self, settings):
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ACCESS_TOKEN_EXPIRE_SECONDS": 1234,
            "ALWAYS_RELOAD_OAUTHLIB_CORE": True,
        }
        server = MCPTokenView.get_oauthlib_core().server
        assert server.bearer.expires_in == 1234

    @pytest.mark.parametrize(
        ("stock", "mcp"),
        [
            (AuthorizationView, MCPAuthorizationView),
            (TokenView, MCPTokenView),
            (RevokeTokenView, MCPRevokeTokenView),
        ],
    )
    def test_a_core_cached_on_the_stock_view_is_not_inherited(
        self, monkeypatch, stock, mcp
    ):
        """DOT caches the core behind `hasattr(cls, "_oauthlib_core")`, which
        a core cached on the stock parent view satisfies. Once a stock view
        has served a request, the subclass must still build its own."""
        stock_core = OAuthLibCore(Server(MCPOAuth2Validator()))
        monkeypatch.setattr(stock, "_oauthlib_core", stock_core, raising=False)
        monkeypatch.delattr(mcp, "_oauthlib_core", raising=False)
        assert type(mcp.get_oauthlib_core().server) is MCPServer
        assert stock.get_oauthlib_core() is stock_core


@pytest.mark.django_db
class TestConsumerServerClassDoesNotWiden:
    """A consumer's `OAUTH2_SERVER_CLASS` (here oauthlib's all-grants
    `Server`, DOT's default) reaches none of the package's endpoints."""

    @pytest.fixture(autouse=True)
    def _all_grants_server(self, settings, monkeypatch):
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "OAUTH2_SERVER_CLASS": "oauthlib.oauth2.Server",
        }
        # A stock view that served a request first (cached its core).
        for stock in (AuthorizationView, TokenView, RevokeTokenView):
            monkeypatch.setattr(
                stock,
                "_oauthlib_core",
                OAuthLibCore(Server(MCPOAuth2Validator())),
                raising=False,
            )
        for mcp in (MCPAuthorizationView, MCPTokenView, MCPRevokeTokenView):
            monkeypatch.delattr(mcp, "_oauthlib_core", raising=False)

    def test_implicit_grant_stays_refused(self, client, mcp_app, mcp_user, mcp_mfa_on):
        client.force_login(mcp_user)
        _verifier, challenge = _s256_pair()
        params = {
            "client_id": "mcp-sql",
            "response_type": "token",
            "redirect_uri": _LOOPBACK,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query = _authorize_query(
            client.get(reverse("authorize") + "?" + urlencode(params))
        )
        assert query["error"] == ["unsupported_response_type"]
        assert not AccessToken.objects.exists()

    def test_plain_pkce_stays_refused(self, client, mcp_app, mcp_user, mcp_mfa_on):
        client.force_login(mcp_user)
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "redirect_uri": _LOOPBACK,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": secrets.token_urlsafe(48),
            "code_challenge_method": "plain",
        }
        query = _authorize_query(
            client.get(reverse("authorize") + "?" + urlencode(params))
        )
        assert query["error"] == ["invalid_request"]
        assert not Grant.objects.exists()

    def test_refresh_grant_stays_refused(self, client, mcp_app):
        response = client.post(
            reverse("token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": "x",
                "client_id": "mcp-sql",
            },
        )
        assert response.json() == {"error": "unsupported_grant_type"}

    def test_query_string_token_stays_refused(
        self, client, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        response = client.post(
            f"/mcp/sql/?access_token={mcp_access_token.token}",
            data="{}",
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.django_db
class TestValidatorBackstopsOnStockViews:
    """`MCPOAuth2Validator` is the install's validator, so its backstops hold
    even for DOT's stock `TokenView` on DOT's stock (all-grants) server — a
    consumer may mount DOT's own URLs beside the package's."""

    @pytest.fixture
    def stock_token(self, monkeypatch):
        core = OAuthLibCore(
            Server(MCPOAuth2Validator(), **oauth2_settings.server_kwargs)
        )
        monkeypatch.setattr(TokenView, "_oauthlib_core", core, raising=False)
        view = TokenView.as_view()

        def post(data: dict):
            return view(RequestFactory().post("/o/token/", data))

        return post

    def test_password_grant_is_invalid_grant_for_any_password(
        self, mcp_app, password_user, no_authenticate, stock_token
    ):
        responses = [
            stock_token(
                {
                    "grant_type": "password",
                    "client_id": "mcp-sql",
                    "username": password_user.get_username(),
                    "password": password,
                }
            )
            for password in (_PASSWORD, "wrong")
        ]
        assert [r.status_code for r in responses] == [HTTPStatus.BAD_REQUEST] * 2
        assert responses[0].content == responses[1].content
        assert b'"invalid_grant"' in responses[0].content
        assert no_authenticate == []
        assert not AccessToken.objects.exists()

    def test_refresh_grant_is_invalid_grant(
        self, mcp_app, mcp_user, mcp_access_token, stock_token, monkeypatch
    ):
        # A refresh token as releases up to and including 0.1.0b5 stored it,
        # which DOT itself would honour (pinned by the monkeypatch control).
        legacy = RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=mcp_app,
            access_token=mcp_access_token,
        )
        data = {
            "grant_type": "refresh_token",
            "refresh_token": legacy.token,
            "client_id": "mcp-sql",
        }
        response = stock_token(data)
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert b'"invalid_grant"' in response.content
        assert list(AccessToken.objects.all()) == [mcp_access_token]
        # Control: DOT's own hook would have renewed access.
        monkeypatch.setattr(
            MCPOAuth2Validator,
            "validate_refresh_token",
            OAuth2Validator.validate_refresh_token,
        )
        assert stock_token(data).status_code == HTTPStatus.OK

    def test_stored_plain_grant_is_invalid_grant(self, mcp_app, mcp_user, stock_token):
        verifier = secrets.token_urlsafe(48)
        grant = _grant(mcp_user, mcp_app, challenge=verifier, method="plain")
        response = stock_token(
            {
                "grant_type": "authorization_code",
                "code": grant.code,
                "redirect_uri": _LOOPBACK,
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            }
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert b'"invalid_grant"' in response.content
        assert not AccessToken.objects.exists()


@pytest.mark.django_db
class TestControlCharacters:
    """A NUL in an identifier reached a Postgres text lookup and raised an
    uncaught 500 (DataError). The default test client re-raises a view
    exception, so a regression fails here with that error, not a status."""

    @pytest.mark.parametrize(
        "params",
        [
            {"code": "\x00", "client_id": "mcp-sql"},
            {"code": "x", "client_id": "\x00"},
            {"code": "x", "client_id": "mcp-sql", "redirect_uri": "http://127.0.0.1\n"},
            {"code": "x", "client_id": "mcp-sql", "code_verifier": "v\x7f"},
        ],
        ids=["code", "client_id", "redirect_uri", "code_verifier"],
    )
    def test_token_request_parameter(self, client, mcp_app, params):
        response = client.post(
            reverse("token"), {"grant_type": "authorization_code", **params}
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_request"
        assert response["Cache-Control"] == "no-store"

    def test_token_query_parameter(self, client, mcp_app):
        response = client.post(
            reverse("token") + "?client_id=%00",
            {"grant_type": "authorization_code", "code": "x"},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_request"

    @pytest.mark.parametrize(
        "credentials", [b"\x00:x", b"%00:x"], ids=["raw", "percent-encoded"]
    )
    def test_token_basic_auth_client_id(self, client, mcp_app, credentials):
        # DOT URL-decodes the Basic credentials itself, so the parameter
        # check cannot see this NUL; the validator refuses the lookup.
        response = client.post(
            reverse("token"),
            {"grant_type": "authorization_code", "code": "x"},
            HTTP_AUTHORIZATION=_basic(credentials),
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.json()["error"] == "invalid_client"

    @pytest.mark.parametrize(
        ("data", "headers"),
        [
            ({"token": "abc", "client_id": "\x00"}, {}),
            ({"token": "abc"}, {"HTTP_AUTHORIZATION": _basic(b"\x00:x")}),
        ],
        ids=["client_id", "basic-auth"],
    )
    def test_revoke_client_id(self, client, mcp_app, data, headers):
        response = client.post(reverse("revoke-token"), data, **headers)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.json()["error"] == "invalid_client"

    def test_revoke_token_value(self, client, mcp_app, mcp_access_token):
        # DOT looks the token up by its SHA-256 checksum, so the NUL never
        # reaches Postgres; RFC 7009 answers 200 for an unknown token.
        response = client.post(
            reverse("revoke-token"), {"token": "\x00", "client_id": "mcp-sql"}
        )
        assert response.status_code == HTTPStatus.OK
        assert AccessToken.objects.filter(pk=mcp_access_token.pk).exists()

    @pytest.mark.parametrize("logged_in", [False, True], ids=["anonymous", "user"])
    def test_authorize_client_id(
        self, client, mcp_app, mcp_user, mcp_mfa_on, logged_in
    ):
        # Anonymous: `prompt=none` is validated before the login redirect.
        if logged_in:
            client.force_login(mcp_user)
        params = {
            "client_id": "\x00",
            "response_type": "code",
            "prompt": "none",
            "redirect_uri": "http://127.0.0.1:9999",
        }
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        # A fatal client error: the error page, never a redirect.
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Location" not in response
