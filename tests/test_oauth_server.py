"""End-to-end tests for the narrow OAuth surface: `oauth_server.MCPServer` on
the package's views, `MCPTokenView`'s guard, and the validator's backstops."""

import base64
from http import HTTPStatus
from urllib.parse import urlencode

import pytest
from django.urls import reverse
from oauth2_provider.models import AccessToken


def _basic(credentials: bytes) -> str:
    """An HTTP Basic `Authorization` header value for raw `id:secret` bytes."""
    return "Basic " + base64.b64encode(credentials).decode("ascii")


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
