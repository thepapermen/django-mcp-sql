"""Tests for the OAuth validator and the issuance-gate AuthorizationView."""

import base64
import hashlib
import json
import secrets
from http import HTTPStatus
from unittest.mock import MagicMock
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import resolve_url
from django.urls import reverse
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP
from mcp_sql.views.oauth_authorize import MCPAuthorizationView
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Grant
from oauth2_provider.models import RefreshToken
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

# A dynamically-registered client's loopback callback for the end-to-end flows.
_LOOPBACK = "http://127.0.0.1:8765/cb"


def _s256_pair() -> tuple[str, str]:
    """A fresh PKCE (code_verifier, S256 code_challenge) pair."""
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


def _register_dcr_client(client) -> str:
    """Register via `/o/register` the way Anthropic's MCP SDK does (it asks for
    `refresh_token` too) and return the minted client_id."""
    response = client.post(
        reverse("oauth_dynamic_client_registration"),
        data=json.dumps(
            {
                "redirect_uris": [_LOOPBACK],
                "grant_types": ["authorization_code", "refresh_token"],
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == HTTPStatus.CREATED, response.content
    return response.json()["client_id"]


def _authorize_params(client_id: str, challenge, method) -> dict:
    """An `/o/authorize/` request; `None` leaves that PKCE parameter out."""
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": _LOOPBACK,
        "scope": "mcp:sql",
        "state": "st4te",
    }
    if challenge is not None:
        params["code_challenge"] = challenge
    if method is not None:
        params["code_challenge_method"] = method
    return params


def _redirect_query(response) -> dict:
    """The query of a 302 back to the loopback callback, parsed."""
    assert response.status_code == HTTPStatus.FOUND, response.content
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == _LOOPBACK
    return parse_qs(location.query)


@pytest.mark.django_db
class TestMCPOAuth2ValidatorClientId:
    """`validate_client_id` rejects anything that isn't the lone `mcp-sql` app."""

    def test_accepts_mcp_sql_application(self, mcp_app):
        validator = MCPOAuth2Validator()
        request = MagicMock(client=mcp_app)
        # Parent validator's lookup is mocked True so we test only our overlay.
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "mcp_sql.oauth.OAuth2Validator.validate_client_id",
                lambda self, client_id, request, *args, **kwargs: True,
            )
            assert validator.validate_client_id(mcp_app.client_id, request) is True

    def test_rejects_application_with_different_name(self, mcp_app, monkeypatch):
        from oauth2_provider.models import Application

        other = Application.objects.create(
            name="something-else",
            client_id="other-client",
            client_secret="",
            client_type="public",
            authorization_grant_type="authorization-code",
            redirect_uris="http://127.0.0.1",
        )
        validator = MCPOAuth2Validator()
        request = MagicMock(client=other)
        monkeypatch.setattr(
            "mcp_sql.oauth.OAuth2Validator.validate_client_id",
            lambda self, client_id, request, *args, **kwargs: True,
        )
        assert validator.validate_client_id(other.client_id, request) is False

    def test_rejects_when_super_rejects(self, monkeypatch):
        validator = MCPOAuth2Validator()
        request = MagicMock(client=None)
        monkeypatch.setattr(
            "mcp_sql.oauth.OAuth2Validator.validate_client_id",
            lambda self, client_id, request, *args, **kwargs: False,
        )
        assert validator.validate_client_id("nonexistent", request) is False


@pytest.mark.django_db
class TestMCPOAuth2ValidatorScopes:
    """`validate_scopes` is pinned to exactly `{mcp:sql}`."""

    def _validator_with_parent_true(self, monkeypatch) -> MCPOAuth2Validator:
        monkeypatch.setattr(
            "mcp_sql.oauth.OAuth2Validator.validate_scopes",
            lambda self, *a, **kw: True,
        )
        return MCPOAuth2Validator()

    def test_accepts_mcp_sql_only(self, monkeypatch):
        v = self._validator_with_parent_true(monkeypatch)
        assert v.validate_scopes("c", ["mcp:sql"], None, MagicMock()) is True

    def test_rejects_extra_scope(self, monkeypatch):
        v = self._validator_with_parent_true(monkeypatch)
        assert v.validate_scopes("c", ["mcp:sql", "read"], None, MagicMock()) is False

    def test_rejects_different_scope(self, monkeypatch):
        v = self._validator_with_parent_true(monkeypatch)
        assert v.validate_scopes("c", ["read"], None, MagicMock()) is False

    def test_rejects_empty_scopes(self, monkeypatch):
        v = self._validator_with_parent_true(monkeypatch)
        assert v.validate_scopes("c", [], None, MagicMock()) is False


class TestMCPOAuth2ValidatorPKCE:
    """S256-only PKCE through the hooks oauthlib actually calls.

    `is_pkce_required` (authorize) forces PKCE on and refuses any method but
    `S256`; `get_code_challenge_method` (token) refuses a stored non-S256
    grant. End-to-end behaviour: `TestPKCEEnforcedEndToEnd`.
    """

    @staticmethod
    def _request(challenge, method):
        return MagicMock(code_challenge=challenge, code_challenge_method=method)

    def test_s256_challenge_is_required_and_accepted(self):
        request = self._request("x" * 43, "S256")
        assert MCPOAuth2Validator().is_pkce_required("c", request) is True

    def test_pkce_stays_required_when_the_consumer_disables_it(self, settings):
        settings.OAUTH2_PROVIDER = {**settings.OAUTH2_PROVIDER, "PKCE_REQUIRED": False}
        request = self._request(None, None)
        assert MCPOAuth2Validator().is_pkce_required("c", request) is True

    @pytest.mark.parametrize("method", ["plain", None, "", "s256", "S512"])
    def test_any_other_method_is_an_invalid_request(self, method):
        with pytest.raises(InvalidRequestError):
            MCPOAuth2Validator().is_pkce_required("c", self._request("x" * 43, method))

    @pytest.mark.parametrize(
        ("stored", "returned"), [("S256", "S256"), ("plain", None), (None, None)]
    )
    def test_token_time_backstop_hides_non_s256_methods(
        self, monkeypatch, stored, returned
    ):
        monkeypatch.setattr(
            OAuth2Validator, "get_code_challenge_method", lambda *_a, **_k: stored
        )
        assert (
            MCPOAuth2Validator().get_code_challenge_method("code", MagicMock())
            == returned
        )


class TestMCPOAuth2ValidatorRefresh:
    """No refresh grants, no refresh tokens. End-to-end: `TestRefreshRefused`."""

    def test_refuses_a_refresh_token_dot_would_accept(self, monkeypatch):
        monkeypatch.setattr(
            OAuth2Validator, "validate_refresh_token", lambda *_a, **_k: True
        )
        assert (
            MCPOAuth2Validator().validate_refresh_token("rt", MagicMock(), MagicMock())
            is False
        )

    def test_refresh_token_is_dropped_before_dot_stores_the_token(self, monkeypatch):
        stored: dict = {}
        monkeypatch.setattr(
            OAuth2Validator,
            "save_bearer_token",
            lambda _self, token, _request, *_a, **_k: stored.update(token),
        )
        token = {"access_token": "at", "refresh_token": "rt", "scope": "mcp:sql"}
        MCPOAuth2Validator().save_bearer_token(token, MagicMock())
        # Mutated in place: oauthlib serialises this same dict as the response.
        assert "refresh_token" not in token
        assert "refresh_token" not in stored
        assert stored["access_token"] == "at"


@pytest.mark.django_db
class TestMCPAuthorizationViewGate:
    """`_enforce_gate` is the issuance gate — exhaustive negative coverage."""

    def test_happy_path_returns_none(self, mcp_user, mcp_mfa_on):
        assert MCPAuthorizationView._enforce_gate(mcp_user) is None

    def test_inactive_user_denied(self, mcp_user, mcp_mfa_on):
        mcp_user.is_active = False
        mcp_user.save()
        with pytest.raises(PermissionDenied, match="active staff"):
            MCPAuthorizationView._enforce_gate(mcp_user)

    def test_non_staff_user_denied(self, mcp_user, mcp_mfa_on):
        mcp_user.is_staff = False
        mcp_user.save()
        with pytest.raises(PermissionDenied, match="active staff"):
            MCPAuthorizationView._enforce_gate(mcp_user)

    def test_no_mfa_denied(self, mcp_user, mcp_mfa_off):
        with pytest.raises(PermissionDenied, match="verified TOTP"):
            MCPAuthorizationView._enforce_gate(mcp_user)

    def test_missing_permission_denied(self, mcp_user, use_mcp_perm, mcp_mfa_on):
        mcp_user.user_permissions.remove(use_mcp_perm)
        # No profile assignment remains → resolve_profile returns NO_PERM.
        mcp_user = type(mcp_user).objects.get(pk=mcp_user.pk)
        with pytest.raises(PermissionDenied, match="MCP profile assignment"):
            MCPAuthorizationView._enforce_gate(mcp_user)

    def test_ambiguous_profile_denied(self, two_profiles, mcp_user_factory, mcp_mfa_on):
        """A user in >1 MCP profile group is denied at issuance (TIC-585)."""
        from django.contrib.auth.models import Group

        user = mcp_user_factory(is_active=True, is_staff=True)
        user.groups.add(Group.objects.get(name="mcp_sql_users"))
        user.groups.add(Group.objects.get(name=SECOND_PROFILE_GROUP))
        with pytest.raises(PermissionDenied, match="more than one MCP profile"):
            MCPAuthorizationView._enforce_gate(user)


@pytest.mark.django_db
class TestMCPAuthorizationViewRouting:
    """Smoke: anonymous GET is redirected by DOT's LoginRequiredMixin."""

    def test_anonymous_authorize_redirects_to_login(self, client):
        response = client.get(reverse("authorize"))
        assert response.status_code == HTTPStatus.FOUND
        # Wherever the consumer's LOGIN_URL points (an allauth
        # /accounts/login/, the admin login, ...) — not a hardcoded path.
        assert resolve_url(settings.LOGIN_URL) in response["Location"]

    def test_anonymous_prompt_none_never_redirects_off_machine(self, client, mcp_app):
        """DOT before 3.4.0 answered an anonymous `prompt=none` request with a
        302 to whatever `redirect_uri` it named — before validating the client
        or the URI (DOT #1719), so before any check of this package. The
        `django-oauth-toolkit>=3.4.1` floor keeps this out: the request is now
        validated first, and an off-machine URI gets an error page.
        """
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "prompt": "none",
            "redirect_uri": "https://evil.example/x",
            "state": "st4te",
        }
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response

    def test_anonymous_prompt_none_errors_back_to_a_valid_loopback(
        self, client, mcp_app
    ):
        # Positive control: for a VALID request, `prompt=none` still answers
        # an anonymous user with `login_required` at the client's redirect URI
        # (OIDC Core §3.1.2.6) instead of a login page.
        _verifier, challenge = _s256_pair()
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "prompt": "none",
            "redirect_uri": "http://127.0.0.1:9999",
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        assert response.status_code == HTTPStatus.FOUND, response.content
        location = urlparse(response["Location"])
        assert f"{location.scheme}://{location.netloc}" == "http://127.0.0.1:9999"
        assert parse_qs(location.query)["error"] == ["login_required"]


@pytest.mark.django_db
class TestOAuthTokenEndpointHappyPath:
    """The /o/token/ endpoint must accept form-encoded PKCE token exchange.

    Pins the contract that fix #1 (commit `679ffd4d`, removing
    `OAUTH2_BACKEND_CLASS=JSONOAuthLibCore`) was about: RFC 6749 §4.1.3
    mandates `application/x-www-form-urlencoded` for the token endpoint.
    The previous backend silently zeroed form bodies; this test would
    have failed under that misconfig.
    """

    def test_pkce_code_exchange_returns_access_token(self, client, mcp_user, mcp_app):
        import base64
        import hashlib
        import secrets as _secrets
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import Grant

        # Generate a PKCE code_verifier / code_challenge pair (S256).
        verifier = _secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode("ascii")
        )

        # Pre-mint a Grant (authorization code) bound to the mcp-sql app.
        # In production this row is created by /o/authorize/ after the gate
        # passes; we skip the gate leg here to keep this test focused on
        # the form-encoded /o/token/ exchange.
        #
        # `redirect_uri="http://127.0.0.1:9999"` (no path): DOT 3.x's
        # `redirect_to_uri_allowed` accepts any port on a registered
        # loopback URI but still requires path-exact-match. The Application
        # row registers `http://127.0.0.1` (no path), so the client URI
        # must also have no path.
        code = _secrets.token_urlsafe(32)
        Grant.objects.create(
            user=mcp_user,
            code=code,
            application=mcp_app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri="http://127.0.0.1:9999",
            scope="mcp:sql",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        response = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:9999",
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
            # NB: form-encoded (the default for Django test Client.post when
            # passing a dict). RFC 6749 §4.1.3 mandates this content type.
        )

        assert response.status_code == HTTPStatus.OK, response.content
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["scope"] == "mcp:sql"
        assert "access_token" in body
        # No refresh token: `MCPOAuth2Validator.save_bearer_token` drops it
        # before DOT stores the token, so neither the response field nor a
        # `RefreshToken` row exists (`REFRESH_TOKEN_EXPIRE_SECONDS=0` alone
        # would NOT have stopped one from working — see TestRefreshRefused).
        assert "refresh_token" not in body
        assert not RefreshToken.objects.exists()

        # Verify the DB row matches what the response describes — defends
        # against a DOT regression that mis-binds the token's user/app/scope.
        from oauth2_provider.models import AccessToken

        token_row = AccessToken.objects.get(token=body["access_token"])
        assert token_row.user_id == mcp_user.pk
        assert token_row.application_id == mcp_app.pk
        assert token_row.scope == "mcp:sql"
        assert token_row.expires > timezone.now()

    @pytest.mark.parametrize("method", ["plain", None], ids=["plain", "omitted"])
    def test_non_s256_pkce_is_rejected_at_authorize(
        self, client, mcp_user, mcp_app, mcp_mfa_on, method
    ):
        """A `plain` (or omitted, which oauthlib defaults to `plain`)
        `code_challenge_method` at /o/authorize/ must be refused.

        Against the canonical row, which skips consent: the GET alone would
        otherwise 302 straight back with a code. The refusal is oauthlib's
        normal error redirect to the (already validated) loopback URI —
        `invalid_request`, no code, no Grant.
        """
        client.force_login(mcp_user)
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "redirect_uri": "http://127.0.0.1:9999",
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": secrets.token_urlsafe(48),
        }
        if method is not None:
            params["code_challenge_method"] = method
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        assert response.status_code == HTTPStatus.FOUND, response.content
        location = urlparse(response["Location"])
        assert f"{location.scheme}://{location.netloc}" == "http://127.0.0.1:9999"
        query = parse_qs(location.query)
        assert query["error"] == ["invalid_request"]
        assert query["state"] == ["st4te"]
        assert "code" not in query
        assert not Grant.objects.filter(application=mcp_app).exists()

    def test_token_minted_via_oauth_pipeline_authenticates_against_mcp_view(
        self, client, mcp_user, mcp_app, mcp_mfa_on, mcp_active_session
    ):
        """End-to-end: a token minted via /o/token/ satisfies MCPOAuth2Authentication.

        This pins the contract the whole subsystem is built on. The two
        existing tests (`TestOAuthTokenEndpointHappyPath` and
        `TestMcpEndpointHappyPath`) only prove each half in isolation —
        this test chains them so a future regression that decouples them
        (e.g. /o/token/ minting tokens with `scope=""` while the auth
        class rejects empty scope) would fail loudly.
        """
        import base64
        import hashlib
        import secrets as _secrets
        from datetime import timedelta

        from django.utils import timezone
        from mcp_sql.auth import MCPOAuth2Authentication
        from oauth2_provider.models import Grant
        from rest_framework.test import APIRequestFactory

        verifier = _secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        code = _secrets.token_urlsafe(32)
        Grant.objects.create(
            user=mcp_user,
            code=code,
            application=mcp_app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri="http://127.0.0.1:9999",
            scope="mcp:sql",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        response = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:9999",
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == HTTPStatus.OK
        access_token = response.json()["access_token"]

        # The token from /o/token/ must satisfy the MCP auth class.
        bearer_request = APIRequestFactory().post(
            "/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        user, token = MCPOAuth2Authentication().authenticate(bearer_request)
        assert user.pk == mcp_user.pk
        assert token.application_id == mcp_app.pk
        assert "mcp:sql" in token.scope.split()


@pytest.mark.django_db
class TestMCPAuthorizationViewLiveGate:
    """Authenticated user hits `/o/authorize/` — the gate fires through the URL.

    `TestMCPAuthorizationViewGate` tests `_enforce_gate(user)` directly.
    These tests exercise the same code path through `dispatch` so a future
    refactor that moves the gate elsewhere (e.g. into a middleware) would
    fail this suite even if `_enforce_gate` is left intact.
    """

    # `redirect_uri=http://127.0.0.1:9999` (no path): DOT 3.x accepts any
    # port on a registered loopback URI but requires path-exact-match.
    # The Application row registers `http://127.0.0.1` (no path). Value is
    # URL-encoded — DOT's URL parser is strict about reserved chars in the
    # query string.
    AUTHORIZE_QS = (
        "?client_id=mcp-sql"
        "&response_type=code"
        "&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999"
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        "&code_challenge_method=S256"
    )

    def _authorize_url(self) -> str:
        return reverse("authorize") + self.AUTHORIZE_QS

    # The `is_active=False` path is NOT integration-tested here: Django's
    # `ModelBackend.get_user` returns `None` for inactive users, and
    # `AuthenticationMiddleware` then resolves `request.user` to
    # `AnonymousUser`. DOT's `LoginRequiredMixin` then 302s to login
    # BEFORE the gate runs. The gate's inactive-user branch is exercised
    # directly in `TestMCPAuthorizationViewGate.test_inactive_user_denied`.

    def test_non_staff_user_denied(self, client, mcp_user, mcp_mfa_on):
        mcp_user.is_staff = False
        mcp_user.save()
        client.force_login(mcp_user)
        response = client.get(self._authorize_url())
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_user_without_mfa_denied(self, client, mcp_user, mcp_mfa_off):
        client.force_login(mcp_user)
        response = client.get(self._authorize_url())
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_user_without_perm_denied(self, client, mcp_user, use_mcp_perm, mcp_mfa_on):
        mcp_user.user_permissions.remove(use_mcp_perm)
        client.force_login(mcp_user)
        response = client.get(self._authorize_url())
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_user_with_all_gates_passes(self, client, mcp_user, mcp_mfa_on):
        """The gate must let a fully-qualified user through to DOT's view.

        Test scope: the issuance gate. Anything other than 403 proves the
        gate did not reject. Whether DOT then issues a 302 to the
        loopback callback (full happy path) or a 400 for some other
        reason (e.g. missing required oauthlib parameter that this fixture
        chose to omit for brevity) is DOT's concern, not the gate's.
        The token-endpoint happy path is exercised by
        `TestOAuthTokenEndpointHappyPath`.
        """
        client.force_login(mcp_user)
        response = client.get(self._authorize_url())
        # Legitimate downstream outcomes when the gate passes: 302 (DOT
        # mints code + redirects to loopback) or 400 (oauthlib rejects a
        # query-string detail the test happened to omit, e.g. `state`).
        # 5xx and 401 are NOT legitimate — they indicate a regression
        # elsewhere in the stack. The gate's pass-through is what's being
        # asserted; DOT's downstream parsing is its own concern.
        assert response.status_code in {HTTPStatus.FOUND, HTTPStatus.BAD_REQUEST}, (
            f"Gate may have rejected a fully-qualified user, or stack broke: "
            f"status={response.status_code}, body={response.content[:200]!r}"
        )


@pytest.mark.django_db
class TestPKCEEnforcedEndToEnd:
    """S256-only, mandatory PKCE through real HTTP: `/o/authorize/` GET, the
    consent POST, and `/o/token/`, for a dynamically-registered client (which
    always shows the consent screen)."""

    @pytest.mark.parametrize("method", ["plain", None], ids=["plain", "omitted"])
    def test_non_s256_is_refused_on_the_consent_get_and_post(
        self, client, mcp_user, mcp_mfa_on, method
    ):
        client_id = _register_dcr_client(client)
        client.force_login(mcp_user)
        params = _authorize_params(client_id, secrets.token_urlsafe(48), method)

        # GET: refused before the consent page renders.
        get = client.get(reverse("authorize") + "?" + urlencode(params))
        assert _redirect_query(get)["error"] == ["invalid_request"]

        # POST: the consent form re-runs oauthlib's request validation, so a
        # crafted POST approving a `plain` challenge is refused the same way.
        post = client.post(reverse("authorize"), data={**params, "allow": "Authorize"})
        query = _redirect_query(post)
        assert query["error"] == ["invalid_request"]
        assert "code" not in query
        assert not Grant.objects.exists()

    def test_pkce_is_required_even_if_the_consumer_disables_it(
        self, client, mcp_user, mcp_mfa_on, settings
    ):
        settings.OAUTH2_PROVIDER = {**settings.OAUTH2_PROVIDER, "PKCE_REQUIRED": False}
        client_id = _register_dcr_client(client)
        client.force_login(mcp_user)
        params = _authorize_params(client_id, None, None)
        post = client.post(reverse("authorize"), data={**params, "allow": "Authorize"})
        query = _redirect_query(post)
        assert query["error"] == ["invalid_request"]
        assert "code" not in query
        assert not Grant.objects.exists()

    def test_s256_flow_completes_without_a_refresh_token(
        self, client, mcp_user, mcp_mfa_on
    ):
        client_id = _register_dcr_client(client)
        client.force_login(mcp_user)
        verifier, challenge = _s256_pair()
        params = _authorize_params(client_id, challenge, "S256")

        get = client.get(reverse("authorize") + "?" + urlencode(params))
        assert get.status_code == HTTPStatus.OK, get.content  # consent page
        post = client.post(reverse("authorize"), data={**params, "allow": "Authorize"})
        code = _redirect_query(post)["code"][0]
        token = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _LOOPBACK,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == HTTPStatus.OK, token.content
        body = token.json()
        assert body["scope"] == "mcp:sql"
        assert "refresh_token" not in body
        assert AccessToken.objects.filter(token=body["access_token"]).exists()
        assert not RefreshToken.objects.exists()

    def test_a_pre_fix_plain_grant_cannot_be_exchanged(self, client, mcp_user, mcp_app):
        # What <= 0.1.0b5 stored for a `plain` authorization — explicit, or an
        # omitted method that oauthlib defaulted to `plain`: the challenge IS
        # the verifier. The token-time backstop refuses it.
        from datetime import timedelta

        from django.utils import timezone

        verifier = secrets.token_urlsafe(48)
        code = secrets.token_urlsafe(32)
        Grant.objects.create(
            user=mcp_user,
            code=code,
            application=mcp_app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri="http://127.0.0.1:9999",
            scope="mcp:sql",
            code_challenge=verifier,
            code_challenge_method="plain",
        )
        response = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:9999",
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_grant"
        assert not AccessToken.objects.exists()


@pytest.mark.django_db
class TestRefreshRefused:
    """`ACCESS_TOKEN_EXPIRE_SECONDS` is the re-consent interval: no refresh
    token is minted, and a refresh token minted by an earlier release (DOT
    honoured those indefinitely under `REFRESH_TOKEN_EXPIRE_SECONDS=0`) is
    refused: `MCPServer` has no refresh grant, so `/o/token/` answers
    `unsupported_grant_type`. (`MCPOAuth2Validator.validate_refresh_token`
    is the backstop for DOT's stock server.)"""

    def _exchange_code(self, client, client_id) -> dict:
        verifier, challenge = _s256_pair()
        params = _authorize_params(client_id, challenge, "S256")
        post = client.post(reverse("authorize"), data={**params, "allow": "Authorize"})
        code = _redirect_query(post)["code"][0]
        token = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _LOOPBACK,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == HTTPStatus.OK, token.content
        return token.json()

    def test_a_pre_fix_refresh_token_is_refused(self, client, mcp_user, mcp_mfa_on):
        client_id = _register_dcr_client(client)
        client.force_login(mcp_user)
        body = self._exchange_code(client, client_id)
        assert "refresh_token" not in body
        # What <= 0.1.0b5 also stored with every access token: a live
        # RefreshToken row bound to it, as DOT's `save_bearer_token` writes it.
        access = AccessToken.objects.get(token=body["access_token"])
        legacy = RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=access.application,
            access_token=access,
        )

        response = client.post(
            reverse("token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": legacy.token,
                "client_id": client_id,
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "unsupported_grant_type"
        # No new access token; the original one is untouched.
        assert list(AccessToken.objects.values_list("token", flat=True)) == [
            body["access_token"]
        ]

    def test_dcr_still_accepts_a_client_asking_for_refresh(self, client):
        # Anthropic's MCP SDK registers with `refresh_token` in grant_types;
        # registration must still succeed and echo only what is supported.
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {
                    "redirect_uris": [_LOOPBACK],
                    "grant_types": ["authorization_code", "refresh_token"],
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED, response.content
        assert response.json()["grant_types"] == ["authorization_code"]

    def test_metadata_advertises_no_refresh_grant(self, client):
        metadata = client.get(reverse("oauth_authorization_server_metadata")).json()
        assert metadata["grant_types_supported"] == ["authorization_code"]
        assert metadata["code_challenge_methods_supported"] == ["S256"]


class TestMCPAuthorizationViewConsentTemplate:
    """The consent page is rendered from a package-owned template and surfaces
    the configured `RESOURCE_NAME` rather than DOT's opaque per-client
    `application.name` (every dynamically-registered client is named
    `mcp-sql-<token>`). Package-internal behaviour — no project-layout coupling.
    """

    def test_template_name_is_package_owned(self):
        assert MCPAuthorizationView.template_name == "mcp_sql/authorize.html"

    def test_render_to_response_injects_resource_name(self, monkeypatch):
        from mcp_sql.conf import mcp_sql_settings
        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response({"application": object()})
        assert captured["resource_name"] == mcp_sql_settings.RESOURCE_NAME

    def test_render_to_response_does_not_clobber_preset_resource_name(
        self, monkeypatch
    ):
        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response({"resource_name": "preset"})
        assert captured["resource_name"] == "preset"


class TestOauthAdminUnregistered:
    """DOT ModelAdmin classes must not be reachable via Django admin.

    `mcp_sql/admin.py` unregisters them so superusers cannot mint
    rogue Applications or rewrite the `mcp-sql` Application's
    redirect_uris through the admin UI. See `admin.py` for the rationale.
    """

    def test_dot_models_not_in_admin_registry(self):
        from django.contrib import admin
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application
        from oauth2_provider.models import Grant
        from oauth2_provider.models import IDToken
        from oauth2_provider.models import RefreshToken

        for model_cls in (
            Application,
            AccessToken,
            Grant,
            RefreshToken,
            IDToken,
        ):
            assert model_cls not in admin.site._registry, (
                f"{model_cls.__name__} is registered on the admin — the "
                f"`mcp_sql/admin.py` unregister did not fire."
            )
