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
    """The validator's PKCE backstops: `is_pkce_required` forces PKCE on and
    `get_code_challenge_method` (token) refuses a stored non-S256 grant. The
    S256-only method check at /o/authorize/ is `MCPServer`'s grant.
    End-to-end behaviour: `TestPKCEEnforcedEndToEnd`.
    """

    def test_pkce_is_required(self):
        assert MCPOAuth2Validator().is_pkce_required("c", MagicMock()) is True

    def test_pkce_stays_required_when_the_consumer_disables_it(self, settings):
        settings.OAUTH2_PROVIDER = {**settings.OAUTH2_PROVIDER, "PKCE_REQUIRED": False}
        assert MCPOAuth2Validator().is_pkce_required("c", MagicMock()) is True

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


class TestMCPOAuth2ValidatorGrantBackstops:
    """No refresh grant and no password grant, even on DOT's stock server.
    End-to-end: `TestRefreshRefused` and
    `test_oauth_server.py::TestValidatorBackstopsOnStockViews`."""

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

    def test_refuses_a_password_without_checking_it(self, monkeypatch):
        checked: list = []
        # DOT's own `validate_user` calls the `authenticate` it imported.
        monkeypatch.setattr(
            "oauth2_provider.oauth2_validators.authenticate",
            lambda *_a, **k: checked.append(k),
        )
        assert (
            MCPOAuth2Validator().validate_user("u", "p", MagicMock(), MagicMock())
            is False
        )
        assert checked == []


@pytest.mark.django_db
class TestMCPAuthorizationViewGate:
    """`_enforce_gate` is the issuance gate — exhaustive negative coverage."""

    def test_happy_path_returns_none(self, mcp_user, mcp_mfa_on):
        assert MCPAuthorizationView._enforce_gate(mcp_user) is None

    def test_inactive_user_denied(self, mcp_user, mcp_mfa_on):
        mcp_user.is_active = False
        mcp_user.save()
        with pytest.raises(PermissionDenied, match="active account"):
            MCPAuthorizationView._enforce_gate(mcp_user)

    def test_non_staff_user_passes(self, mcp_user, mcp_mfa_on):
        # No staff requirement: the explicit profile assignment is the gate.
        mcp_user.is_staff = False
        mcp_user.save()
        assert MCPAuthorizationView._enforce_gate(mcp_user) is None

    def test_non_staff_user_without_profile_denied(self, mcp_user, mcp_mfa_on):
        mcp_user.is_staff = False
        mcp_user.save()
        mcp_user.user_permissions.clear()
        mcp_user.groups.clear()
        user = type(mcp_user).objects.get(pk=mcp_user.pk)  # drop the perm cache
        with pytest.raises(PermissionDenied, match="profile assignment"):
            MCPAuthorizationView._enforce_gate(user)

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
        # No refresh token: `MCPServer`'s grant never generates one, so
        # neither the response field nor a `RefreshToken` row exists
        # (`REFRESH_TOKEN_EXPIRE_SECONDS=0` alone would NOT have stopped one
        # from working — see TestRefreshRefused).
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

        Against the canonical row (the fixture creates it, so the client is
        known and the check is not vacuous): oauthlib checks the method on the
        GET, before the consent page. The refusal is oauthlib's normal error
        redirect to the (already validated) loopback URI — `invalid_request`,
        no code, no Grant.
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

    def test_non_staff_user_with_profile_is_not_forbidden(
        self, client, mcp_user, mcp_mfa_on
    ):
        mcp_user.is_staff = False
        mcp_user.save()
        client.force_login(mcp_user)
        response = client.get(self._authorize_url())
        # Same pass-through contract as `test_user_with_all_gates_passes`,
        # and a 302 must not be a bounce to the login page.
        assert response.status_code in {HTTPStatus.FOUND, HTTPStatus.BAD_REQUEST}, (
            f"status={response.status_code}, body={response.content[:200]!r}"
        )
        assert "login" not in response.get("Location", "")

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
    refused: `/o/token/` answers every refresh grant with a constant
    `invalid_grant`, the error that makes an MCP client re-authorize.
    (`MCPOAuth2Validator.validate_refresh_token` is the backstop for DOT's
    stock server.)"""

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
        assert response.json()["error"] == "invalid_grant"
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
        from types import SimpleNamespace

        from mcp_sql.conf import mcp_sql_settings
        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {"application": SimpleNamespace(name="mcp-sql-" + "a" * 22)}
        )
        assert captured["resource_name"] == mcp_sql_settings.RESOURCE_NAME

    def test_self_registered_client_gets_no_label(self, monkeypatch):
        """A dynamically-registered client's `client_name` is attacker-chosen
        free text, so the consent page must not present a label for it — the
        destination line is its only identifier."""
        from types import SimpleNamespace

        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {
                "application": SimpleNamespace(name="mcp-sql-" + "a" * 22),
                "redirect_uri": "http://127.0.0.1:53682/callback",
            }
        )
        assert captured["client_label"] == ""
        assert captured["client_destination"] == "http://127.0.0.1:53682"

    @pytest.mark.parametrize(
        ("redirect", "expected"),
        [
            # `urlparse().hostname` strips an IPv6 literal's brackets, so
            # re-composing naively rendered `http://::1:8787` — a corrupt
            # address on the one line of this page the user is asked to check.
            # `::1` is an accepted DCR loopback host, so it is reachable.
            ("http://[::1]:8787/callback", "http://[::1]:8787"),
            ("http://[::1]/callback", "http://[::1]"),
            # An explicit `:0` must not vanish into a falsy-port test.
            ("http://localhost:0/callback", "http://localhost:0"),
        ],
    )
    def test_destination_renders_unusual_hosts_faithfully(
        self, monkeypatch, redirect, expected
    ):
        from types import SimpleNamespace

        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {
                "application": SimpleNamespace(name="mcp-sql-" + "a" * 22),
                "redirect_uri": redirect,
            }
        )
        assert captured["client_destination"] == expected

    def test_declared_client_shows_its_operator_authored_label(
        self, settings, monkeypatch
    ):
        from types import SimpleNamespace

        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {
                "application": SimpleNamespace(name="mcp-sql-cloud.claude"),
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            }
        )
        assert captured["client_label"] == "Claude.ai"
        assert captured["client_destination"] == "https://claude.ai"

    def test_template_renders_the_destination_and_escapes_it(self):
        """The rendered page must actually carry the destination — the whole
        point of the screen — and must escape everything it interpolates."""
        from django.template.loader import render_to_string

        html = render_to_string(
            MCPAuthorizationView.template_name,
            {
                "resource_name": "MCP SQL",
                "client_label": "<script>alert(1)</script>",
                "client_destination": "https://claude.ai",
                "scopes_descriptions": ["Read-only SQL"],
                "form": "",
            },
        )
        assert "https://claude.ai" in html
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            pytest.param("http://localhost:notaport/cb", id="malformed-port"),
            pytest.param("not a url at all", id="unparseable"),
            pytest.param("", id="absent"),
        ],
    )
    def test_unusable_redirect_renders_no_destination(self, monkeypatch, redirect_uri):
        """Blank beats a half-rendered address: showing part of an address the
        user cannot act on is worse than showing none."""
        from types import SimpleNamespace

        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {
                "application": SimpleNamespace(name="mcp-sql"),
                "redirect_uri": redirect_uri,
            }
        )
        assert captured["client_destination"] == ""

    def test_destination_never_renders_a_userinfo_component(self, monkeypatch):
        """`https://claude.ai@evil.example/` must not read as "claude.ai"."""
        from types import SimpleNamespace

        from oauth2_provider.views import AuthorizationView

        captured = {}
        monkeypatch.setattr(
            AuthorizationView,
            "render_to_response",
            lambda self, context, **kw: captured.update(context) or "ok",
        )
        MCPAuthorizationView().render_to_response(
            {
                "application": SimpleNamespace(name="mcp-sql"),
                "redirect_uri": "https://claude.ai@evil.example/cb",
            }
        )
        assert captured["client_destination"] == "https://evil.example"

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


@pytest.mark.django_db
class TestApprovalPromptCannotSkipConsent:
    """DOT's `approval_prompt=auto` must not bypass the consent page.

    On "auto" (from the query string, or `REQUEST_APPROVAL_PROMPT`) DOT issues
    a code on a plain GET whenever the user already holds a live token for the
    same Application. A declared client is one Application shared by every
    account at its provider, so that turned a phished link into a silent code
    for an attacker's own connector. `MCPAuthorizationView.dispatch` pins the
    value to "force".
    """

    CALLBACK = "https://claude.ai/api/mcp/auth_callback"

    def _url(self, approval_prompt):
        from urllib.parse import urlencode

        query = {
            "response_type": "code",
            "client_id": "mcp-sql-cloud.claude",
            "redirect_uri": self.CALLBACK,
            "scope": "mcp:sql",
            "state": "attacker-state",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        if approval_prompt is not None:
            query["approval_prompt"] = approval_prompt
        return reverse("authorize") + "?" + urlencode(query)

    @pytest.mark.parametrize(
        ("approval_prompt", "setting"),
        [
            ("auto", "force"),  # the query string overriding DOT's default
            (None, "auto"),  # a consumer who set the global default to auto
            ("force", "auto"),
        ],
    )
    def test_live_token_still_gets_the_consent_page(  # noqa: PLR0913 — four fixtures + two parameters, all load-bearing
        self, client, mcp_user, mcp_mfa_on, settings, approval_prompt, setting
    ):
        import secrets
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "REQUEST_APPROVAL_PROMPT": setting,
        }
        # The shipped `claude` client, provisioned by `post_migrate`.
        app = Application.objects.get(client_id="mcp-sql-cloud.claude")
        assert app.skip_authorization is False
        AccessToken.objects.create(
            user=mcp_user,
            application=app,
            scope="mcp:sql",
            token=secrets.token_urlsafe(24),
            expires=timezone.now() + timedelta(hours=1),
        )
        client.force_login(mcp_user)
        response = client.get(self._url(approval_prompt))
        # Pre-fix, ("auto", "force") was a 302 straight to the callback with
        # `code=...&state=attacker-state` and no page in between.
        assert response.status_code == HTTPStatus.OK
        assert b'id="authorizationForm"' in response.content
        assert "Location" not in response


@pytest.mark.django_db
class TestCuratedClientRequiresConsent:
    """The curated `mcp-sql` client shows the consent page (ledger F08).

    Its registered redirect is `http://127.0.0.1` and DOT accepts any port on
    a loopback IP, so with consent skipped a phished link opened by a
    logged-in, gate-passing user got an immediate 302 with a code to any
    local port the link named. Now the GET renders the page and only the
    CSRF-protected consent POST issues a code.
    """

    PHISHED_REDIRECT = "http://127.0.0.1:31337"

    def _query(self):
        return {
            "client_id": "mcp-sql",
            "redirect_uri": self.PHISHED_REDIRECT,
            "response_type": "code",
            "scope": "mcp:sql",
            "state": "s",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

    def test_get_renders_the_consent_page_and_issues_no_code(
        self, client, mcp_user, mcp_app, gate_posture
    ):
        from urllib.parse import urlencode

        from oauth2_provider.models import Grant

        client.force_login(mcp_user)
        response = client.get(reverse("authorize") + "?" + urlencode(self._query()))
        assert response.status_code == HTTPStatus.OK
        assert b'id="authorizationForm"' in response.content
        assert "Location" not in response
        assert not Grant.objects.exists()

    def test_consent_post_issues_the_code(
        self, client, mcp_user, mcp_app, gate_posture
    ):
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        from oauth2_provider.models import Grant

        client.force_login(mcp_user)
        response = client.post(
            reverse("authorize"), data={**self._query(), "allow": "Authorize"}
        )
        assert response.status_code == HTTPStatus.FOUND
        location = urlparse(response["Location"])
        assert f"{location.scheme}://{location.netloc}" == self.PHISHED_REDIRECT
        assert "code" in parse_qs(location.query)
        assert Grant.objects.filter(application=mcp_app, user=mcp_user).count() == 1


@pytest.mark.django_db
def test_provisioning_never_re_enables_skip_on_the_curated_row(mcp_app):
    """The post_migrate provisioning receivers (profiles, declared clients,
    grants drift) leave the curated row's consent requirement alone."""
    from django.apps import apps
    from mcp_sql import signals

    sender = apps.get_app_config("mcp_sql")
    signals.provision_mcp_profiles(sender=sender)
    signals.provision_mcp_clients(sender=sender)
    mcp_app.refresh_from_db()
    assert mcp_app.skip_authorization is False


class TestCuratedConsentMigration:
    """Migration 0016 flips the curated row (and only it); 0005 creates new
    installs' row with consent required. The suite runs `--nomigrations`, so
    the RunPython functions are called directly against the app registry."""

    @staticmethod
    def _module(name):
        import importlib

        return importlib.import_module(f"mcp_sql.migrations.{name}")

    @pytest.mark.django_db
    def test_forward_requires_consent_and_reverse_restores(self):
        from django.apps import apps
        from oauth2_provider.models import Application

        migration = self._module("0016_curated_application_requires_consent")
        curated = Application.objects.create(
            name="mcp-sql",
            client_id="mcp-sql",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=True,
            redirect_uris="http://127.0.0.1",
        )
        other = Application.objects.create(
            name="unrelated-trusted-app",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=True,
            redirect_uris="https://app.example/cb",
        )
        migration.require_consent(apps, None)
        curated.refresh_from_db()
        other.refresh_from_db()
        assert curated.skip_authorization is False
        assert other.skip_authorization is True  # untouched
        migration.skip_consent(apps, None)
        curated.refresh_from_db()
        assert curated.skip_authorization is True

    @pytest.mark.django_db
    def test_fresh_install_creates_the_row_requiring_consent(self):
        from django.apps import apps
        from oauth2_provider.models import Application

        self._module("0005_create_mcp_sql_application").create_application(apps, None)
        assert Application.objects.get(name="mcp-sql").skip_authorization is False


@pytest.mark.django_db
class TestLogoutKillsPendingCode:
    """Logout must also revoke an authorization code not yet exchanged.

    Logout deletes the user's MCP access tokens, but a code issued just
    before it (a consent approved a moment ago — or a phished approval the
    user is now trying to undo) used to survive and be exchanged afterwards
    for a fresh token that nothing had deleted. Walked end to end: a real
    consent POST at `/o/authorize/` with S256 PKCE, a real logout, then the
    exchange.
    """

    CALLBACK = "https://claude.ai/api/mcp/auth_callback"
    CLIENT_ID = "mcp-sql-cloud.claude"  # the shipped declared client

    def _consent_code(self, client, mcp_user):
        """A real consent POST with S256 PKCE -> (code, verifier)."""
        import base64
        import hashlib
        import secrets
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        client.force_login(mcp_user)
        consent = client.post(
            reverse("authorize"),
            data={
                "client_id": self.CLIENT_ID,
                "redirect_uri": self.CALLBACK,
                "response_type": "code",
                "scope": "mcp:sql",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "allow": "Authorize",
            },
        )
        assert consent.status_code == HTTPStatus.FOUND, consent.content
        location = urlparse(consent["Location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            self.CALLBACK
        )
        return parse_qs(location.query)["code"][0], verifier

    def _exchange(self, client, code, verifier):
        return client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.CALLBACK,
                "client_id": self.CLIENT_ID,
                "code_verifier": verifier,
            },
        )

    def test_code_issued_before_logout_cannot_be_exchanged_after(
        self, client, mcp_user, mcp_mfa_on, django_capture_on_commit_callbacks
    ):
        from oauth2_provider.models import AccessToken

        code, verifier = self._consent_code(client, mcp_user)
        with django_capture_on_commit_callbacks(execute=True):
            client.logout()

        exchange = self._exchange(client, code, verifier)
        assert exchange.status_code == HTTPStatus.BAD_REQUEST, exchange.content
        assert exchange.json()["error"] == "invalid_grant"
        assert not AccessToken.objects.filter(user=mcp_user).exists()

    def test_refresh_token_from_before_logout_yields_no_usable_token(
        self,
        client,
        mcp_user,
        mcp_mfa_on,
        settings,
        django_capture_on_commit_callbacks,
    ):
        """A refresh token from before logout cannot mint a token afterwards.

        By default the package's server issues no refresh token at all
        (`oauth_server.MCPAuthorizationCodeGrant`); with the opt-in refresh
        grant on (`REFRESH_TOKEN_MAX_AGE_SECONDS`), logout deletes the user's
        MCP refresh tokens with the access tokens and pending codes
        (`signals._revoke_and_audit`), and the refresh grant then answers
        `invalid_grant`. (Before the merge with the refresh-token round this
        test pinned DOT's own behaviour for a refresh token left behind;
        with DOT >= 3.4.1 as the floor and the rows deleted that branch is
        gone.)
        """
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import RefreshToken

        settings.MCP_SQL = {**settings.MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": 3600}
        code, verifier = self._consent_code(client, mcp_user)
        refresh_token = self._exchange(client, code, verifier).json()["refresh_token"]
        assert RefreshToken.objects.filter(user=mcp_user).exists()
        with django_capture_on_commit_callbacks(execute=True):
            client.logout()
        # Logout deletes access tokens, refresh tokens and pending codes.
        assert not RefreshToken.objects.filter(user=mcp_user).exists()
        tokens_before = AccessToken.objects.count()

        refreshed = client.post(
            reverse("token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.CLIENT_ID,
            },
        )
        assert refreshed.status_code == HTTPStatus.BAD_REQUEST, refreshed.content
        assert refreshed.json()["error"] == "invalid_grant"
        assert AccessToken.objects.count() == tokens_before


@pytest.mark.django_db
class TestConsentPostErrorsNeverRedirectOffClient:
    """A consent POST's error redirect goes only to a URI the client owns.

    DOT raises Cancel's `access_denied` and an invalid `resource`'s
    `invalid_target` BEFORE oauthlib validates the form's hidden
    `redirect_uri`, and then redirected to whatever that field held. A
    tampered form (it takes a same-origin, CSRF-bearing POST) could send the
    user's browser, with `state`, anywhere. The view now re-validates the
    redirect against the client first and renders the error page when it
    fails. An unknown `client_id` in the POST was a 500 (`DoesNotExist`); it
    renders the same error page.
    """

    CLIENT_ID = "mcp-sql-cloud.claude"  # the shipped declared client
    CALLBACK = "https://claude.ai/api/mcp/auth_callback"
    EVIL = "https://evil.example/steal"

    def _post(self, client, mcp_user, query="", **overrides):
        data = {
            "client_id": self.CLIENT_ID,
            "redirect_uri": self.CALLBACK,
            "response_type": "code",
            "scope": "mcp:sql",
            "state": "s",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        data.update(overrides)
        client.force_login(mcp_user)
        return client.post(reverse("authorize") + query, data=data)

    @staticmethod
    def _assert_error_page(response):
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Location" not in response
        assert b'id="authorizationForm"' not in response.content

    def test_cancel_with_tampered_redirect_renders_error_page(
        self, client, mcp_user, gate_posture
    ):
        response = self._post(client, mcp_user, redirect_uri=self.EVIL)
        self._assert_error_page(response)
        assert b"evil.example" not in response.content

    def test_bad_resource_with_tampered_redirect_renders_error_page(
        self, client, mcp_user, gate_posture
    ):
        # The invalid `resource` raises `invalid_target` before oauthlib has
        # validated the redirect (the package's check in `form_valid`, on
        # every DOT version); the re-validation in `error_response` is what
        # stops it. Error page, no redirect.
        response = self._post(
            client,
            mcp_user,
            redirect_uri=self.EVIL,
            resource="not a uri",
            allow="Authorize",
        )
        self._assert_error_page(response)

    def test_cancel_with_the_registered_redirect_still_redirects(
        self, client, mcp_user, gate_posture
    ):
        response = self._post(client, mcp_user)
        assert response.status_code == HTTPStatus.FOUND
        assert response["Location"].startswith(self.CALLBACK + "?")
        assert "error=access_denied" in response["Location"]

    def test_bad_resource_with_the_registered_redirect_still_redirects(
        self, client, mcp_user, gate_posture
    ):
        response = self._post(client, mcp_user, resource="not a uri", allow="Authorize")
        assert response.status_code == HTTPStatus.FOUND
        assert response["Location"].startswith(self.CALLBACK + "?")
        assert "error=invalid_target" in response["Location"]

    def test_nul_client_id_on_the_get_renders_error_page_not_500(
        self, client, mcp_user, gate_posture
    ):
        """DOT looks the client up (`Application.objects.get`) inside
        `validate_authorization_request`, so a NUL in `client_id` reached
        Postgres and raised `DataError` (a 500) on every retry. The view
        refuses it before DOT runs."""
        from urllib.parse import urlencode

        client.force_login(mcp_user)
        query = urlencode(
            {
                "client_id": "mcp-sql-cloud.claude\x00",
                "redirect_uri": self.CALLBACK,
                "response_type": "code",
                "scope": "mcp:sql",
                "state": "s",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            }
        )
        response = client.get(reverse("authorize") + "?" + query)
        self._assert_error_page(response)

    def test_nul_client_id_on_the_post_renders_error_page(
        self, client, mcp_user, gate_posture
    ):
        # Defence in depth: without `dispatch`'s check this was not a 500 but
        # a 200 re-render (Django's form validation rejects the NUL first);
        # with it, both methods get the same fatal-client error page.
        response = self._post(
            client, mcp_user, client_id="mcp-sql-cloud.claude\x00", allow="Authorize"
        )
        self._assert_error_page(response)

    def test_unknown_client_id_renders_error_page_not_500(
        self, client, mcp_user, gate_posture
    ):
        response = self._post(
            client, mcp_user, client_id="no-such-client", allow="Authorize"
        )
        self._assert_error_page(response)

    MATCHING = "https://testserver/mcp/sql/"

    # Every consent-POST branch, each with the client deleted right after the
    # view's unknown-client check. `foreign`: the package's `invalid_target`
    # path (B11). The rest reach DOT's own `form_valid`, whose
    # `Application.objects.get` raised `DoesNotExist` (a 500) on DOT 3.2 and
    # 3.4 alike: Authorize with a matching `resource`, Authorize with none,
    # Cancel with none, and a matching `resource` only in the query string
    # with no form field (DOT 3.2 has no such field, so it is DOT's path
    # there; from 3.4 the blank field disagrees with the query, the package's
    # path).
    VANISHED_CASES = {
        "foreign": {"resource": "not a uri", "allow": "Authorize"},
        "matching": {"resource": MATCHING, "allow": "Authorize"},
        "none": {"allow": "Authorize"},
        "cancel": {},
        "query_only": {
            "query": "?resource=https%3A%2F%2Ftestserver%2Fmcp%2Fsql%2F",
            "allow": "Authorize",
        },
    }

    @pytest.mark.parametrize("case", list(VANISHED_CASES))
    def test_client_deleted_mid_request_renders_error_page_not_500(
        self, client, mcp_user, gate_posture, monkeypatch, case
    ):
        """A client deleted between the view's unknown-client check and the
        Application lookup after it (an operator removing it while a consent
        POST is in flight) was a `DoesNotExist` 500. Now the same error page
        as an unknown client: no redirect, nothing stored."""
        from mcp_sql.views.oauth_authorize import MCPAuthorizationView
        from oauth2_provider.models import Grant
        from oauth2_provider.models import get_application_model

        known = MCPAuthorizationView._is_known_client_id
        deleted = []

        def known_then_deleted(client_id):
            result = known(client_id)
            if not deleted:
                get_application_model().objects.filter(client_id=client_id).delete()
                deleted.append(client_id)
            return result

        monkeypatch.setattr(
            MCPAuthorizationView,
            "_is_known_client_id",
            staticmethod(known_then_deleted),
        )
        response = self._post(client, mcp_user, **self.VANISHED_CASES[case])
        self._assert_error_page(response)
        assert b"Invalid client_id" in response.content
        assert deleted == [self.CLIENT_ID]
        assert not Grant.objects.exists()

    def test_other_does_not_exist_from_dots_form_valid_is_not_masked(
        self, client, mcp_user, gate_posture, monkeypatch
    ):
        """The error page is only for a client that is really gone: an
        Application `DoesNotExist` from DOT's `form_valid` while the client
        still exists propagates instead of being reported as an unknown
        client."""
        from oauth2_provider.models import get_application_model
        from oauth2_provider.views import AuthorizationView

        application_model = get_application_model()

        def raises(self, form):
            raise application_model.DoesNotExist

        monkeypatch.setattr(AuthorizationView, "form_valid", raises)
        with pytest.raises(application_model.DoesNotExist):
            self._post(client, mcp_user, allow="Authorize")
        assert application_model.objects.filter(client_id=self.CLIENT_ID).exists()


@pytest.mark.django_db
class TestConsentFormInvalidRender:
    """DOT's `form_invalid` re-renders the consent template without
    `application`; `{{ resource_name|default:application.name }}` resolved
    the filter argument anyway and raised `VariableDoesNotExist` (500)."""

    def test_incomplete_consent_post_renders(self, client, mcp_user, mcp_mfa_on):
        client_id = _register_dcr_client(client)
        client.force_login(mcp_user)
        _verifier, challenge = _s256_pair()
        params = _authorize_params(client_id, challenge, "S256")
        del params["scope"]  # a required AllowForm field
        response = client.post(reverse("authorize"), data={**params, "allow": "1"})
        assert response.status_code == HTTPStatus.OK, response.content
        assert b"MCP SQL" in response.content
        assert not Grant.objects.exists()


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
