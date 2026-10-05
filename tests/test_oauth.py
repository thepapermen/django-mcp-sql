"""Tests for the OAuth validator and the issuance-gate AuthorizationView."""

from http import HTTPStatus
from unittest.mock import MagicMock

import pytest
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import resolve_url
from django.urls import reverse
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP
from mcp_sql.views.oauth_authorize import MCPAuthorizationView


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


class TestMCPOAuth2ValidatorCodeChallengeMethod:
    """`validate_code_challenge_method` is pinned to `S256` only.

    oauthlib's default also accepts `plain`, but plain PKCE collapses to no
    PKCE under verifier leak. The Authorization Server Metadata advertises
    `S256` only; the validator enforces what the metadata promises.
    """

    def test_accepts_s256(self):
        v = MCPOAuth2Validator()
        assert v.validate_code_challenge_method(MagicMock(), "S256") is True

    def test_rejects_plain(self):
        v = MCPOAuth2Validator()
        assert v.validate_code_challenge_method(MagicMock(), "plain") is False

    def test_rejects_unknown_method(self):
        v = MCPOAuth2Validator()
        assert v.validate_code_challenge_method(MagicMock(), "S512") is False
        assert v.validate_code_challenge_method(MagicMock(), "") is False


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
        # `REFRESH_TOKEN_EXPIRE_SECONDS=0` does NOT prevent DOT from issuing
        # a refresh_token field — it just sets its lifetime to 0 seconds.
        # The refresh token is structurally present but immediately expired
        # and so cannot be used to refresh. Effectively-no-refresh-tokens,
        # not literally-no-refresh-tokens.
        assert "refresh_token" in body  # DOT 3.2.0 still mints them; expiry is 0s.

        # Verify the DB row matches what the response describes — defends
        # against a DOT regression that mis-binds the token's user/app/scope.
        from oauth2_provider.models import AccessToken

        token_row = AccessToken.objects.get(token=body["access_token"])
        assert token_row.user_id == mcp_user.pk
        assert token_row.application_id == mcp_app.pk
        assert token_row.scope == "mcp:sql"
        assert token_row.expires > timezone.now()

    def test_plain_pkce_is_rejected_at_authorize(self, client, mcp_user, mcp_mfa_on):
        """`code_challenge_method=plain` at /o/authorize/ must be refused.

        Integration counterpart to the unit test in
        `TestMCPOAuth2ValidatorCodeChallengeMethod`: proves the override is
        actually consulted by oauthlib during the live authorize flow.
        oauthlib only calls `validate_code_challenge_method` here (the
        method comes in as a query-string parameter); the /o/token/
        exchange verifies the verifier against the stored method without
        re-validating the method itself. So /o/authorize/ is where the
        defense fires, and where a regression would surface.
        """
        client.force_login(mcp_user)
        # Same shape as the happy-path AUTHORIZE_QS in
        # TestMCPAuthorizationViewLiveGate, but `code_challenge_method=plain`.
        url = reverse("authorize") + (
            "?client_id=mcp-sql"
            "&response_type=code"
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999"
            "&code_challenge=any-value-since-the-method-is-rejected-first"
            "&code_challenge_method=plain"
        )
        response = client.get(url)
        # oauthlib's standard rejection on a PKCE-method validator returning
        # False is a 302 redirect back to the client with
        # `?error=invalid_request` (the OAuth error-response shape). A 200
        # / 400 would still prove the validator didn't approve — but the 302
        # is the path oauthlib actually takes. We accept anything other than
        # the happy 302-to-loopback-with-?code= and 5xx.
        assert response.status_code != HTTPStatus.OK, response.content
        if response.status_code == HTTPStatus.FOUND:
            # The error must surface as a redirect with an error param —
            # NOT as a redirect with a code (which would mean the validator
            # approved plain).
            location = response["Location"]
            assert "code=" not in location, (
                f"Plain PKCE was approved — Grant minted: {location}"
            )

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

    def test_code_issued_before_logout_cannot_be_exchanged_after(
        self, client, mcp_user, mcp_mfa_on, django_capture_on_commit_callbacks
    ):
        import base64
        import hashlib
        import secrets
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        from oauth2_provider.models import AccessToken

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
        code = parse_qs(location.query)["code"][0]

        with django_capture_on_commit_callbacks(execute=True):
            client.logout()

        exchange = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.CALLBACK,
                "client_id": self.CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert exchange.status_code == HTTPStatus.BAD_REQUEST, exchange.content
        assert exchange.json()["error"] == "invalid_grant"
        assert not AccessToken.objects.filter(user=mcp_user).exists()


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
