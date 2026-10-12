"""Tests for the RFC 7591 dynamic client registration endpoint.

Three things are pinned here:

1. Happy path: POST with valid loopback `redirect_uris` creates an
   `Application` row with the curated public-client / PKCE-required
   posture and returns the RFC 7591 §3.2.1 response shape.
2. Validation: malformed JSON, non-loopback redirect URIs, https on
   loopback, and unsupported grant/response/auth-method values all return
   RFC 7591 §3.2.2 error responses with the right `error` code.
3. End-to-end: a dynamically-registered client can complete the full
   OAuth flow (authorize gate + token exchange) and the resulting bearer
   token satisfies `MCPOAuth2Authentication`. This is the integration
   counterpart to `TestOAuthTokenEndpointHappyPath` (which uses the
   curated `mcp-sql` Application from migration 0005) — without it, a
   regression that broke the prefix-based `Application` recognition in
   `MCPOAuth2Validator` / `MCPOAuth2Authentication` would still pass the
   isolated unit tests.
"""

import base64
import hashlib
import json
import secrets
from datetime import timedelta
from http import HTTPStatus

import pytest
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from mcp_sql.auth import MCPOAuth2Authentication
from mcp_sql.conf import mcp_sql_settings
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Application
from oauth2_provider.models import Grant
from rest_framework.test import APIClient
from rest_framework.test import APIRequestFactory


def _post(client, body) -> object:
    """Wrap the JSON POST so individual tests stay focused on the assertions."""
    return client.post(
        reverse("oauth_dynamic_client_registration"),
        data=json.dumps(body),
        content_type="application/json",
    )


@pytest.mark.django_db
class TestDynamicClientRegistrationHappyPath:
    """RFC 7591 §3.2.1 response shape and side-effects."""

    def test_returns_201_and_rfc7591_shape(self, client):
        response = _post(
            client,
            {
                "redirect_uris": ["http://127.0.0.1:3456/callback"],
                "client_name": "Claude Code Test",
            },
        )
        assert response.status_code == HTTPStatus.CREATED, response.content
        body = response.json()
        # PREFIX already carries a trailing dash, so no extra separator is needed.
        assert body["client_id"].startswith(mcp_sql_settings.APPLICATION_NAME_PREFIX)
        assert isinstance(body["client_id_issued_at"], int)
        assert body["client_name"] == "Claude Code Test"
        assert body["redirect_uris"] == ["http://127.0.0.1:3456/callback"]
        assert body["grant_types"] == ["authorization_code"]
        assert body["response_types"] == ["code"]
        assert body["token_endpoint_auth_method"] == "none"

    def test_application_row_has_curated_defaults(self, client):
        response = _post(
            client,
            {"redirect_uris": ["http://127.0.0.1:3456/callback"]},
        )
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        # The Application must carry the MCP-purpose prefix so
        # `MCPOAuth2Validator.validate_client_id` and
        # `MCPOAuth2Authentication.authenticate` recognise it.
        assert app.name.startswith(mcp_sql_settings.APPLICATION_NAME_PREFIX)
        assert app.client_type == Application.CLIENT_PUBLIC
        assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
        # Dynamically-registered clients MUST show the consent screen at
        # `/o/authorize/`. Silent code issuance lets an attacker who
        # registers a rogue client phish a logged-in MCP-cohort victim
        # with a fully-formed authorize link and capture the auth code
        # at the (loopback) `redirect_uri` they registered. The consent
        # screen forces a CSRF-protected POST that a phished GET cannot
        # complete. The curated migration-0005 `mcp-sql` Application
        # keeps `skip_authorization=True` because it is operator-
        # provisioned; see the test below for that invariant.
        assert app.skip_authorization is False
        assert "http://127.0.0.1:3456/callback" in app.redirect_uris
        # Public client — the registered "secret" is an opaque hash of an
        # empty string (DOT 3.2 calls `make_password` on save), not the
        # plain-empty literal. What matters is that the registration
        # response carries no `client_secret` per RFC 7591 §3.2.1 — pinned
        # in `test_returns_201_and_rfc7591_shape`.
        assert "client_secret" not in body

    def test_curated_mcp_sql_application_still_skips_consent(self, mcp_app):
        """Pin the asymmetry: only DCR-minted clients require consent.

        Migration 0005's `mcp-sql` Application is operator-provisioned (its
        redirect_uri is hardcoded in the migration, no attacker can mint a
        rogue copy through `/o/register`). Showing a consent screen on the
        operator-installed client would be friction without security. Pinning
        the asymmetry here so a future "let's make this consistent" refactor
        does not silently break the operator install path.

        Uses the `mcp_app` fixture (defined in conftest.py) because
        `make test` runs with `--nomigrations` and the actual migration
        does not execute — the fixture mirrors the migration's intent.
        """
        assert mcp_app.skip_authorization is True

    def test_omitted_client_name_gets_placeholder(self, client):
        response = _post(client, {"redirect_uris": ["http://127.0.0.1:9999"]})
        assert response.json()["client_name"] == "Unnamed MCP client"

    def test_ipv6_loopback_accepted(self, client):
        response = _post(client, {"redirect_uris": ["http://[::1]:9999/cb"]})
        assert response.status_code == HTTPStatus.CREATED, response.content

    def test_each_post_creates_a_distinct_application(self, client):
        a = _post(client, {"redirect_uris": ["http://127.0.0.1:1111"]}).json()
        b = _post(client, {"redirect_uris": ["http://127.0.0.1:2222"]}).json()
        assert a["client_id"] != b["client_id"]


@pytest.mark.django_db
class TestDynamicClientRegistrationValidation:
    """RFC 7591 §3.2.2 error responses."""

    def test_malformed_json_rejected(self, client):
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data="not-json",
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_non_object_body_rejected(self, client):
        response = _post(client, ["just", "a", "list"])
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_missing_redirect_uris_rejected(self, client):
        response = _post(client, {"client_name": "no-uri"})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_empty_redirect_uris_list_rejected(self, client):
        response = _post(client, {"redirect_uris": []})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_non_loopback_host_rejected(self, client):
        response = _post(client, {"redirect_uris": ["http://attacker.example.com/cb"]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_localhost_accepted_for_industry_compatibility(self, client):
        # RFC 8252 §7.3 says "SHOULD NOT" localhost — but Anthropic's MCP SDK,
        # Google's native-app OAuth, GitHub's, etc. all use http://localhost.
        # We accept it to stay interoperable; the stored URI is exact-matched
        # at /o/authorize/ and /o/token/, so accepting `localhost` here does
        # not loosen the matching anywhere downstream.
        response = _post(client, {"redirect_uris": ["http://localhost:3456/cb"]})
        assert response.status_code == HTTPStatus.CREATED, response.content

    def test_https_loopback_rejected(self, client):
        # RFC 8252 §7.3: native-app loopback URIs use http — no CA issues
        # certs for 127.0.0.1.
        response = _post(client, {"redirect_uris": ["https://127.0.0.1:3456/cb"]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_loopback_with_userinfo_rejected(self, client):
        # `http://user:pass@127.0.0.1/cb` has a loopback host, so a bare
        # hostname check would accept it — but the userinfo component is
        # attacker-chosen and would be stored verbatim. Reject both the
        # user:pass form and the username-only form.
        for uri in (
            "http://attacker:secret@127.0.0.1:3456/cb",
            "http://attacker@127.0.0.1:3456/cb",
        ):
            response = _post(client, {"redirect_uris": [uri]})
            assert response.status_code == HTTPStatus.BAD_REQUEST, uri
            assert response.json()["error"] == "invalid_redirect_uri"

    def test_grant_types_missing_authorization_code_rejected(self, client):
        response = _post(
            client,
            {
                "redirect_uris": ["http://127.0.0.1:9999"],
                "grant_types": ["client_credentials"],
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_response_types_missing_code_rejected(self, client):
        response = _post(
            client,
            {
                "redirect_uris": ["http://127.0.0.1:9999"],
                "response_types": ["token"],
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_grant_types_with_refresh_token_accepted(self, client):
        # Anthropic's MCP SDK sends `["authorization_code", "refresh_token"]`.
        # RFC 7591 §3.2.1 lets the server register a subset; we accept the
        # request as long as `authorization_code` is in it and echo back
        # only what we actually support.
        response = _post(
            client,
            {
                "redirect_uris": ["http://127.0.0.1:9999"],
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
        assert response.status_code == HTTPStatus.CREATED, response.content
        # Honest response: only authorization_code is what we registered.
        assert response.json()["grant_types"] == ["authorization_code"]

    def test_unsupported_token_endpoint_auth_method_rejected(self, client):
        response = _post(
            client,
            {
                "redirect_uris": ["http://127.0.0.1:9999"],
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"


@pytest.mark.django_db
class TestDynamicClientRegistrationMethodRejection:
    """`@require_POST` should refuse anything other than POST."""

    def test_get_returns_405(self):
        api_client = APIClient()
        response = api_client.get(reverse("oauth_dynamic_client_registration"))
        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED

    def test_put_returns_405(self):
        api_client = APIClient()
        response = api_client.put(reverse("oauth_dynamic_client_registration"))
        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED

    def test_delete_returns_405(self):
        api_client = APIClient()
        response = api_client.delete(reverse("oauth_dynamic_client_registration"))
        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED


@pytest.mark.django_db
class TestRegisteredClientCompletesOAuthFlow:
    """A dynamically-registered client must work end-to-end.

    Pins that the prefix-based Application recognition in
    `MCPOAuth2Validator` / `MCPOAuth2Authentication` actually accepts
    dynamically-registered clients alongside the curated `mcp-sql` one.
    """

    def test_registered_client_token_satisfies_mcp_auth_class(
        self, client, mcp_user, mcp_mfa_on, mcp_active_session
    ):
        # Step 1: register a fresh client via /o/register.
        register_response = _post(
            client,
            {"redirect_uris": ["http://127.0.0.1:8765/cb"]},
        )
        assert register_response.status_code == HTTPStatus.CREATED
        client_id = register_response.json()["client_id"]
        app = Application.objects.get(client_id=client_id)

        # Step 2: simulate an authorize → token PKCE exchange with the
        # registered client. We pre-mint the Grant (the gate is already
        # exercised in `TestMCPAuthorizationViewLiveGate`) to focus on
        # the validator-accepts-registered-client property.
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        code = secrets.token_urlsafe(32)
        Grant.objects.create(
            user=mcp_user,
            code=code,
            application=app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri="http://127.0.0.1:8765/cb",
            scope="mcp:sql",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        token_response = client.post(
            reverse("token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:8765/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        assert token_response.status_code == HTTPStatus.OK, token_response.content
        access_token = token_response.json()["access_token"]

        # Step 3: the bearer satisfies MCPOAuth2Authentication. The
        # auth class uses `startswith(mcp_sql_settings.APPLICATION_NAME_PREFIX)`, so
        # this dynamically-registered client must be accepted.
        bearer_request = APIRequestFactory().post(
            "/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        user, token = MCPOAuth2Authentication().authenticate(bearer_request)
        assert user.pk == mcp_user.pk
        assert token.application_id == app.pk

    def test_registered_client_appears_in_logout_revocation(
        self, client, mcp_user, mcp_app, mcp_mfa_on, django_capture_on_commit_callbacks
    ):
        # Mint a token under a dynamically-registered Application, then
        # invoke the logout signal directly. The signal uses
        # `application__name__startswith` so the dynamic client's token
        # MUST be deleted alongside the curated `mcp-sql` Application's.
        from django.contrib.auth.signals import user_logged_out

        register_response = _post(
            client,
            {"redirect_uris": ["http://127.0.0.1:8765/cb"]},
        )
        dynamic_app = Application.objects.get(
            client_id=register_response.json()["client_id"]
        )

        # One token from the curated Application + one from the dynamic.
        for application in (mcp_app, dynamic_app):
            AccessToken.objects.create(
                user=mcp_user,
                token="tok_" + secrets.token_urlsafe(16),
                application=application,
                expires=timezone.now() + timedelta(hours=1),
                scope="mcp:sql",
            )

        # `django-axes`'s `user_logged_out` receiver reads `request.axes_ip_address`;
        # a bare None raises AttributeError. Match the posture from
        # `tests/test_signals.py::_logout_request`. Revocation now runs in
        # `transaction.on_commit`, so capture+execute the deferred callback.
        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(mcp_user),
                request=RequestFactory().get("/logout/"),
                user=mcp_user,
            )

        # Both tokens revoked — neither is left in the table.
        assert (
            AccessToken.objects.filter(user=mcp_user, application=mcp_app).count() == 0
        )
        assert (
            AccessToken.objects.filter(user=mcp_user, application=dynamic_app).count()
            == 0
        )


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestRegistrationSilentBlock:
    """Per-IP registration spam is blocked silently: a normal-looking 201
    with NO `Application` row persisted, byte-shape-indistinguishable from a
    real success so an attacker can neither pace under the threshold nor
    fingerprint the block. Shares the bad-token throttle's threshold/window
    knobs under a `register` scope key."""

    def test_successful_registration_increments_register_counter(self, client):
        from django.core.cache import cache

        _post(client, {"redirect_uris": ["http://127.0.0.1:3456/cb"]})
        assert cache.get("mcp_sql:register:ip:127.0.0.1") == 1

    def test_blocked_ip_gets_inert_201_without_creating_a_row(self, client, settings):
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 2}
        cache.set("mcp_sql:register:ip:127.0.0.1", 2, timeout=3600)

        before = Application.objects.count()
        response = _post(
            client,
            {"redirect_uris": ["http://127.0.0.1:9999/cb"], "client_name": "blocked"},
        )

        assert response.status_code == HTTPStatus.CREATED
        body = response.json()
        # Identical shape to a real registration response...
        assert set(body) == {
            "client_id",
            "client_id_issued_at",
            "client_name",
            "redirect_uris",
            "grant_types",
            "response_types",
            "token_endpoint_auth_method",
            "registration_client_uri",
        }
        assert body["client_id"].startswith(mcp_sql_settings.APPLICATION_NAME_PREFIX)
        # ...but no row was persisted and the inert client_id resolves to nothing.
        assert Application.objects.count() == before
        assert not Application.objects.filter(client_id=body["client_id"]).exists()

    def test_blocked_ip_does_not_advance_the_counter(self, client, settings):
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 1}
        cache.set("mcp_sql:register:ip:127.0.0.1", 5, timeout=3600)
        _post(client, {"redirect_uris": ["http://127.0.0.1:9999/cb"]})
        # Frozen: blocked requests short-circuit before record_attempt.
        assert cache.get("mcp_sql:register:ip:127.0.0.1") == 5
