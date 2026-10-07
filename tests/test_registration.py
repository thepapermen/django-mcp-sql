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

    @pytest.mark.parametrize(("debug", "scheme"), [(True, "http"), (False, "https")])
    def test_registration_client_uri_shares_the_discovery_origin(
        self, client, settings, debug, scheme
    ):
        # Composed through `consts.absolute_url` like every discovery URL, so
        # with DEBUG off it is https even when the request reached Django over
        # plain http (a TLS terminator that does not forward the scheme) — the
        # same origin the AS metadata advertises `registration_endpoint` on.
        settings.DEBUG = debug
        body = _post(client, {"redirect_uris": ["http://127.0.0.1:3456/cb"]}).json()
        expected = (
            f"{scheme}://testserver{reverse('oauth_dynamic_client_registration')}"
        )
        assert body["registration_client_uri"] == expected
        asm = client.get(reverse("oauth_authorization_server_metadata")).json()
        assert asm["registration_endpoint"] == expected


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

    def test_non_loopback_uris_are_filtered_not_fatal(self, client, db):
        # RFC 7591 §3.2.1: register the subset we support and echo what was
        # registered. Real clients present more than they will use — Cursor's
        # IDE sends its loopback callback alongside a hosted https one and a
        # `cursor://` deeplink — and refusing the whole request would lock them
        # out of DCR entirely.
        from oauth2_provider.models import Application

        response = _post(
            client,
            {
                "redirect_uris": [
                    "http://localhost:8787/callback",
                    "https://www.cursor.com/agents/mcp/oauth/callback",
                    "cursor://anysphere.cursor-mcp/oauth/callback",
                ]
            },
        )
        assert response.status_code == HTTPStatus.CREATED, response.content
        body = response.json()
        assert body["redirect_uris"] == ["http://localhost:8787/callback"]
        # And nothing non-loopback reached the stored Application.
        app = Application.objects.get(client_id=body["client_id"])
        assert app.redirect_uris == "http://localhost:8787/callback"

    def test_all_non_loopback_uris_still_rejected(self, client):
        # Filtering must not become "accept anything": an empty subset is a
        # refusal, exactly as before.
        response = _post(
            client,
            {
                "redirect_uris": [
                    "https://www.cursor.com/agents/mcp/oauth/callback",
                    "cursor://anysphere.cursor-mcp/oauth/callback",
                ]
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_duplicate_loopback_uris_are_collapsed(self, client, db):
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/cb", "http://localhost:8787/cb"]},
        )
        assert response.status_code == HTTPStatus.CREATED, response.content
        assert response.json()["redirect_uris"] == ["http://localhost:8787/cb"]

    def test_non_string_client_name_rejected(self, client):
        # It is echoed in the 201 and written to the registration log line, so
        # it must be a bounded string before it reaches either.
        response = _post(
            client,
            {
                "redirect_uris": ["http://localhost:8787/cb"],
                "client_name": {"nested": "object"},
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_absurdly_long_client_name_rejected(self, client):
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/cb"], "client_name": "A" * 5000},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    def test_absurd_redirect_uri_count_rejected(self, client):
        # Whatever survives the filter is stored verbatim on the Application,
        # so an anonymous caller must not be able to persist an unbounded
        # string.
        response = _post(
            client,
            {"redirect_uris": [f"http://localhost:{9000 + i}/cb" for i in range(11)]},
        )
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


@pytest.mark.django_db
class TestRedirectUriLengthBound:
    """`_MAX_REDIRECT_URIS` bounds the COUNT; this bounds each one's LENGTH.

    `Application.redirect_uris` is an unbounded `TextField`, so ten 6 KB URIs
    still persisted ~60 KB from a single anonymous request inside the 64 KiB
    body cap — which is what the count cap's comment claimed to prevent.
    """

    def test_over_long_loopback_uri_drops_out_of_the_subset(self, client):
        # Bounded, but by dropping it from the subset — the request as a whole
        # is only refused when NOTHING loopback survives, same as any other
        # unusable URI.
        long_uri = "http://127.0.0.1:8765/" + "a" * 1100
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": [long_uri]}),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_over_long_loopback_uri_does_not_sink_a_usable_sibling(self, client):
        long_uri = "http://127.0.0.1:8765/" + "a" * 1100
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {"redirect_uris": ["http://localhost:8787/callback", long_uri]}
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == ["http://localhost:8787/callback"]

    def test_long_discarded_hosted_callback_does_not_fail_the_registration(
        self, client
    ):
        """The regression this bound nearly introduced.

        Cursor Desktop presents its loopback callback alongside a hosted
        `https://…` one and the legacy `cursor://` deeplink (observed live:
        "registered 1 of 3"). The hosted URL can carry a long `state` query.
        Bounding length across the WHOLE request — rather than across the
        subset actually stored — turned that into a 400 and locked Cursor out
        of DCR entirely, which is the all-or-nothing behaviour the subset
        filter exists to replace.
        """
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {
                    "client_name": "Cursor",
                    "redirect_uris": [
                        "http://localhost:8787/callback",
                        "https://www.cursor.com/agents/mcp/oauth/callback?state="
                        + "s" * 1100,
                        "cursor://anysphere.cursor-mcp/oauth/callback",
                    ],
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == ["http://localhost:8787/callback"]

    def test_a_null_entry_is_filtered_not_fatal(self, client):
        # `null` in the array is discarded like any other non-loopback entry.
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {"redirect_uris": [None, "http://localhost:8787/callback"]}
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == ["http://localhost:8787/callback"]

    @pytest.mark.parametrize(
        ("length", "status"),
        [(1024, HTTPStatus.CREATED), (1025, HTTPStatus.BAD_REQUEST)],
    )
    def test_the_bound_is_1024_characters_inclusive(self, client, length, status):
        prefix = "http://127.0.0.1:8765/"
        uri = prefix + "a" * (length - len(prefix))
        assert len(uri) == length
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": [uri]}),
            content_type="application/json",
        )
        assert response.status_code == status
        if status == HTTPStatus.CREATED:
            assert response.json()["redirect_uris"] == [uri]

    def test_normal_length_redirect_uri_still_registers(self, client):
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": ["http://127.0.0.1:8765/callback"]}),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED


@pytest.mark.django_db
class TestWhitespaceSmuggling:
    """A registered redirect URI must be exactly ONE URI.

    `Application.redirect_uris` stores the list as `" ".join(...)` and DOT
    matches with `redirect_uris.split()`, so a single submitted string carrying
    whitespace used to become TWO registered URIs — `urlparse` reports the
    loopback hostname, the string is stored verbatim, and DOT then exact-matches
    the smuggled off-machine URI as a valid redirect for the client. That
    delivers the authorization code off the victim's machine, which is exactly
    what loopback-only registration exists to make impossible. PKCE is no help:
    the attacker registered the client and holds the verifier.

    Predates the multi-client work (identical predicate and join on `main`);
    found by the 0.2.0b1 security review.
    """

    @pytest.mark.parametrize("gap", [" ", "\t", "\n", "\r", "\x0c", "\x0b"])
    def test_smuggled_second_uri_is_refused(self, client, gap):
        smuggled = f"http://127.0.0.1:8765/cb{gap}http://evil.example/steal"
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": [smuggled]}),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_smuggled_uri_does_not_ride_along_with_a_clean_one(self, client):
        # The clean sibling registers; the smuggling attempt drops out of the
        # subset rather than being stored beside it.
        smuggled = "http://127.0.0.1:8765/cb http://evil.example/steal"
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {"redirect_uris": ["http://localhost:8787/callback", smuggled]}
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == ["http://localhost:8787/callback"]

    def test_dot_cannot_be_talked_into_the_off_machine_redirect(self, client):
        """End-to-end: the guarantee, asserted on the STORED row through DOT's
        own matcher.

        Submits the smuggling attempt beside a clean sibling, because that is
        the shape that registers a row at all (the subset filter refuses a
        request with nothing usable in it). Under the old, whitespace-unaware
        predicate the smuggled string passed the host check and was stored
        verbatim, so the row's `redirect_uris.split()` yielded the off-machine
        URI and DOT admitted it.
        """
        from oauth2_provider.models import Application

        clean = "http://localhost:8787/callback"
        smuggled = "http://127.0.0.1:8765/cb http://evil.example/steal"
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": [clean, smuggled]}),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.CREATED
        app = Application.objects.get(client_id=response.json()["client_id"])
        # Every stored URI is a single token, so `.split()` cannot manufacture
        # one we never validated.
        assert app.redirect_uris.split() == [clean]
        assert app.redirect_uri_allowed(clean)
        assert not app.redirect_uri_allowed("http://evil.example/steal")


_URI_REFUSAL = (
    "redirect_uris must not contain control, format, separator or surrogate characters"
)
_NAME_REFUSAL = (
    "client_name must be a string of at most 200 characters, without control, "
    "separator, surrogate, bidirectional-control or invisible characters"
)


@pytest.mark.django_db
class TestUnacceptableCharactersAreA400:
    """No character the database, the encoder or a reader would mishandle is
    stored or echoed: such a request is a whole-request 400.

    - Control characters (Unicode `Cc`: C0, DEL, C1). A NUL inside a loopback
      `redirect_uri` passed the loopback filter, reached
      `Application.objects.create`, and Postgres refused it (`DataError`): an
      anonymous 500 on every retry, before the per-IP `register` counter.
    - Lone surrogates (`Cs`, a legal JSON escape such as `\\ud800`): the
      driver cannot encode them as UTF-8 (`UnicodeEncodeError`), the same 500.
    - Format characters (`Cf`: bidi overrides, zero-width space, BOM, ...)
      and line / paragraph separators (`Zl`, `Zp`): storable, but in a
      callback stored on the Application (copied into every audit row's
      `client_redirect`) or in a logged client name they let a registrant
      make the text read as something else. A redirect URI refuses every
      `Cf`; a client name only the display-altering ones (joiners, tags and
      variation selectors are ordinary text there).

    Refused even beside a clean URI, and the error description is asserted so
    that a regression to "drop it from the loopback subset" (which answers a
    different 400 for a lone URI) cannot pass.
    """

    @pytest.mark.parametrize(
        "char",
        [
            "\x00",  # NUL (Cc)
            "\x01",  # C0
            "\x1b",  # ESC
            "\x7f",  # DEL
            "\x85",  # C1 NEL
            chr(0xD800),  # lone high surrogate (Cs)
            chr(0xDFFF),  # lone low surrogate (Cs)
            "\u202e",  # right-to-left override (Cf)
            "\u200b",  # zero-width space (Cf)
            "\ufeff",  # BOM / zero-width no-break space (Cf)
            "\u2028",  # line separator (Zl)
            "\u2029",  # paragraph separator (Zp)
        ],
    )
    @pytest.mark.parametrize(
        "uris",
        [
            ["http://127.0.0.1:8761/cb{c}"],
            ["http://localhost:8787/callback", "http://127.0.0.1:8761/c{c}b"],
            ["http://localhost:8787/callback", "https://cursor.com/cb{c}"],
        ],
    )
    def test_redirect_uri(self, client, char, uris):
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [u.format(c=char) for u in uris]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json() == {
            "error": "invalid_redirect_uri",
            "error_description": _URI_REFUSAL,
        }
        assert Application.objects.count() == before

    @pytest.mark.parametrize(
        "char",
        [
            "\x00",
            "\n",
            "\x1b",
            chr(0xD800),  # lone surrogate
            chr(0x2028),  # line separator
            chr(0x202E),  # right-to-left override
            chr(0x2066),  # left-to-right isolate
            chr(0x200E),  # left-to-right mark
            chr(0x061C),  # Arabic letter mark
            chr(0x200B),  # zero-width space
            chr(0x2060),  # word joiner
            chr(0xFEFF),  # BOM
            chr(0x00AD),  # soft hyphen (invisible unless at a line break)
            chr(0x3164),  # Hangul filler (renders blank)
        ],
    )
    def test_client_name(self, client, char):
        before = Application.objects.count()
        response = _post(
            client,
            {
                "redirect_uris": ["http://localhost:8787/callback"],
                "client_name": f"Claude{char}Code",
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json() == {
            "error": "invalid_client_metadata",
            "error_description": _NAME_REFUSAL,
        }
        assert Application.objects.count() == before

    @pytest.mark.parametrize(
        "name",
        [
            "Café — Kód ✓ 😀",
            # Persian "I want": the zero-width NON-joiner is part of correct
            # spelling, so it is allowed in a name.
            "\u0645\u06cc" + chr(0x200C) + "\u062e\u0648\u0627\u0647\u0645",
            # Emoji ZWJ sequence (man technologist): the zero-width joiner.
            "Dev \U0001f468" + chr(0x200D) + "\U0001f4bb",
            # Subdivision flag (Scotland): tag characters, format class `Cf`.
            "\U0001f3f4"
            + "".join(chr(0xE0000 + ord(c)) for c in "gbsct")
            + chr(0xE007F),
            # Variation selector (emoji presentation).
            "Heart \u2764" + chr(0xFE0F),
        ],
        ids=["accents-emoji", "zwnj", "zwj-emoji", "flag-tags", "variation-sel"],
    )
    def test_ordinary_non_ascii_name_is_not_refused(self, client, name):
        """Letters, punctuation, emoji and the joiners real scripts and emoji
        sequences need are fine in a name: only characters that make it
        display as something it is not are refused."""
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/callback"], "client_name": name},
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["client_name"] == name

    def test_ordinary_non_ascii_uri_is_not_refused(self, client):
        uri = "http://localhost:8787/callbäck"
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == [uri]

    @pytest.mark.parametrize("char", [chr(0x200C), chr(0x200D), chr(0xE0067)])
    def test_joiners_and_tags_stay_refused_in_a_redirect_uri(self, client, char):
        """Redirect URIs stay strict: every format character, joiners and tag
        characters included, since nothing legitimate in a callback needs one."""
        response = _post(client, {"redirect_uris": [f"http://localhost:8787/c{char}b"]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error_description"] == _URI_REFUSAL


@pytest.mark.django_db
class TestRegistrationNeverAnswers500:
    """`/o/register` is anonymous: no input may raise past the view.

    Each of these used to escape as a 500 (a traceback per request, before
    the per-IP `register` counter): a body that is not UTF-8
    (`UnicodeDecodeError` is not a `JSONDecodeError`), JSON nested past the
    recursion limit, an integer longer than Python's digit limit, and a
    `grant_types` / `response_types` that is not a list (`"x" in None` raises,
    and a string made `in` a substring test).
    """

    def _raw(self, client, raw: bytes):
        return client.post(
            reverse("oauth_dynamic_client_registration"),
            data=raw,
            content_type="application/json",
        )

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"redirect_uris": ["http://127.0.0.1:1/cb\xff\xfe"]}',
            b"\x80\x81\x82",
            b"[" * 60000,
            b'{"redirect_uris": ["http://127.0.0.1:1/cb"], "n": ' + b"1" * 5000 + b"}",
        ],
        ids=["invalid-utf8-in-string", "invalid-utf8", "deep-nesting", "huge-int"],
    )
    def test_unparseable_body(self, client, raw):
        response = self._raw(client, raw)
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"

    @pytest.mark.parametrize("field", ["grant_types", "response_types"])
    @pytest.mark.parametrize(
        "value",
        [
            None,
            1,
            True,
            "authorization_code",
            "code",
            {"authorization_code": 1},
            ["authorization_code", "code", 5],
            ["authorization_code", "code", None],
        ],
        ids=[
            "null",
            "int",
            "bool",
            "string-gt",
            "string-rt",
            "object",
            "list-with-int",
            "list-with-null",
        ],
    )
    def test_types_must_be_a_list(self, client, field, value):
        before = Application.objects.count()
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/callback"], field: value},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json() == {
            "error": "invalid_client_metadata",
            "error_description": f"{field} must be an array of strings",
        }
        assert Application.objects.count() == before


_MALFORMED_URIS = [
    "http://[::1",
    "http://[::1]]/cb",
    "http://[::1]x/cb",
    "http://[zz]/cb",
    "http://[1:2:3]:80/cb",
    "http://[v.foo]/cb",
    "http://[127.0.0.1]/cb",
    "http://[gggg::1]/cb",
    "http://127.0.0.1[/cb",
    f"http://127.0.0.1{chr(0x2100)}/cb",  # NFKC-invalid netloc
    f"http://127.0.0.1{chr(0xFF0F)}evil.example/cb",  # fullwidth solidus
    "http://127.0.0.1:99999/cb",  # port out of range
    "http://127.0.0.1:-1/cb",
    "http://127.0.0.1:abc/cb",
    "https://cursor.com:0x50/cb",
]


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestMalformedRedirectUris:
    """A redirect URI that `urllib` cannot parse (a bad bracketed host, a netloc
    invalid under NFKC normalisation, a port that is not a valid number) is a
    whole-request 400 `invalid_redirect_uri`, alone or beside a clean URI.
    `urlparse` raised `ValueError` inside the loopback filter: an anonymous 500
    before the per-IP `register` counter."""

    @pytest.mark.parametrize("uri", _MALFORMED_URIS)
    @pytest.mark.parametrize("beside_clean", [False, True])
    def test_refused(self, client, uri, beside_clean):
        uris = ["http://localhost:8787/callback", uri] if beside_clean else [uri]
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": uris})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json() == {
            "error": "invalid_redirect_uri",
            "error_description": "redirect_uris must be valid URIs",
        }
        assert Application.objects.count() == before


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestRegistrationFuzz:
    """Seeded fuzz of the anonymous endpoint: no generated redirect URI or
    client name, however malformed, may make it answer anything but a 201 or
    an RFC 7591 400. The test client re-raises any exception, so a 500 path
    fails loudly with its traceback."""

    _PIECES = [
        "http://",
        "https://",
        "HTTP://",
        "http:/",
        "http:\\\\",
        "//",
        "",
        "127.0.0.1",
        "[::1]",
        "[::1",
        "::1]",
        "localhost",
        "LOCALHOST",
        "0x7f.1",
        "2130706433",
        "[::ffff:127.0.0.1]",
        "[fe80::1%25eth0]",
        "evil.example",
        "xn--n3h.example",
        chr(0x131) + ".example",  # dotless i
        ":",
        ":0",
        ":8787",
        ":99999",
        ":-1",
        ":abc",
        ":" + chr(0xFF18),  # fullwidth digit
        "@",
        "user:pw@",
        "%",
        "%00",
        "%zz",
        "%2e%2e",
        "/",
        "\\",
        "/cb",
        "/../",
        "?",
        "?a=b",
        "#",
        "#frag",
        "[",
        "]",
        chr(0x2100),
        chr(0xFF0F),
        chr(0xFF20),
        chr(0x3002),
        "é",
        "\U0001f600",
        " ",
        "\t",
        "\x00",
        chr(0x202E),
        chr(0x200B),
        chr(0xFEFF),
        chr(0xD800),
    ]

    def test_no_generated_input_answers_500(self, client):
        import random

        rng = random.Random(20261007)  # noqa: S311 — reproducible fuzz, not crypto
        for _ in range(400):
            uris = [
                "".join(rng.choice(self._PIECES) for _ in range(rng.randint(1, 6)))
                for _ in range(rng.randint(1, 3))
            ]
            if rng.random() < 0.5:
                uris.append("http://localhost:8787/callback")
            body = {"redirect_uris": uris}
            if rng.random() < 0.3:
                body["client_name"] = "".join(
                    rng.choice(self._PIECES) for _ in range(rng.randint(1, 4))
                )
            response = _post(client, body)
            assert response.status_code in {
                HTTPStatus.CREATED,
                HTTPStatus.BAD_REQUEST,
            }, (
                body,
                response.status_code,
            )
            if response.status_code == HTTPStatus.BAD_REQUEST:
                assert response.json()["error"] in {
                    "invalid_redirect_uri",
                    "invalid_client_metadata",
                }
