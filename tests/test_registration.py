"""Tests for the RFC 7591 dynamic client registration endpoint.

Three things are pinned here:

1. Happy path: POST with valid loopback `redirect_uris` creates an
   `Application` row with the curated public-client / PKCE-required
   posture and returns the RFC 7591 §3.2.1 response shape.
2. Validation: malformed JSON, non-loopback redirect URIs, https on
   loopback, whitespace-smuggled / malformed / non-ASCII redirect URIs, and
   unsupported grant/response/auth-method values all return RFC 7591
   §3.2.2 error responses with the right `error` code — never a 500, and
   never a persisted row.
3. End-to-end: a dynamically-registered client can complete the full
   OAuth flow (authorize gate + token exchange) and the resulting bearer
   token satisfies `MCPOAuth2Authentication`. This is the integration
   counterpart to `TestOAuthTokenEndpointHappyPath` (which uses the
   curated `mcp-sql` Application from migration 0005) — without it, a
   regression that broke the prefix-based `Application` recognition in
   `MCPOAuth2Validator` / `MCPOAuth2Authentication` would still pass the
   isolated unit tests.
4. Defense in depth at `/o/authorize/`: a DCR row that ALREADY stores a
   smuggled off-machine redirect (minted before the registration check
   existed), or a canonical row edited to one, cannot be redirected to it —
   `MCPOAuth2Validator` re-applies the loopback predicate to the requested
   URI — while legitimate loopback redirects keep working.
"""

import base64
import hashlib
import json
import secrets
from datetime import timedelta
from http import HTTPStatus
from urllib.parse import urlencode

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


def _registered_applications():
    """`Application` rows `/o/register` minted: every row but the curated one
    and the declared clients `post_migrate` provisions."""
    return Application.objects.exclude(name=mcp_sql_settings.APPLICATION_NAME).exclude(
        client_id__in=list(mcp_sql_settings.clients())
    )


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
        # complete. The curated `mcp-sql` Application requires consent too
        # (migration 0016); see the test below.
        assert app.skip_authorization is False
        assert "http://127.0.0.1:3456/callback" in app.redirect_uris
        # Public client — the registered "secret" is an opaque hash of an
        # empty string (DOT hashes it on save, `hash_client_secret` defaulting
        # to on), not the
        # plain-empty literal. What matters is that the registration
        # response carries no `client_secret` per RFC 7591 §3.2.1 — pinned
        # in `test_returns_201_and_rfc7591_shape`.
        assert "client_secret" not in body

    def test_curated_mcp_sql_application_requires_consent_too(self, mcp_app):
        """No asymmetry: the curated `mcp-sql` Application shows the consent
        page like DCR-minted and declared clients.

        It used to skip consent ("operator-provisioned, friction without
        security"), but its registered redirect is `http://127.0.0.1` and DOT
        accepts any port on a loopback IP, so a phished authorize link sent a
        code silently to any local port. Migration 0016 flips existing rows;
        0005 creates new ones with consent required. The `mcp_app` fixture
        mirrors both (`--nomigrations`); `test_oauth.py::
        TestCuratedClientRequiresConsent` walks the flow end to end.
        """
        assert mcp_app.skip_authorization is False

    def test_stored_redirect_uris_are_exactly_the_submitted_ones(self, client):
        # Pin what DOT will actually match against: it re-splits the stored
        # string with `str.split()`, so the round-trip must give back exactly
        # the submitted list — no extra entry, and nothing off-machine allowed.
        clean = "http://127.0.0.1:3456/cb"
        response = _post(client, {"redirect_uris": [clean]})
        assert response.status_code == HTTPStatus.CREATED, response.content
        app = Application.objects.get(client_id=response.json()["client_id"])
        assert app.redirect_uris.split() == [clean]
        assert app.redirect_uri_allowed(clean) is True
        assert app.redirect_uri_allowed("http://evil.example/steal") is False

    def test_multiple_clean_redirect_uris_round_trip(self, client):
        uris = ["http://127.0.0.1:3456/cb", "http://localhost:3456/cb"]
        response = _post(client, {"redirect_uris": uris})
        assert response.status_code == HTTPStatus.CREATED, response.content
        app = Application.objects.get(client_id=response.json()["client_id"])
        assert app.redirect_uris.split() == uris

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

    @pytest.mark.parametrize(
        "host", ["testserver:443", "TESTSERVER", "TestServer:443", "testserver:0443"]
    )
    def test_registration_client_uri_spells_the_host_canonically(
        self, client, settings, host
    ):
        # A forwarded `Host: <name>:443` or an uppercase name: the 201 names
        # the same canonical origin as discovery and the bearer check
        # (`consts.canonical_authority`), never the raw `get_host()`.
        settings.ALLOWED_HOSTS = ["testserver"]
        body = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": ["http://127.0.0.1:3456/cb"]}),
            content_type="application/json",
            HTTP_HOST=host,
        ).json()
        expected = f"https://testserver{reverse('oauth_dynamic_client_registration')}"
        assert body["registration_client_uri"] == expected
        asm = client.get(
            reverse("oauth_authorization_server_metadata"), HTTP_HOST=host
        ).json()
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

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"redirect_uris": ["http://127.0.0.1:9999"], "client_name": "\xff"}',
            # 20k levels (~40 KB, under the 64 KiB cap): deep enough to raise
            # RecursionError on Python 3.11 through 3.13 (3.12+ tolerates ~3k).
            # Python 3.14's decoder parses it (its recursion guard is
            # stack-based), so there it is an object lacking `redirect_uris`.
            b'{"x": ' + b"[" * 20000 + b"]" * 20000 + b"}",
        ],
        ids=["invalid-utf8", "deeply-nested"],
    )
    def test_undecodable_body_rejected_not_500(self, client, raw):
        # The default `client` re-raises view exceptions, so an uncaught
        # UnicodeDecodeError / RecursionError fails here loudly.
        try:
            json.loads(raw)
        except (ValueError, RecursionError):
            expected = "invalid_client_metadata"
        else:  # Python 3.14+: decodes; refused for its missing redirect_uris
            expected = "invalid_redirect_uri"
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=raw,
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == expected
        assert not _registered_applications().exists()

    def test_recursion_error_while_decoding_is_a_400(self, client, monkeypatch):
        # Pins the `RecursionError` handler on every Python, including 3.14,
        # where no body under the 64 KiB cap is deep enough to reach it.
        from mcp_sql.views import registration

        def too_deep(*_args, **_kwargs):
            raise RecursionError

        with monkeypatch.context() as patched:
            patched.setattr(registration.json, "loads", too_deep)
            response = client.post(
                reverse("oauth_dynamic_client_registration"),
                data=b'{"redirect_uris": ["http://127.0.0.1:9999"]}',
                content_type="application/json",
            )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_client_metadata"
        assert not _registered_applications().exists()

    @pytest.mark.parametrize(
        "metadata",
        [
            {"grant_types": None},
            {"grant_types": 5},
            {"grant_types": "authorization_code"},  # substring-matched before
            {"grant_types": ["authorization_code", 5]},
            {"grant_types": {"authorization_code": True}},
            {"response_types": None},
            {"response_types": 5},
            {"response_types": "code"},
            {"response_types": ["code", None]},
        ],
        ids=[
            "grant-null",
            "grant-number",
            "grant-string",
            "grant-non-string-member",
            "grant-object",
            "response-null",
            "response-number",
            "response-string",
            "response-non-string-member",
        ],
    )
    def test_malformed_grant_or_response_types_rejected(self, client, metadata):
        response = _post(
            client, {"redirect_uris": ["http://127.0.0.1:9999"], **metadata}
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_client_metadata"
        assert not _registered_applications().exists()

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
        # attacker-chosen and would be stored verbatim. Reject the user:pass
        # form, the username-only form, and an EMPTY userinfo (which parses to
        # a falsy username, so only a raw `@` test catches it).
        for uri in (
            "http://attacker:secret@127.0.0.1:3456/cb",
            "http://attacker@127.0.0.1:3456/cb",
            "http://@127.0.0.1:3456/cb",
            "http://:@127.0.0.1:3456/cb",
        ):
            response = _post(client, {"redirect_uris": [uri]})
            assert response.status_code == HTTPStatus.BAD_REQUEST, uri
            assert response.json()["error"] == "invalid_redirect_uri"

    @pytest.mark.parametrize(
        "separator",
        [
            " ",
            "\t",
            "\n",
            "\r",
            "\x0b",  # vertical tab
            "\x0c",  # form feed
            "\x1c",  # file separator
            "\x85",  # next line (NEL)
            "\xa0",  # no-break space
            "\u2028",  # line separator
            "\u3000",  # ideographic space
        ],
        ids=["space", "tab", "lf", "cr", "vt", "ff", "fs", "nel", "nbsp", "ls", "ideo"],
    )
    def test_whitespace_smuggled_redirect_rejected(self, client, separator):
        # DOT stores an Application's redirect URIs as one whitespace-joined
        # string and matches with `str.split()`. A single submitted URI with
        # embedded `str.split()` whitespace would register a SECOND, off-machine
        # redirect, while `urlparse` still reports the loopback host. ASCII
        # space is the only separator here that the printable-ASCII rule would
        # let through, so it is the case that pins the split check; the others
        # are refused by both checks (the charset rule is pinned on its own by
        # `test_non_printable_or_non_ascii_rejected`).
        smuggled = f"http://127.0.0.1:3456/cb{separator}http://evil.example/steal"
        # Guard the parameter itself: each case must be a real smuggle under
        # DOT's parsing, or this test would pass without exercising the hole.
        assert smuggled.split() == [
            "http://127.0.0.1:3456/cb",
            "http://evil.example/steal",
        ]
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [smuggled]})
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

    def test_smuggled_uri_anywhere_in_list_refuses_whole_request(self, client):
        # All-or-nothing: one bad entry refuses the registration outright,
        # rather than registering the clean entries and dropping the bad one.
        before = Application.objects.count()
        response = _post(
            client,
            {
                "redirect_uris": [
                    "http://127.0.0.1:3456/cb",
                    "http://127.0.0.1:3456/cb2 http://evil.example/steal",
                ]
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

    @pytest.mark.parametrize(
        "uri",
        [
            # ASCII-only, so these reach `urlparse` and pin its ValueError path.
            "http://[::1/cb",  # unterminated IPv6 literal: `urlparse` raises
            "http://::1]/cb",  # stray closing bracket: `urlparse` raises
        ],
    )
    def test_malformed_authority_rejected_not_500(self, client, uri):
        # The default `client` re-raises view exceptions, so a regression to
        # an uncaught ValueError fails here loudly rather than as a status.
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

    @pytest.mark.parametrize(
        "uri",
        [
            "http://localhost:abc/cb",
            "http://localhost:99999/cb",
            "http://127.0.0.1:-1/cb",
        ],
    )
    def test_unparseable_port_rejected(self, client, uri):
        # Previously stored as-is; DOT's `.port` access then raised at
        # `/o/authorize/`. Refused at registration so it never reaches DOT.
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

    @pytest.mark.parametrize(
        "uri",
        [
            "http://127.0.0.1:3456/cb\x00",  # NUL: PostgreSQL refuses it on INSERT
            "\x01http://127.0.0.1:3456/cb",  # leading C0: `urlsplit` strips it
            "http://127.0.0.1:3456/cb\x7f",  # DEL
            "http://127.0.0.1:3456/cb\ud800",  # lone surrogate: not encodable
            "http://127.0.0.1:3456/caf\u00e9",  # non-ASCII: not an RFC 3986 URI
            # A netloc character that becomes `#` under NFKC; `urlparse` would
            # raise on it, but the non-ASCII rule refuses it first.
            "http://localhost\uff03@evil.example/cb",
        ],
        ids=["nul", "leading-c0", "del", "lone-surrogate", "non-ascii", "nfkc-netloc"],
    )
    def test_non_printable_or_non_ascii_rejected(self, client, uri):
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

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
class TestAuthorizeLoopbackRecheck:
    """A DCR row minted before the registration check existed may already
    store a smuggled off-machine redirect. `MCPOAuth2Validator` re-applies the
    loopback predicate to the requested URI at `/o/authorize/` for every
    client that is not a declared cloud client, so such an entry can never
    receive a code even if the operator never finds and deletes the row. Its
    loopback entries, and the canonical row's port-wildcarded loopback
    redirect, keep working."""

    LOOPBACK = "http://127.0.0.1:3456/cb"
    EVIL = "http://evil.example/steal"

    @pytest.fixture
    def legacy_app(self, db):
        # Exactly what a <= 0.1.0b5 `/o/register` stored for a single submitted
        # `LOOPBACK + " " + EVIL` URI: DOT reads it back as TWO redirects.
        client_id = (
            f"{mcp_sql_settings.APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(16)}"
        )
        app = Application.objects.create(
            name=client_id,
            client_id=client_id,
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=False,
            redirect_uris=f"{self.LOOPBACK} {self.EVIL}",
            algorithm="",
        )
        # Precondition: DOT's own matching WOULD allow the off-machine URI.
        assert app.redirect_uri_allowed(self.EVIL) is True
        return app

    def _params(self, app, redirect_uri) -> dict:
        return {
            "client_id": app.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "mcp:sql",
            "state": "xyz",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

    def test_consent_screen_refused_for_smuggled_redirect(
        self, client, mcp_user, mcp_mfa_on, legacy_app
    ):
        client.force_login(mcp_user)
        response = client.get(
            reverse("authorize") + "?" + urlencode(self._params(legacy_app, self.EVIL))
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response

    def test_consent_approval_never_redirects_off_machine(
        self, client, mcp_user, mcp_mfa_on, legacy_app
    ):
        client.force_login(mcp_user)
        response = client.post(
            reverse("authorize"),
            data={**self._params(legacy_app, self.EVIL), "allow": "Authorize"},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response
        assert not Grant.objects.filter(application=legacy_app).exists()

    def test_loopback_redirect_on_the_same_row_still_works(
        self, client, mcp_user, mcp_mfa_on, legacy_app
    ):
        # Positive control: the guard refuses the off-machine entry, not the row.
        client.force_login(mcp_user)
        response = client.post(
            reverse("authorize"),
            data={**self._params(legacy_app, self.LOOPBACK), "allow": "Authorize"},
        )
        assert response.status_code == HTTPStatus.FOUND, response.content
        assert response["Location"].startswith(self.LOOPBACK + "?")
        assert Grant.objects.filter(application=legacy_app).exists()

    def test_legacy_unparseable_port_row_is_a_400_not_a_500(
        self, client, mcp_user, mcp_mfa_on
    ):
        # A <= 0.1.0b5 row could store a garbage port. DOT parses a stored
        # `localhost` candidate's port (only loopback IPs are port-wildcarded)
        # while matching a request for a DIFFERENT, valid loopback URI — a
        # ValueError that must surface as the normal refusal, not a 500.
        client_id = (
            f"{mcp_sql_settings.APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(16)}"
        )
        app = Application.objects.create(
            name=client_id,
            client_id=client_id,
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=False,
            redirect_uris="http://localhost:99999/cb",
            algorithm="",
        )
        client.force_login(mcp_user)
        response = client.get(
            reverse("authorize")
            + "?"
            + urlencode(self._params(app, "http://localhost:3456/cb"))
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response

    def test_legacy_unparseable_port_on_a_loopback_ip_still_matches_loopback(
        self, client, mcp_user, mcp_mfa_on
    ):
        # The other side of the test above: DOT port-wildcards loopback IPs, so
        # it never reads the garbage port of a stored `127.0.0.1` candidate and
        # a request for a valid port on the same path is authorized. Harmless —
        # the destination stays on the loopback — and pinned so the CHANGELOG's
        # description of it stays true.
        client_id = (
            f"{mcp_sql_settings.APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(16)}"
        )
        app = Application.objects.create(
            name=client_id,
            client_id=client_id,
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=False,
            redirect_uris="http://127.0.0.1:99999/cb",
            algorithm="",
        )
        client.force_login(mcp_user)
        params = self._params(app, "http://127.0.0.1:3456/cb")
        response = client.post(
            reverse("authorize"), data={**params, "allow": "Authorize"}
        )
        assert response.status_code == HTTPStatus.FOUND, response.content
        assert response["Location"].startswith("http://127.0.0.1:3456/cb?")
        assert "code=" in response["Location"]

    @pytest.mark.parametrize("send_redirect_uri", [True, False])
    def test_canonical_row_edited_off_machine_is_refused(
        self, client, mcp_user, mcp_mfa_on, mcp_app, send_redirect_uri
    ):
        # A stored off-machine redirect would be a code delivery off the
        # machine (a silent one while the canonical row skipped consent).
        # Explicit `redirect_uri`: refused by `validate_redirect_uri`. Omitted:
        # oauthlib resolves the stored default
        # WITHOUT calling `validate_redirect_uri`, and `get_default_redirect_uri`
        # drops it, so oauthlib fails fatally. (DOT would also re-validate the
        # default when creating the response, but only on this success path —
        # the error paths are pinned by the test below.) Pin both.
        mcp_app.redirect_uris = "https://evil.example/cb"
        mcp_app.save()
        params = self._params(mcp_app, "https://evil.example/cb")
        if not send_redirect_uri:
            del params["redirect_uri"]
        client.force_login(mcp_user)
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response
        assert not Grant.objects.filter(application=mcp_app).exists()

    @pytest.mark.parametrize(
        "broken",
        [{"response_type": None}, {"scope": "not-a-scope"}],
        ids=["no-response-type", "bad-scope"],
    )
    def test_off_machine_stored_default_gets_no_error_redirect(
        self, client, mcp_user, mcp_mfa_on, mcp_app, broken
    ):
        # With `redirect_uri` omitted, oauthlib resolves the stored default
        # without calling `validate_redirect_uri`, and a later NON-fatal error
        # is 302'd to that default — off-machine, though carrying no code.
        # `get_default_redirect_uri` drops a non-loopback default for a
        # non-cloud client, so oauthlib fails fatally instead: no redirect.
        mcp_app.redirect_uris = "https://evil.example/cb"
        mcp_app.save()
        params = self._params(mcp_app, "unused")
        del params["redirect_uri"]
        for key, value in broken.items():
            if value is None:
                del params[key]
            else:
                params[key] = value
        client.force_login(mcp_user)
        response = client.get(reverse("authorize") + "?" + urlencode(params))
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert "Location" not in response

    def test_canonical_loopback_port_wildcard_still_redirects(
        self, client, mcp_user, mcp_mfa_on, mcp_app
    ):
        # Positive control for the canonical row: it stores bare
        # `http://127.0.0.1` and DOT port-wildcards loopback IPs, so a request
        # for an ephemeral port must still pass the re-check and 302 with a code.
        # The canonical row requires consent (migration 0016): the GET shows
        # the consent page (the re-check passed) and the consent POST 302s.
        client.force_login(mcp_user)
        params = self._params(mcp_app, "http://127.0.0.1:9999")
        page = client.get(reverse("authorize") + "?" + urlencode(params))
        assert page.status_code == HTTPStatus.OK, page.content
        assert b'id="authorizationForm"' in page.content
        response = client.post(reverse("authorize"), {**params, "allow": "Authorize"})
        assert response.status_code == HTTPStatus.FOUND, response.content
        assert response["Location"].startswith("http://127.0.0.1:9999?")
        assert "code=" in response["Location"]

    def test_canonical_loopback_default_still_used_when_omitted(
        self, client, mcp_user, mcp_mfa_on, mcp_app
    ):
        # Positive control for `get_default_redirect_uri`: a loopback stored
        # default must still be used when the request omits `redirect_uri`.
        # The canonical row requires consent (migration 0016): the consent page
        # carries the stored default as its `redirect_uri`, and posting it
        # back issues the code there.
        params = self._params(mcp_app, "unused")
        del params["redirect_uri"]
        client.force_login(mcp_user)
        page = client.get(reverse("authorize") + "?" + urlencode(params))
        assert page.status_code == HTTPStatus.OK, page.content
        assert b'name="redirect_uri" value="http://127.0.0.1"' in page.content
        response = client.post(
            reverse("authorize"),
            {**params, "redirect_uri": "http://127.0.0.1", "allow": "Authorize"},
        )
        assert response.status_code == HTTPStatus.FOUND, response.content
        assert response["Location"].startswith("http://127.0.0.1?")
        assert "code=" in response["Location"]


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

    def test_a_null_entry_refuses_the_request(self, client):
        # A non-string member is a malformed request, not an unsupported URI:
        # it is refused rather than dropped (`TestNonStringRedirectUriMembers`).
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {"redirect_uris": [None, "http://localhost:8787/callback"]}
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"

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
        # A smuggling attempt beside a clean sibling refuses the whole request
        # (`_requested_uris_error`): nothing is registered.
        before = Application.objects.count()
        smuggled = "http://127.0.0.1:8765/cb http://evil.example/steal"
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps(
                {"redirect_uris": ["http://localhost:8787/callback", smuggled]}
            ),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"
        assert Application.objects.count() == before

    def test_dot_cannot_be_talked_into_the_off_machine_redirect(
        self, client, monkeypatch
    ):
        """End-to-end: the guarantee, asserted on the STORED row through DOT's
        own matcher.

        The whole-request whitespace refusal (`_requested_uris_error`) is
        switched off here, so the smuggling attempt beside a clean sibling
        reaches the subset filter, which is what registers a row at all.
        Under the old, whitespace-unaware predicate the smuggled string passed
        the host check and was stored verbatim, so the row's
        `redirect_uris.split()` yielded the off-machine URI and DOT admitted
        it; the loopback predicate alone keeps it out.
        """
        from mcp_sql.views import registration
        from oauth2_provider.models import Application

        original = registration._requested_uris_error

        def without_whitespace_refusal(uris):
            error = original(uris)
            if error is not None and b"without whitespace" in error.content:
                return None
            return error

        monkeypatch.setattr(
            registration, "_requested_uris_error", without_whitespace_refusal
        )
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
    "redirect_uris must not contain control, separator, surrogate, format or "
    "other invisible characters"
)
_NAME_REFUSAL = (
    "client_name must be a string of at most 200 characters of assigned, "
    "visible text (no control, separator, private-use or stray invisible "
    "characters)"
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
    - Invisible, blank, unassigned and private-use characters, and line /
      paragraph separators: storable, but in a callback stored on the
      Application (copied into every audit row's `client_redirect`) or in a
      logged client name they let a registrant make the text read as
      something else. The rule is documented once, in the comment heading
      the character section of `views/registration.py`: a redirect URI must
      be printable and visible; a name may use invisible characters only
      inside well-formed sequences (joiners in words and emoji ZWJ
      sequences, Unicode's emoji variation sequences, Mongolian variation
      selectors, the combining grapheme joiner before a mark, subdivision
      flags).

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
            chr(0x2800),  # braille pattern blank
            chr(0xFDD0),  # noncharacter
            chr(0xE000),  # private use
            chr(0x00A0),  # no-break space
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
            chr(0x034F),  # combining grapheme joiner (Mn, invisible)
            chr(0x180B),  # Mongolian free variation selector (Mn)
            chr(0xFE0F),  # VS16 after an ASCII letter: no visible effect
            chr(0x200C),  # ZWNJ between ASCII letters
            chr(0x200D),  # ZWJ between ASCII letters
            chr(0xE0067),  # a tag character outside a flag sequence
            chr(0x1D173),  # musical symbol begin beam (Cf, invisible)
            chr(0x1BCA0),  # shorthand format letter overlap (Cf)
            chr(0xFFF9),  # interlinear annotation anchor
            chr(0x1161),  # Hangul vowel jamo with no leading consonant
            chr(0x17B4),  # Khmer inherent vowel (deprecated, invisible)
            chr(0x2800),  # braille pattern blank
            chr(0xFDD0),  # noncharacter
            chr(0x2FFFE),  # noncharacter (plane 2)
            chr(0xE000),  # private use
            chr(0x0378),  # unassigned
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
            # Heart on fire: VS16 then ZWJ.
            "\u2764" + chr(0xFE0F) + chr(0x200D) + "\U0001f525",
            # Woman technologist, medium skin tone.
            "\U0001f469\U0001f3fd" + chr(0x200D) + "\U0001f4bb",
            # Keycap one.
            "Room 1" + chr(0xFE0F) + "\u20e3",
            # Decomposed (NFD) Korean "han": conjoining jamo in sequence.
            "\u1112\u1161\u11ab",
            # Emoji variation sequences on non-symbol bases.
            "Swap \u2194" + chr(0xFE0F),  # left-right arrow (Sm)
            "Wow\u203c" + chr(0xFE0F),  # double exclamation (Po)
            "\u2139" + chr(0xFE0F) + " Info",  # information source (Ll)
            "\u3030" + chr(0xFE0F),  # wavy dash (Pd)
            # Mongolian with a free variation selector.
            "\u1820" + chr(0x180B) + "\u1821",
            # Combining grapheme joiner before a combining mark.
            "a\u00e9" + chr(0x034F) + "\u0301",
            # Arabic number sign: a visible format character.
            "\u0600\u0661\u0662",
            # Combining accents (decomposed e-acute).
            "Cafe\u0301",
        ],
        ids=[
            "accents-emoji",
            "zwnj",
            "zwj-emoji",
            "flag-tags",
            "variation-sel",
            "heart-on-fire",
            "skin-tone-zwj",
            "keycap",
            "nfd-korean",
            "vs16-arrow",
            "vs16-exclamation",
            "vs16-info",
            "vs16-wavy-dash",
            "mongolian-fvs",
            "cgj-before-mark",
            "arabic-number-sign",
            "combining-accent",
        ],
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

    @pytest.mark.parametrize(
        "name",
        [
            "Star \u2605" + chr(0xFE0F),  # VS16 on a base with no variation sequence
            "\u845b" + chr(0xE0100),  # ideographic variation selector
            "X\U0001f3f4" + chr(0xE0020) + chr(0xE007F),  # tag space, not a flag
            "\U0001f3f4" + chr(0xE0067) + chr(0xE0062) + chr(0xE007F),  # region only
            "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbsct"),  # no cancel
            "Trusted" + chr(0x034F) + "Client",  # CGJ not before a mark
            "\u1780" + chr(0x17B4),  # deprecated Khmer inherent vowel
        ],
        ids=[
            "undefined-vs16",
            "ivs",
            "tag-space-flag",
            "region-only-flag",
            "unterminated-flag",
            "cgj-in-word",
            "khmer-inherent-vowel",
        ],
    )
    def test_invisible_outside_a_well_formed_sequence_is_refused(self, client, name):
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/callback"], "client_name": name},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error_description"] == _NAME_REFUSAL

    def test_ordinary_non_ascii_uri_is_not_refused_as_invisible(self, client):
        # Not one of the whole-request character refusals: it is judged per
        # URI, and the loopback predicate takes printable ASCII only (RFC 3986
        # URIs; `_is_loopback_redirect`), so it is not registered.
        uri = "http://localhost:8787/callbäck"
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"
        assert response.json()["error_description"] != _URI_REFUSAL
        assert (
            "none of the requested redirect_uris"
            in (response.json()["error_description"])
        )
        response = _post(
            client, {"redirect_uris": [uri, "http://localhost:8787/callback"]}
        )
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == ["http://localhost:8787/callback"]

    @pytest.mark.parametrize(
        "char",
        [
            chr(0x200C),
            chr(0x200D),
            chr(0xE0067),
            chr(0x034F),
            chr(0xFE0F),
            chr(0x180B),
            chr(0x1161),
            chr(0x1100),
            chr(0x3164),
            chr(0xFFA0),
            chr(0x0600),  # Arabic number sign: Cf, visible, still no place in a URI
        ],
    )
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
    invalid under NFKC normalisation, a port that is not a valid number) is
    never registered: it drops out of the loopback subset like any other URI
    we do not support. Alone, that leaves nothing to register (400); beside a
    clean loopback URI, the clean one is registered and echoed (201).

    In 0.1.0b5 the bracketed-host and NFKC kinds made `urlparse` raise inside
    the loopback filter (an anonymous 500 before the per-IP `register`
    counter), and a loopback URI with a bad port, whose port the filter never
    read, was registered verbatim.
    """

    @pytest.mark.parametrize("uri", _MALFORMED_URIS)
    def test_alone_is_a_400(self, client, uri):
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": [uri]})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_redirect_uri"
        assert response.json()["error_description"].startswith(
            "none of the requested redirect_uris is a valid loopback URI"
        )
        assert Application.objects.count() == before

    @pytest.mark.parametrize("uri", _MALFORMED_URIS)
    def test_beside_a_clean_uri_drops_out(self, client, uri):
        clean = "http://localhost:8787/callback"
        response = _post(client, {"redirect_uris": [clean, uri]})
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["redirect_uris"] == [clean]
        app = Application.objects.get(client_id=response.json()["client_id"])
        assert app.redirect_uris == clean


@pytest.mark.django_db
class TestNonStringRedirectUriMembers:
    """Every `redirect_uris` member must be a string, as with `grant_types`;
    a non-string member was silently dropped (or, alone, reported as "not a
    loopback URI")."""

    @pytest.mark.parametrize(
        "uris",
        [[5], [None], [{"uri": "x"}], [5, "http://localhost:8787/callback"]],
        ids=["int", "null", "object", "beside-clean"],
    )
    def test_refused(self, client, uris):
        before = Application.objects.count()
        response = _post(client, {"redirect_uris": uris})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json() == {
            "error": "invalid_redirect_uri",
            "error_description": (
                "redirect_uris must be a non-empty array of URI strings"
            ),
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


@pytest.mark.django_db
class TestClientNameType:
    """`client_name` is optional free text. Absent, `null` or empty gets the
    default name; any other non-string is a 400. A falsy non-string (`0`,
    `false`, `[]`) used to be replaced by the default silently while a truthy
    one (`1`, `["x"]`) was refused."""

    @pytest.mark.parametrize(
        "value", ["absent", None, ""], ids=["absent", "null", "empty"]
    )
    def test_defaulted(self, client, value):
        body = {"redirect_uris": ["http://localhost:8787/callback"]}
        if value != "absent":
            body["client_name"] = value
        response = _post(client, body)
        assert response.status_code == HTTPStatus.CREATED
        assert response.json()["client_name"] == "Unnamed MCP client"

    @pytest.mark.parametrize(
        "value",
        [0, False, [], {}, 1, True, 1.5, ["x"], {"name": "x"}],
        ids=[
            "zero",
            "false",
            "empty-list",
            "empty-object",
            "one",
            "true",
            "float",
            "list",
            "object",
        ],
    )
    def test_non_string_is_a_400(self, client, value):
        before = Application.objects.count()
        response = _post(
            client,
            {"redirect_uris": ["http://localhost:8787/callback"], "client_name": value},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_client_metadata"
        assert Application.objects.count() == before
