"""RFC 8707 `resource`: only this server's MCP endpoint, and tokens bound to
it always work (`audience.py`, ledger F135).

From DOT 3.4 a `resource` is copied onto the grant and the access token, and
DOT audience-checks every bearer that carries one against the request URL.
Before this fix a `resource` naming anything else — another URL, the
endpoint with another scheme / host / path, or the advertised `https`
identifier behind a TLS-terminating proxy whose requests reach Django as
`http` — was accepted at `/o/authorize/` and `/o/token/` and minted a token
`/mcp/sql/` refused with a bare 401 on every call (no audit row, each one
counted toward the bad-token IP throttle).

The suite's test client speaks `http` with `DEBUG` off, so discovery
advertises `https://testserver/mcp/sql/` while every request arrives as
`http`: exactly the proxy-without-`SECURE_PROXY_SSL_HEADER` deployment. The
end-to-end tests therefore fail on DOT 3.4 without the bearer half of the
fix, and the refusal tests fail on every DOT version without the issuance
half.

DOT below 3.4 ignores `resource` (no field on the grant or token); the
package's checks run on every version, so the answers are the same there and
a token is simply unrestricted.
"""

import base64
import hashlib
import json
import secrets
from collections.abc import Sequence
from datetime import timedelta
from http import HTTPStatus
from importlib.metadata import version
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest
from django.urls import reverse
from django.utils import timezone

REDIRECT = "http://127.0.0.1:3456"
SLASHED = "https://testserver/mcp/sql/"
SLASHLESS = "https://testserver/mcp/sql"

FOREIGN = [
    "https://somewhere.example/api",
    "http://testserver/mcp/sql/",  # scheme differs from what discovery says
    "https://testserver/mcp/sql//",
    "https://testserver/mcp/",
    "https://testserver/mcp/sql/tools",
    "https://other.example/mcp/sql/",
    "https://TESTSERVER/mcp/sql/",
    "https://testserver:443/mcp/sql/",
    "https://testserver/mcp/sql/?x=1",
    "https://testserver/mcp/sql/#f",
    "https://user@testserver/mcp/sql/",
    "",
    "not a uri",
    f"{SLASHED} https://somewhere.example/api",
]


def _dot_stores_resource() -> bool:
    """DOT 3.4 added RFC 8707: `resource` on Grant / AccessToken and the
    audience check. Below it the parameter is ignored."""
    dot = tuple(int(p) for p in version("django-oauth-toolkit").split(".")[:2])
    return dot >= (3, 4)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _authorize_params(challenge: str, resources: list[str]) -> list[tuple[str, str]]:
    params = [
        ("client_id", "mcp-sql"),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "mcp:sql"),
        ("state", "st4te"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
    return params + [("resource", value) for value in resources]


def _consent(client, query: str, form_resource: str | None):
    """The consent POST as a browser sends it: back to the page's URL (query
    string included) with the form's fields, `resource` among them from
    DOT 3.4 (blank when the GET carried none)."""
    data = dict(parse_qs(query))
    data = {key: values[-1] for key, values in data.items() if key != "resource"}
    data["allow"] = "Authorize"
    if form_resource is not None:
        data["resource"] = form_resource
    return client.post(reverse("authorize") + "?" + query, data=data)


def _code_from(response) -> str:
    assert response.status_code == HTTPStatus.FOUND, response.content[:300]
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT
    return parse_qs(location.query)["code"][0]


def _exchange(client, code: str, verifier: str, resources: Sequence[str] = ()):
    data = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("client_id", "mcp-sql"),
        ("code_verifier", verifier),
    ] + [("resource", value) for value in resources]
    return client.post(
        reverse("token"),
        data=urlencode(data),
        content_type="application/x-www-form-urlencoded",
    )


def _ping(client, access_token: str, path: str = "/mcp/sql/", **extra):
    return client.post(
        path,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        content_type="application/json",
        HTTP_ACCEPT="application/json, text/event-stream",
        HTTP_AUTHORIZATION=f"Bearer {access_token}",
        **extra,
    )


def _assert_invalid_target_redirect(response, accepted: str = SLASHED) -> None:
    assert response.status_code == HTTPStatus.FOUND, response.content[:300]
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT
    query = parse_qs(location.query)
    assert query["error"] == ["invalid_target"]
    assert query["state"] == ["st4te"]
    assert "code" not in query
    assert accepted in query["error_description"][0]


def _grant_count() -> int:
    from oauth2_provider.models import Grant

    return Grant.objects.count()


@pytest.mark.django_db
class TestMatchingResourceWorksEndToEnd:
    """A `resource` equal to discovery's `resource` (either spelling) gets a
    token that `/mcp/sql/` accepts, over either transport spelling."""

    @pytest.mark.parametrize("metadata_path_slash", [True, False])
    @pytest.mark.parametrize("transport", ["/mcp/sql/", "/mcp/sql"])
    def test_discovered_resource_round_trips(  # noqa: PLR0913 — fixtures + two parametrize axes
        self,
        client,
        mcp_app,
        mcp_user,
        mcp_active_session,
        gate_posture,
        metadata_path_slash,
        transport,
    ):
        metadata_path = reverse("mcp_sql_protected_resource_metadata")
        if metadata_path_slash:
            metadata_path += "/"
        resource = client.get(metadata_path).json()["resource"]
        assert resource == (SLASHED if metadata_path_slash else SLASHLESS)

        verifier, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        page = client.get(reverse("authorize") + "?" + query)
        assert page.status_code == HTTPStatus.OK
        assert b'id="authorizationForm"' in page.content
        assert _grant_count() == 0

        code = _code_from(_consent(client, query, resource))
        # MCP clients send `resource` at the token endpoint too.
        token = _exchange(client, code, verifier, [resource])
        assert token.status_code == HTTPStatus.OK, token.content
        access_token = token.json()["access_token"]

        from oauth2_provider.models import AccessToken

        row = AccessToken.objects.get(token=access_token)
        if _dot_stores_resource():
            assert row.resource == [resource]
        else:
            assert not hasattr(row, "resource")

        response = _ping(client, access_token, transport)
        assert response.status_code == HTTPStatus.OK, response.content
        assert json.loads(response.content) == {"jsonrpc": "2.0", "id": 1, "result": {}}

    def test_no_resource_is_unchanged(
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture
    ):
        verifier, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, []))
        client.force_login(mcp_user)
        assert client.get(reverse("authorize") + "?" + query).status_code == 200
        # DOT 3.4's form carries a blank `resource` field when the GET had
        # none; a blank field is no resource.
        form_resource = "" if _dot_stores_resource() else None
        code = _code_from(_consent(client, query, form_resource))
        token = _exchange(client, code, verifier)
        assert token.status_code == HTTPStatus.OK, token.content
        access_token = token.json()["access_token"]

        from oauth2_provider.models import AccessToken

        row = AccessToken.objects.get(token=access_token)
        if _dot_stores_resource():
            assert row.resource == []
        assert _ping(client, access_token).status_code == HTTPStatus.OK

    def test_debug_on_advertises_and_accepts_http(  # noqa: PLR0913 — fixtures, all load-bearing
        self, client, settings, mcp_app, mcp_user, mcp_active_session, gate_posture
    ):
        """With `DEBUG` on discovery keeps the request's scheme (local dev
        over http); the accepted resource follows it."""
        settings.DEBUG = True
        resource = client.get(
            reverse("mcp_sql_protected_resource_metadata") + "/"
        ).json()["resource"]
        assert resource == "http://testserver/mcp/sql/"
        verifier, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        code = _code_from(_consent(client, query, resource))
        token = _exchange(client, code, verifier)
        assert token.status_code == HTTPStatus.OK, token.content
        assert _ping(client, token.json()["access_token"]).status_code == 200

        # ...and the https spelling is now the foreign one.
        verifier, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [SLASHED]))
        _assert_invalid_target_redirect(
            client.get(reverse("authorize") + "?" + query),
            accepted="http://testserver/mcp/sql/",
        )


@pytest.mark.django_db
class TestForeignResourceIsRefusedAtAuthorize:
    """Anything but the advertised identifier → `invalid_target` to the
    registered redirect, with `state`, and no grant."""

    @pytest.mark.parametrize("resource", FOREIGN)
    def test_get(self, client, mcp_app, mcp_user, gate_posture, resource):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        _assert_invalid_target_redirect(client.get(reverse("authorize") + "?" + query))
        assert _grant_count() == 0

    def test_get_with_a_nul_is_invalid_target_not_500(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        """A NUL `resource` never reaches DOT (which, from 3.4, stores it on
        the grant: a Postgres `DataError` where consent is skipped)."""
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [SLASHED + "\x00"]))
        client.force_login(mcp_user)
        _assert_invalid_target_redirect(client.get(reverse("authorize") + "?" + query))

    def test_get_with_one_foreign_among_repeated_values(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        _, challenge = _pkce()
        query = urlencode(
            _authorize_params(challenge, [SLASHED, "https://somewhere.example/api"])
        )
        client.force_login(mcp_user)
        _assert_invalid_target_redirect(client.get(reverse("authorize") + "?" + query))
        assert _grant_count() == 0

    def test_get_with_both_spellings_is_accepted(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [SLASHED, SLASHLESS]))
        client.force_login(mcp_user)
        assert client.get(reverse("authorize") + "?" + query).status_code == 200

    @pytest.mark.parametrize("resource", FOREIGN)
    def test_consent_post_form_field(
        self, client, mcp_app, mcp_user, gate_posture, resource
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, []))
        client.force_login(mcp_user)
        if not resource.split():
            # A blank form field is "no resource" (DOT 3.4 renders it so).
            code = _code_from(_consent(client, query, resource))
            assert code
            return
        _assert_invalid_target_redirect(_consent(client, query, resource))
        assert _grant_count() == 0

    def test_consent_post_query_string(self, client, mcp_app, mcp_user, gate_posture):
        """oauthlib reads the POST's query string too (ledger F55: a value
        there reached the grant)."""
        _, challenge = _pkce()
        query = urlencode(
            _authorize_params(challenge, ["https://somewhere.example/api"])
        )
        client.force_login(mcp_user)
        _assert_invalid_target_redirect(_consent(client, query, SLASHED))
        assert _grant_count() == 0

    @pytest.mark.parametrize("form_resource", ["", SLASHLESS])
    def test_consent_post_query_and_form_must_agree(
        self, client, mcp_app, mcp_user, gate_posture, form_resource
    ):
        """From DOT 3.4, a blank form field beside a query-string `resource`
        let oauthlib's string reading reach the grant: a 500 (ledger F55)
        even for the advertised value. A browser posts the page's own query
        back, so the two always agree; when they do not, `invalid_target`.
        Below 3.4 the form has no field and DOT ignores both."""
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [SLASHED]))
        client.force_login(mcp_user)
        response = _consent(client, query, form_resource)
        if _dot_stores_resource():
            _assert_invalid_target_redirect(response)
            assert _grant_count() == 0
        else:
            assert _code_from(response)

    def test_cancel_with_a_foreign_resource_is_invalid_target(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        _, challenge = _pkce()
        data = dict(_authorize_params(challenge, []))
        data["resource"] = "https://somewhere.example/api"
        client.force_login(mcp_user)
        _assert_invalid_target_redirect(client.post(reverse("authorize"), data=data))

    def test_foreign_resource_never_redirects_to_a_tampered_target(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        _, challenge = _pkce()
        data = dict(_authorize_params(challenge, []))
        data.update(
            redirect_uri="https://evil.example/steal",
            resource="https://somewhere.example/api",
            allow="Authorize",
        )
        client.force_login(mcp_user)
        response = client.post(reverse("authorize"), data=data)
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Location" not in response
        assert _grant_count() == 0


@pytest.mark.django_db
class TestForeignResourceIsRefusedAtToken:
    """`/o/token/` checks `resource` (query and body) before DOT runs; the
    code is not consumed, so the client can retry without it."""

    def _grant(self, mcp_app, mcp_user) -> tuple[str, str]:
        from oauth2_provider.models import Grant

        verifier, challenge = _pkce()
        code = secrets.token_urlsafe(32)
        Grant.objects.create(
            user=mcp_user,
            code=code,
            application=mcp_app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri=REDIRECT,
            scope="mcp:sql",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        return code, verifier

    @pytest.mark.parametrize("resource", FOREIGN)
    def test_body(self, client, mcp_app, mcp_user, gate_posture, resource):
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Grant

        code, verifier = self._grant(mcp_app, mcp_user)
        response = _exchange(client, code, verifier, [resource])
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response["Cache-Control"] == "no-store"
        body = response.json()
        assert body["error"] == "invalid_target"
        assert SLASHED in body["error_description"]
        assert not AccessToken.objects.exists()
        assert Grant.objects.filter(code=code).exists()
        # The same code still works without the resource.
        assert _exchange(client, code, verifier).status_code == HTTPStatus.OK

    def test_nul_is_invalid_target_not_500(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        code, verifier = self._grant(mcp_app, mcp_user)
        response = _exchange(client, code, verifier, [SLASHED + "\x00"])
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_target"

    def test_query_string(self, client, mcp_app, mcp_user, gate_posture):
        from oauth2_provider.models import AccessToken

        code, verifier = self._grant(mcp_app, mcp_user)
        response = client.post(
            reverse("token") + "?resource=https%3A%2F%2Fsomewhere.example%2Fapi",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_target"
        assert not AccessToken.objects.exists()

    @pytest.mark.parametrize("resource", [SLASHED, SLASHLESS])
    def test_matching_resource_on_a_resource_less_grant(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, resource
    ):
        from oauth2_provider.models import AccessToken

        code, verifier = self._grant(mcp_app, mcp_user)
        response = _exchange(client, code, verifier, [resource])
        assert response.status_code == HTTPStatus.OK, response.content
        access_token = response.json()["access_token"]
        if _dot_stores_resource():
            assert AccessToken.objects.get(token=access_token).resource == [resource]
        assert _ping(client, access_token).status_code == HTTPStatus.OK


@pytest.mark.django_db
@pytest.mark.skipif(
    not _dot_stores_resource(), reason="DOT audience-checks tokens from 3.4"
)
class TestBearerAudienceCheck:
    """`/mcp/sql/` compares a bound token with the URL built as discovery
    builds `resource`, not with Django's `build_absolute_uri`; DOT's check
    itself stays in force."""

    def _token(self, mcp_user, mcp_app, resource: list[str]):
        from oauth2_provider.models import AccessToken

        return AccessToken.objects.create(
            user=mcp_user,
            token="test_" + secrets.token_urlsafe(24),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
            resource=resource,
        )

    @pytest.mark.parametrize("secure", [False, True])
    @pytest.mark.parametrize("resource", [SLASHED, SLASHLESS])
    def test_advertised_identifier_passes_over_either_scheme(  # noqa: PLR0913 — fixtures + two parametrize axes
        self,
        client,
        mcp_app,
        mcp_user,
        mcp_active_session,
        gate_posture,
        resource,
        secure,
    ):
        token = self._token(mcp_user, mcp_app, [resource])
        response = _ping(client, token.token, secure=secure)
        assert response.status_code == HTTPStatus.OK, response.content

    @pytest.mark.parametrize(
        "resource",
        [
            "https://somewhere.example/api",
            "https://other.example/mcp/sql/",
            "https://testserver/mcp/sql/tools",
            "https://testserver/o/",
        ],
    )
    def test_a_token_bound_elsewhere_is_still_refused(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, resource
    ):
        """Rows from before this fix (or written by hand) keep failing DOT's
        audience check: the check is pointed at the right URL, not off."""
        token = self._token(mcp_user, mcp_app, [resource])
        response = _ping(client, token.token)
        assert response.status_code == HTTPStatus.UNAUTHORIZED

    def test_debug_on_uses_the_request_scheme(  # noqa: PLR0913 — fixtures, all load-bearing
        self, client, settings, mcp_app, mcp_user, mcp_active_session, gate_posture
    ):
        settings.DEBUG = True
        token = self._token(mcp_user, mcp_app, ["http://testserver/mcp/sql/"])
        assert _ping(client, token.token).status_code == HTTPStatus.OK
        token = self._token(mcp_user, mcp_app, [SLASHED])
        assert _ping(client, token.token).status_code == HTTPStatus.UNAUTHORIZED


def test_token_endpoint_is_the_package_view():
    from django.urls import resolve
    from mcp_sql.views.oauth_token import MCPTokenView

    assert resolve(reverse("token")).func.view_class is MCPTokenView


@pytest.mark.django_db
def test_the_token_view_stays_csrf_exempt():
    """A CSRF-enforcing client reaches the resource check (400), not
    Django's CSRF 403: `MCPTokenView` keeps DOT's `csrf_exempt`."""
    from django.test import Client

    response = Client(enforce_csrf_checks=True).post(
        reverse("token"), data={"resource": "https://somewhere.example/api"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_target"
