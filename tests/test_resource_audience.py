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

"The advertised identifier" is compared by RFC 3986 equivalence of scheme
and authority (case, default port), with the path exact; and the host in it
is spelled canonically whatever the Host header says (`<name>:443`, an
uppercase name), so a client that parses discovery's value and sends back
the normalised form is accepted end to end on that host.

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
from html.parser import HTMLParser
from http import HTTPStatus
from importlib.metadata import version
from urllib.parse import parse_qs
from urllib.parse import unquote
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
    "ftp://testserver/mcp/sql/",
    "https://testserver/mcp/sql//",
    "https://testserver/mcp/",
    "https://testserver/mcp",
    "https://testserver/mcp/sql/tools",
    "https://testserver/MCP/SQL/",  # the path is case-sensitive
    "https://testserver/mcp/%73ql/",  # no percent-decoding
    "https://testserver/mcp/./sql/",  # no dot segments
    "https://testserver",  # the bare origin
    "https://testserver/",
    "https://other.example/mcp/sql/",
    "https://testserver.example/mcp/sql/",
    "https://testserver./mcp/sql/",
    "https://testserver:8443/mcp/sql/",
    "https://testserver:80/mcp/sql/",  # http's default port, not https's
    "https://testserver:/mcp/sql/",  # an empty port
    "https://testserver/mcp/sql/?x=1",
    "https://testserver/mcp/sql/?",  # an empty query
    "https://testserver/mcp/sql/#f",
    "https://testserver/mcp/sql/#",
    "https://user@testserver/mcp/sql/",
    "https://@testserver/mcp/sql/",
    "https:testserver/mcp/sql/",
    "//testserver/mcp/sql/",
    "testserver/mcp/sql/",
    "https://testserver/mcp/\tsql/",  # urlsplit would drop the tab
    "https://testsérver/mcp/sql/",
    "",
    "not a uri",
    f"{SLASHED} https://somewhere.example/api",
]

# The advertised identifier in other spellings of the same URL (RFC 3986
# §6.2.2.1 / §6.2.3): scheme and host in any case, the default port explicit.
# The MCP spec has servers accept uppercase scheme and host; a client that
# parses discovery's value sends the canonical form, one that does not may
# send what its user typed.
EQUIVALENT = [
    "https://TESTSERVER/mcp/sql/",
    "https://TestServer/mcp/sql",
    "HTTPS://testserver/mcp/sql/",
    "Https://testserver/mcp/sql",
    "https://testserver:443/mcp/sql/",
    "https://testserver:443/mcp/sql",
    "https://TESTSERVER:0443/mcp/sql/",
]

# Host headers naming this server non-canonically: a proxy forwarding
# `$host:$server_port` (nginx), an `X-Forwarded-Host` with the port, an
# uppercase name. All in `ALLOWED_HOSTS` (Django compares it lowercased).
NON_CANONICAL_HOSTS = [
    "testserver:443",
    "TESTSERVER",
    "TestServer:443",
    "testserver:0443",
]

# A value no answer may carry back (RFC 8707 errors go into a redirect).
ECHO_MARKER = "NoEchoMarker" + "Q" * 300
ECHOED = [
    f"https://somewhere.example/{ECHO_MARKER}",
    f"https://testserver/mcp/sql/?{ECHO_MARKER}=1",
    f"https://{ECHO_MARKER.lower()}.example/mcp/sql/",
]


def exact_audience_validator(request_uri: str, audiences: list[str]) -> bool:
    """A `RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR` comparing strings (bar
    the trailing slash), stricter than DOT's default."""
    return request_uri.rstrip("/") in {audience.rstrip("/") for audience in audiences}


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


def _consent(client, query: str, form_resource: str | None, **extra):
    """The consent POST as a browser sends it: back to the page's URL (query
    string included) with the form's fields, `resource` among them from
    DOT 3.4 (blank when the GET carried none)."""
    data = dict(parse_qs(query))
    data = {key: values[-1] for key, values in data.items() if key != "resource"}
    data["allow"] = "Authorize"
    if form_resource is not None:
        data["resource"] = form_resource
    return client.post(reverse("authorize") + "?" + query, data=data, **extra)


class _HiddenFields(HTMLParser):
    """The hidden `<input>`s of the consent page's `authorizationForm`, as
    a browser would submit them (name, value; in page order)."""

    def __init__(self) -> None:
        super().__init__()
        self.in_form = False
        self.fields: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self.in_form = attributes.get("id") == "authorizationForm"
        elif self.in_form and tag == "input" and attributes.get("type") == "hidden":
            self.fields.append((attributes["name"], attributes.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False


def _submit_consent_page(client, page_url: str, page, **extra):
    """Approve the rendered consent page as a browser does: its own hidden
    fields, untouched, posted back to the page's URL (the form has no
    `action`)."""
    parser = _HiddenFields()
    parser.feed(page.content.decode())
    assert parser.fields, page.content[:300]
    data = urlencode([*parser.fields, ("allow", "Authorize")])
    return client.post(
        page_url,
        data=data,
        content_type="application/x-www-form-urlencoded",
        **extra,
    )


def _code_from(response) -> str:
    assert response.status_code == HTTPStatus.FOUND, response.content[:300]
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT
    return parse_qs(location.query)["code"][0]


def _exchange(client, code: str, verifier: str, resources: Sequence[str] = (), **extra):
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
        **extra,
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


def _round_trip(client, mcp_user, resource: str, **extra) -> str:
    """Authorize GET (consent page) → consent POST → token, all sending
    `resource`; the access token."""
    verifier, challenge = _pkce()
    query = urlencode(_authorize_params(challenge, [resource]))
    client.force_login(mcp_user)
    page = client.get(reverse("authorize") + "?" + query, **extra)
    assert page.status_code == HTTPStatus.OK, page.get("Location", page.content[:300])
    assert b'id="authorizationForm"' in page.content
    code = _code_from(_consent(client, query, resource, **extra))
    token = _exchange(client, code, verifier, [resource], **extra)
    assert token.status_code == HTTPStatus.OK, token.content
    return token.json()["access_token"]


@pytest.mark.django_db
class TestEquivalentSpellingsAreAccepted:
    """The advertised identifier with an uppercase scheme or host, or the
    default port spelled out, is the same resource: accepted end to end, and
    the token works (DOT's default audience validator compares the parsed
    scheme, host, port and path the same way)."""

    @pytest.mark.parametrize("resource", EQUIVALENT)
    def test_round_trip(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, resource
    ):
        access_token = _round_trip(client, mcp_user, resource)

        from oauth2_provider.models import AccessToken

        if _dot_stores_resource():
            assert AccessToken.objects.get(token=access_token).resource == [resource]
        assert _ping(client, access_token).status_code == HTTPStatus.OK

    def test_mixed_spellings_in_one_request(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [SLASHED, *EQUIVALENT]))
        client.force_login(mcp_user)
        assert client.get(reverse("authorize") + "?" + query).status_code == 200


@pytest.mark.django_db
class TestConsentPageRoundTrip:
    """The consent POST built from the RENDERED page, not from the test's
    idea of it: DOT 3.4 renders the GET's `resource` values as one
    whitespace-joined hidden field, and `form_valid` splits it and requires
    it to agree with the query string. Every other consent test posts a
    hand-built field; this pins that what DOT actually renders goes back
    through the check and gets a code (were the rendering and the split to
    disagree, every real consent POST carrying a `resource` would be
    refused)."""

    @pytest.mark.parametrize(
        "resources",
        [
            [SLASHED],
            [SLASHLESS],
            [SLASHED, SLASHLESS],
            ["https://TESTSERVER:443/mcp/sql/"],
            [SLASHED, *EQUIVALENT],
            [],
        ],
    )
    def test_the_rendered_form_round_trips(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, resources
    ):
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Grant

        verifier, challenge = _pkce()
        page_url = (
            reverse("authorize")
            + "?"
            + urlencode(_authorize_params(challenge, resources))
        )
        client.force_login(mcp_user)
        page = client.get(page_url)
        assert page.status_code == HTTPStatus.OK
        code = _code_from(_submit_consent_page(client, page_url, page))
        if _dot_stores_resource():
            assert Grant.objects.get(code=code).resource == resources
        # No `resource` at the token endpoint: the token inherits the grant's.
        token = _exchange(client, code, verifier)
        assert token.status_code == HTTPStatus.OK, token.content
        access_token = token.json()["access_token"]
        if _dot_stores_resource():
            assert AccessToken.objects.get(token=access_token).resource == resources
        assert _ping(client, access_token).status_code == HTTPStatus.OK


@pytest.mark.django_db
class TestSpellingsAcrossSteps:
    """Equivalent spellings are equivalent at each step on its own, not
    across steps: from DOT 3.4, `/o/token/` also requires each `resource`
    to be one of the grant's, compared as strings
    (`_check_and_set_request_resource`). Another accepted spelling passes
    the package's check and then gets DOT's own `invalid_target` (which
    names the value sent); the code is not consumed, and the exchange
    works with the authorization request's own string, or with none."""

    @pytest.mark.parametrize(
        ("at_authorize", "at_token"),
        [
            (SLASHED, SLASHLESS),
            ("https://TESTSERVER/mcp/sql/", SLASHED),
            ("https://testserver:443/mcp/sql/", SLASHED),
        ],
    )
    def test_the_token_step_wants_the_granted_string(  # noqa: PLR0913 — fixtures + two parameters
        self,
        client,
        mcp_app,
        mcp_user,
        mcp_active_session,
        gate_posture,
        at_authorize,
        at_token,
    ):
        verifier, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [at_authorize]))
        client.force_login(mcp_user)
        assert client.get(reverse("authorize") + "?" + query).status_code == 200
        code = _code_from(_consent(client, query, at_authorize))
        response = _exchange(client, code, verifier, [at_token])
        if not _dot_stores_resource():
            # Below 3.4 DOT ignores `resource`.
            assert response.status_code == HTTPStatus.OK, response.content
            return
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        # DOT's answer, not the package's (whose check the value passed);
        # DOT labels its JSON body `text/html`.
        body = json.loads(response.content)
        assert body["error"] == "invalid_target"
        assert "Token request cannot escalate" in body["error_description"]
        response = _exchange(client, code, verifier, [at_authorize])
        assert response.status_code == HTTPStatus.OK, response.content
        assert _ping(client, response.json()["access_token"]).status_code == 200


@pytest.mark.django_db
class TestNonCanonicalHostHeader:
    """A Host header naming this server non-canonically (`<name>:443`, an
    uppercase name) no longer leaks into the identifier: discovery
    advertises the canonical URL, which is what a client that parses it
    sends back, and that value works end to end on the same host. Before,
    discovery said `https://testserver:443/mcp/sql/`, the client sent
    `https://testserver/mcp/sql/`, and the exact comparison answered
    `invalid_target`."""

    @pytest.mark.parametrize("slash", [True, False])
    @pytest.mark.parametrize("host", NON_CANONICAL_HOSTS)
    def test_discovery_advertises_the_canonical_host(self, client, host, slash):
        path = reverse("mcp_sql_protected_resource_metadata") + ("/" if slash else "")
        document = client.get(path, HTTP_HOST=host).json()
        assert document["resource"] == (SLASHED if slash else SLASHLESS)
        assert document["authorization_servers"] == ["https://testserver/o"]
        metadata = client.get(
            reverse("oauth_authorization_server_metadata"), HTTP_HOST=host
        ).json()
        assert metadata["issuer"] == "https://testserver/o"
        assert metadata["token_endpoint"] == "https://testserver/o/token/"
        challenge = client.post("/mcp/sql/", HTTP_HOST=host)["WWW-Authenticate"]
        assert 'resource_metadata="https://testserver/.well-known/' in challenge

    def test_an_unbounded_port_is_kept_not_a_500(self, client):
        host = "testserver:" + "9" * 5000
        response = client.get(
            reverse("mcp_sql_protected_resource_metadata") + "/", HTTP_HOST=host
        )
        assert response.status_code == HTTPStatus.OK
        assert response.json()["resource"] == f"https://{host}/mcp/sql/"

    @pytest.mark.parametrize("host", NON_CANONICAL_HOSTS)
    def test_discovered_resource_round_trips(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, host
    ):
        resource = client.get(
            reverse("mcp_sql_protected_resource_metadata") + "/", HTTP_HOST=host
        ).json()["resource"]
        access_token = _round_trip(client, mcp_user, resource, HTTP_HOST=host)
        response = _ping(client, access_token, HTTP_HOST=host)
        assert response.status_code == HTTPStatus.OK, response.content

    @pytest.mark.skipif(
        not _dot_stores_resource(), reason="DOT audience-checks tokens from 3.4"
    )
    @pytest.mark.parametrize("resource", [SLASHED, SLASHLESS])
    @pytest.mark.parametrize("host", NON_CANONICAL_HOSTS)
    def test_bearer_sees_the_canonical_url(  # noqa: PLR0913 — fixtures + two parametrize axes
        self,
        client,
        settings,
        mcp_app,
        mcp_user,
        mcp_active_session,
        gate_posture,
        host,
        resource,
    ):
        """The URL `/mcp/sql/` hands DOT's audience check is built like
        discovery's, so it is canonical too: a token bound to the
        advertised value passes even a validator that compares strings."""
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR": (
                "mcp_sql.tests.test_resource_audience.exact_audience_validator"
            ),
        }
        from oauth2_provider.models import AccessToken

        token = AccessToken.objects.create(
            user=mcp_user,
            token="test_" + secrets.token_urlsafe(24),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
            resource=[resource],
        )
        response = _ping(client, token.token, HTTP_HOST=host)
        assert response.status_code == HTTPStatus.OK, response.content
        foreign = ["https://testserver:443/mcp/sql/"]
        token = AccessToken.objects.create(
            user=mcp_user,
            token="test_" + secrets.token_urlsafe(24),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
            resource=foreign,
        )
        # ...and the validator is really in force.
        assert _ping(client, token.token, HTTP_HOST=host).status_code == 401

    @pytest.mark.parametrize("resource", [SLASHED, *EQUIVALENT])
    @pytest.mark.parametrize("host", NON_CANONICAL_HOSTS)
    def test_every_spelling_is_accepted_on_every_host(  # noqa: PLR0913 — fixtures + two parametrize axes
        self, client, mcp_app, mcp_user, gate_posture, host, resource
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        page = client.get(reverse("authorize") + "?" + query, HTTP_HOST=host)
        assert page.status_code == HTTPStatus.OK, page.get("Location")

    @pytest.mark.parametrize(
        "resource",
        [
            "https://testserver",
            "https://testserver:8443/mcp/sql/",
            "http://testserver/mcp/sql/",
            "https://other.example/mcp/sql/",
            "https://testserver/mcp/sql/?x=1",
        ],
    )
    @pytest.mark.parametrize("host", NON_CANONICAL_HOSTS)
    def test_foreign_values_stay_refused(  # noqa: PLR0913 — fixtures + two parametrize axes
        self, client, mcp_app, mcp_user, gate_posture, host, resource
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        response = client.get(reverse("authorize") + "?" + query, HTTP_HOST=host)
        _assert_invalid_target_redirect(response)
        assert _grant_count() == 0


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

    def test_consent_form_field_with_a_nul_is_refused_not_500(
        self, client, mcp_app, mcp_user, gate_posture
    ):
        """From DOT 3.4 the consent form has a `resource` field, and Django's
        form validation refuses a NUL in it before `form_valid` runs: the
        consent page is re-rendered with the form error (no redirect,
        nothing stored). Below 3.4 the form has no such field, and the
        package's check answers `invalid_target`."""
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, []))
        client.force_login(mcp_user)
        response = _consent(client, query, SLASHED + "\x00")
        assert _grant_count() == 0
        if _dot_stores_resource():
            assert response.status_code == HTTPStatus.OK
            assert "Location" not in response
            assert b'id="authorizationForm"' in response.content
        else:
            _assert_invalid_target_redirect(response)

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
        """Rows from before this fix (or written by hand) bound to a URL that
        is not a prefix of the endpoint's keep failing DOT's audience check:
        the check is pointed at the right URL, not off."""
        token = self._token(mcp_user, mcp_app, [resource])
        response = _ping(client, token.token)
        assert response.status_code == HTTPStatus.UNAUTHORIZED

    @pytest.mark.parametrize(
        "resource",
        [
            "https://testserver",
            "https://testserver/",
            "https://testserver/mcp",
            "https://testserver/mcp/",
            "https://TESTSERVER:443/",
        ],
    )
    def test_a_token_bound_to_a_prefix_passes(  # noqa: PLR0913 — fixtures + parameter
        self, client, mcp_app, mcp_user, mcp_active_session, gate_posture, resource
    ):
        """DOT's default validator (`validate_resource_as_url_prefix`) takes
        a token's `resource` as a base the request URL must fall under, so a
        token bound to a prefix of the endpoint URL (the origin, `/mcp`)
        passes at `/mcp/sql/`. The package no longer issues one (those
        values are `invalid_target`); a row from before this fix, or written
        by hand, works until it expires."""
        token = self._token(mcp_user, mcp_app, [resource])
        response = _ping(client, token.token)
        assert response.status_code == HTTPStatus.OK, response.content

    def test_debug_on_uses_the_request_scheme(  # noqa: PLR0913 — fixtures, all load-bearing
        self, client, settings, mcp_app, mcp_user, mcp_active_session, gate_posture
    ):
        settings.DEBUG = True
        token = self._token(mcp_user, mcp_app, ["http://testserver/mcp/sql/"])
        assert _ping(client, token.token).status_code == HTTPStatus.OK
        token = self._token(mcp_user, mcp_app, [SLASHED])
        assert _ping(client, token.token).status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.django_db
class TestInvalidTargetNeverEchoesTheValue:
    """`invalid_target` names the accepted value only: the client's own
    `resource` is never carried back — not in `error_description`, not in
    the redirect, not in a page or JSON body."""

    @staticmethod
    def _assert_not_echoed(response) -> None:
        location = response.get("Location", "")
        assert ECHO_MARKER not in location
        assert ECHO_MARKER not in unquote(location)
        assert ECHO_MARKER.lower() not in unquote(location).lower()
        assert ECHO_MARKER.lower() not in response.content.decode().lower()

    @pytest.mark.parametrize("resource", ECHOED)
    def test_authorize_get(self, client, mcp_app, mcp_user, gate_posture, resource):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource]))
        client.force_login(mcp_user)
        response = client.get(reverse("authorize") + "?" + query)
        _assert_invalid_target_redirect(response)
        self._assert_not_echoed(response)

    @pytest.mark.parametrize("in_query", [False, True])
    @pytest.mark.parametrize("resource", ECHOED)
    def test_consent_post(  # noqa: PLR0913 — fixtures + two parametrize axes
        self, client, mcp_app, mcp_user, gate_posture, resource, in_query
    ):
        _, challenge = _pkce()
        query = urlencode(_authorize_params(challenge, [resource] if in_query else []))
        client.force_login(mcp_user)
        response = _consent(client, query, SLASHED if in_query else resource)
        _assert_invalid_target_redirect(response)
        self._assert_not_echoed(response)

    @pytest.mark.parametrize("in_query", [False, True])
    @pytest.mark.parametrize("resource", ECHOED)
    def test_token(  # noqa: PLR0913 — fixtures + two parametrize axes
        self, client, mcp_app, mcp_user, gate_posture, resource, in_query
    ):
        path = reverse("token")
        data = {"grant_type": "authorization_code", "code": "x", "client_id": "mcp-sql"}
        if in_query:
            path += "?" + urlencode({"resource": resource})
        else:
            data["resource"] = resource
        response = client.post(path, data=data)
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_target"
        assert SLASHED in response.json()["error_description"]
        self._assert_not_echoed(response)


@pytest.mark.django_db
@pytest.mark.filterwarnings("ignore:JSONOAuthLibCore:DeprecationWarning")
def test_the_token_view_ignores_a_json_backend(settings, client, mcp_app, mcp_user):
    """`MCPTokenView` reads the form body, and so must DOT under it: with a
    consumer's `OAUTH2_BACKEND_CLASS = JSONOAuthLibCore` a JSON body (never
    seen by the `resource` check) was parsed by DOT and its `resource` put
    on the token. Also with a core already cached on DOT's stock
    `TokenView`, which DOT's class-level cache would otherwise hand down."""
    from mcp_sql.views.oauth_token import MCPTokenView
    from oauth2_provider.models import AccessToken
    from oauth2_provider.models import Grant
    from oauth2_provider.views import TokenView

    def clear_cached_cores() -> None:
        for view in (TokenView, MCPTokenView):
            if "_oauthlib_core" in view.__dict__:
                delattr(view, "_oauthlib_core")

    settings.OAUTH2_PROVIDER = {
        **settings.OAUTH2_PROVIDER,
        "OAUTH2_BACKEND_CLASS": "oauth2_provider.oauth2_backends.JSONOAuthLibCore",
    }
    # As in a process started with these settings: no core cached yet,
    # then the stock view serves a request first.
    clear_cached_cores()
    TokenView.get_oauthlib_core()
    try:
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
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": "mcp-sql",
            "code_verifier": verifier,
            "resource": "https://somewhere.example/api",
        }
        response = client.post(
            reverse("token"), data=json.dumps(body), content_type="application/json"
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
        assert not AccessToken.objects.exists()
        # The form-encoded exchange is unaffected.
        del body["resource"]
        response = client.post(reverse("token"), data=body)
        assert response.status_code == HTTPStatus.OK, response.content
    finally:
        clear_cached_cores()


@pytest.mark.parametrize(
    "value",
    [
        "https://\u212aelvin.example/mcp/sql/",  # KELVIN SIGN lowercases to k
        "https://\u212aELVIN.EXAMPLE:443/mcp/sql",
    ],
)
def test_non_ascii_that_lowercases_to_the_host_is_foreign(settings, rf, value):
    from mcp_sql.audience import foreign_resource

    settings.ALLOWED_HOSTS = ["kelvin.example"]
    request = rf.get("/", HTTP_HOST="kelvin.example")
    assert foreign_resource(request, ["https://KELVIN.example/mcp/sql/"]) is None
    assert foreign_resource(request, [value]) == value


@pytest.mark.parametrize(
    ("scheme", "authority", "canonical"),
    [
        ("https", "Example.COM", "example.com"),
        ("https", "example.com:443", "example.com"),
        ("https", "example.com:0443", "example.com"),
        ("http", "example.com:80", "example.com"),
        ("https", "example.com:80", "example.com:80"),
        ("http", "example.com:443", "example.com:443"),
        ("https", "example.com:08443", "example.com:8443"),
        ("https", "example.com:0", "example.com:0"),
        ("https", "example.com:", "example.com:"),
        ("https", "[::1]", "[::1]"),
        ("https", "[::1]:443", "[::1]"),
        ("https", "[::1]:8443", "[::1]:8443"),
        ("https", "[::FFFF:1.2.3.4]:443", "[::ffff:1.2.3.4]"),
        ("ftp", "example.com:21", "example.com:21"),
        # Two ports is not `host[:port]`: kept as it is (bar the case), so it
        # never equals a real authority. Splitting at the last colon made
        # `example.com:8443:443` the canonical `example.com:8443`.
        ("https", "example.com:8443:443", "example.com:8443:443"),
        ("https", "Example.COM:8443:0443", "example.com:8443:0443"),
        ("https", "example.com:443:443", "example.com:443:443"),
        ("https", "[::1]:8443:443", "[::1]:8443:443"),
        ("https", "::1:443", "::1:443"),
    ],
)
def test_canonical_authority(scheme, authority, canonical):
    from mcp_sql.consts import canonical_authority

    assert canonical_authority(scheme, authority) == canonical


# Spellings of a `host[:port]` request's own endpoint that no URL parser
# takes: two ports, or a port out of range or overlong. DOT (3.4+) refuses
# such a value at `/o/authorize/` with an `invalid_target` of its own that
# names the client's value; the package refuses it first, with its own.
UNPARSEABLE_PORTS = [
    ("testserver:8443", "https://testserver:8443:443/mcp/sql/"),
    ("testserver:8443", "https://testserver:8443:0443/mcp/sql"),
    ("testserver", "https://testserver:443:443/mcp/sql/"),
    ("testserver", "https://testserver:000443/mcp/sql/"),  # over five digits
    ("testserver", "https://testserver:" + "0" * 4300 + "443/mcp/sql/"),
    ("testserver", "https://testserver:65979/mcp/sql/"),
    ("testserver:99999", "https://testserver:99999/mcp/sql/"),  # its own host
    ("testserver:65536", "https://testserver:65536/mcp/sql/"),
]


@pytest.mark.parametrize(("host", "value"), UNPARSEABLE_PORTS)
def test_an_unparseable_port_is_foreign(rf, host, value):
    from mcp_sql.audience import foreign_resource

    request = rf.get("/", HTTP_HOST=host)
    assert foreign_resource(request, [value]) == value


@pytest.mark.parametrize(
    ("host", "value"),
    [
        ("testserver:8443", "https://testserver:8443/mcp/sql/"),
        ("testserver:8443", "https://TESTSERVER:08443/mcp/sql"),
        ("testserver:65535", "https://testserver:65535/mcp/sql/"),
        ("testserver", "https://testserver:00443/mcp/sql/"),  # five digits
    ],
)
def test_a_parseable_port_is_still_accepted(rf, host, value):
    from mcp_sql.audience import foreign_resource

    request = rf.get("/", HTTP_HOST=host)
    assert foreign_resource(request, [value]) is None


@pytest.mark.django_db
@pytest.mark.parametrize(("host", "value"), UNPARSEABLE_PORTS)
def test_an_unparseable_port_gets_the_packages_invalid_target(  # noqa: PLR0913 — fixtures + two parameters
    client, mcp_app, mcp_user, gate_posture, host, value
):
    """End to end: the package's own `invalid_target` (the accepted value,
    not the client's), never DOT's; no grant. Below DOT 3.4 the value was a
    consent page; from 3.4 DOT's answer named the client's value."""
    _, challenge = _pkce()
    query = urlencode(_authorize_params(challenge, [value]))
    client.force_login(mcp_user)
    response = client.get(reverse("authorize") + "?" + query, HTTP_HOST=host)
    advertised = client.get(
        reverse("mcp_sql_protected_resource_metadata") + "/", HTTP_HOST=host
    ).json()["resource"]
    _assert_invalid_target_redirect(response, accepted=advertised)
    description = parse_qs(urlparse(response["Location"]).query)["error_description"]
    assert description[0].startswith("resource must be this server's MCP endpoint")
    if value != advertised:
        assert value not in unquote(response["Location"])
    assert _grant_count() == 0


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
