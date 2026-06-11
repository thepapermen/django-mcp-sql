"""Tests for the `/mcp/sql/` view and its tool callables."""

import io
import secrets
from datetime import timedelta
from http import HTTPStatus
from unittest.mock import MagicMock

import pytest
from asgiref.sync import async_to_sync
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from mcp_sql import fencing
from mcp_sql.conf import Profile
from mcp_sql.schemas import ToolName
from mcp_sql.views.mcp_endpoint import _SERVER_INSTRUCTIONS
from mcp_sql.views.mcp_endpoint import _build_mcp_server
from mcp_sql.views.mcp_endpoint import _get_asgi_loop
from mcp_sql.views.mcp_endpoint import _invoke_wsgi_app
from rest_framework.test import APIClient

_DEFAULT_PROFILE = Profile(
    name="default",
    role="mcp_readonly_role",
    codename="use_mcp_session",
    group_name="mcp_sql_users",
    allowed_models=("auth.Permission",),
    session_context=None,
)


class TestSharedAsgiLoop:
    """C1: the a2wsgi bridge must reuse one process-global event loop. a2wsgi
    spawns a fresh loop + daemon thread whenever `ASGIMiddleware` is built
    without `loop=`, so a per-request construction would leak one idle-loop
    thread per `/mcp/sql/` call. The view passes `_get_asgi_loop()` instead."""

    def test_loop_is_reused_and_running(self):
        first = _get_asgi_loop()
        second = _get_asgi_loop()
        assert first is second
        assert first.is_running()


@pytest.mark.django_db
class TestBuildMcpServer:
    """Per-request `FastMCP` server: tool registration + closure correctness."""

    def test_three_tools_registered(self, mcp_user):
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        names = {t.name for t in server._tool_manager.list_tools()}
        assert names == {"list_tables", "describe_table", "run_query"}

    def test_server_advertises_security_instructions(self, mcp_user):
        """The MCP `initialize` response carries the standing security posture:
        the untrusted-data warning plus the human-in-the-loop recommendation,
        delivered once at connect time, out-of-band from any row content."""
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        assert server.instructions == _SERVER_INSTRUCTIONS
        # Pin the load-bearing content so a future edit can't quietly gut it.
        assert "UNTRUSTED" in _SERVER_INSTRUCTIONS
        assert "data_handling" in _SERVER_INSTRUCTIONS
        assert "human-in-the-loop" in _SERVER_INSTRUCTIONS
        assert "other tools" in _SERVER_INSTRUCTIONS
        # The fence token described to the agent must match what run_query
        # actually emits — renaming fencing.FENCE_TAG must break this.
        assert fencing.FENCE_TAG in _SERVER_INSTRUCTIONS

    def test_tools_are_annotated_read_only(self, mcp_user):
        """All three tools advertise honest read-only / closed-world hints.
        These tools are genuinely safe; the residual injection risk is the
        agent's OTHER tools (see the server instructions), not these."""
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        for name in ("list_tables", "describe_table", "run_query"):
            annotations = server._tool_manager.get_tool(name).annotations
            assert annotations is not None, f"{name} missing annotations"
            assert annotations.readOnlyHint is True
            assert annotations.openWorldHint is False

    def test_list_tables_returns_declared_tables(self, mcp_user, monkeypatch):
        # `auth.Permission` is the conventional demo whitelist entry; it
        # exists in every Django test DB.
        # Mock the audit write at the executor boundary (mirrors the
        # `run_query` test): the closure dispatches it through
        # `sync_to_async(..., thread_sensitive=False)`, whose separate-thread
        # ORM write would escape the test transaction. The real write is
        # covered synchronously in `TestAuditToolCall`.
        audited: list[dict] = []
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint.executor.audit_tool_call",
            lambda **kw: audited.append(kw),
        )
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        list_tables = server._tool_manager.get_tool("list_tables").fn
        assert async_to_sync(list_tables)() == ["auth_permission"]
        assert audited == [
            {
                "user": mcp_user,
                "profile": _DEFAULT_PROFILE,
                "tool": ToolName.LIST_TABLES,
                "token_id": "t1",
                "client_ip": "127.0.0.1",
            }
        ]

    def test_describe_table_returns_columns_for_whitelisted(
        self, mcp_user, monkeypatch
    ):
        audited: list[dict] = []
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint.executor.audit_tool_call",
            lambda **kw: audited.append(kw),
        )
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        describe = server._tool_manager.get_tool("describe_table").fn
        result = async_to_sync(describe)("auth_permission")
        assert "columns" in result
        assert "codename" in result["columns"]
        assert result["columns"]["id"]["primary_key"] is True
        # Audited with the requested table captured in `detail`.
        assert audited[0]["tool"] == ToolName.DESCRIBE_TABLE
        assert audited[0]["detail"] == "describe_table('auth_permission')"

    def test_describe_table_rejects_non_whitelisted(self, mcp_user, monkeypatch):
        audited: list[dict] = []
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint.executor.audit_tool_call",
            lambda **kw: audited.append(kw),
        )
        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="t1",  # noqa: S106 — opaque DB id, not a credential
            client_ip="127.0.0.1",
        )
        describe = server._tool_manager.get_tool("describe_table").fn
        result = async_to_sync(describe)("pg_class")
        assert "error" in result
        assert "whitelist" in result["error"]
        # A probe for a non-whitelisted table is still audited.
        assert audited[0]["tool"] == ToolName.DESCRIBE_TABLE
        assert audited[0]["detail"] == "describe_table('pg_class')"

    def test_run_query_closure_passes_auth_principal(self, mcp_user, monkeypatch):
        """The `run_query` closure must forward the authenticated principal
        to `executor.run_query`, not pull from a thread-local or request."""
        from mcp_sql.schemas import QueryResult

        captured: dict = {}

        def fake_run_query(  # noqa: PLR0913
            *, user, profile, raw_sql, limit, token_id, client_ip
        ):
            captured.update(
                user=user,
                profile=profile,
                raw_sql=raw_sql,
                limit=limit,
                token_id=token_id,
                client_ip=client_ip,
            )
            return QueryResult(row_count=0)

        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint.executor.run_query", fake_run_query
        )

        server = _build_mcp_server(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            token_id="tok-42",  # noqa: S106 — opaque DB id, not a credential
            client_ip="10.0.0.7",
        )
        run_query = server._tool_manager.get_tool("run_query").fn
        # `run_query` is `async def` so the FastMCP SDK can `await` it from
        # its event loop (sync tools would trip Django's async-context
        # detection on the executor's ORM audit write). `async_to_sync`
        # drives the coroutine from a sync test without pulling in
        # pytest-asyncio.
        result = async_to_sync(run_query)("SELECT 1", limit=5)
        # The closure serialises the real QueryResult via `asdict`, then passes
        # it through the untrusted-content fence (see tests/test_fencing.py).
        assert result["row_count"] == 0
        assert "data_handling" in result
        assert result["rows"].startswith("<untrusted-data-")
        assert captured["user"].pk == mcp_user.pk
        assert captured["profile"] is _DEFAULT_PROFILE
        assert captured["raw_sql"] == "SELECT 1"
        assert captured["limit"] == 5
        assert captured["token_id"] == "tok-42"
        assert captured["client_ip"] == "10.0.0.7"


@pytest.mark.django_db
class TestAuditToolCall:
    """`executor.audit_tool_call` writes one allowed metadata row directly
    (the metadata tools never enter the readonly executor)."""

    def test_writes_allowed_metadata_row(self, mcp_user):
        from mcp_sql import executor
        from mcp_sql.models import MCPQueryLog

        executor.audit_tool_call(
            user=mcp_user,
            profile=_DEFAULT_PROFILE,
            tool=ToolName.DESCRIBE_TABLE,
            token_id="tok9",  # noqa: S106 — opaque DB id, not a credential
            client_ip="10.0.0.1",
            detail="describe_table('auth_permission')",
        )
        row = MCPQueryLog.objects.get()
        assert row.tool == ToolName.DESCRIBE_TABLE
        assert row.profile == "default"
        assert row.decision == MCPQueryLog.DECISION_ALLOWED
        assert row.rejection_reason == ""
        assert row.raw_sql == "describe_table('auth_permission')"
        assert row.token_id == "tok9"
        assert row.client_ip == "10.0.0.1"
        # Metadata-only shape: no SQL pipeline fields, no execution metrics.
        assert row.normalized_sql == ""
        assert row.wrapped_sql == ""
        assert row.duration_ms is None
        assert row.row_count is None
        assert row.truncated is False


@pytest.mark.django_db
class TestMcpEndpointAuthGate:
    """The auth + permission decorators must reject before the bridge runs."""

    def test_unauthenticated_post_returns_401_or_403(self, client):
        url = reverse("mcp_sql_endpoint")
        response = client.post(url, data=b"", content_type="application/json")
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

    def test_wrong_scope_token_rejected(self, mcp_user, mcp_app, mcp_mfa_on):
        from oauth2_provider.models import AccessToken

        bad_token = AccessToken.objects.create(
            user=mcp_user,
            token="bad_" + secrets.token_urlsafe(16),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="read",  # Not "mcp:sql".
        )
        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {bad_token.token}")
        response = api_client.post(reverse("mcp_sql_endpoint"), data={}, format="json")
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}


@pytest.mark.django_db
class TestStockDRFDefaultsDoNotPiercePackage:
    """Anonymous probes get 401 + RFC 9728 challenge even under stock DRF.

    The view's `@permission_classes([IsAuthenticated])` decorator is the
    package's self-declared permission contract; without it the endpoint
    would inherit `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` from the
    consumer, which in stock DRF is `AllowAny`. An anonymous request
    would then reach the FastMCP bridge, return 200 with a JSON-RPC
    error, and MCP clients (e.g. Claude Code) would never receive the
    `WWW-Authenticate: Bearer ..., resource_metadata="..."` challenge
    they need to bootstrap the OAuth dance.

    This test overrides `REST_FRAMEWORK` to the worst-case shape a
    consumer could ship — no auth defaults, `AllowAny` permission
    defaults — and pins that the package still rejects with the
    discovery-bearing 401.
    """

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": (),
            "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),
        }
    )
    def test_anonymous_request_returns_401_with_resource_metadata(self, client):
        url = reverse("mcp_sql_endpoint")
        response = client.post(url, data=b"", content_type="application/json")
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith("Bearer ")
        assert 'resource_metadata="' in challenge


@pytest.mark.django_db
class TestMcpEndpointHappyPath:
    """End-to-end: valid bearer token + real decorator stack → 200 from the bridge.

    This pins three claims the docstring of `views/mcp_endpoint.py` makes:
    (1) the auth class gates before the bridge runs, (2) `wsgi.input` is
    re-seeded from `request.body` so the bridged ASGI app sees the request
    payload intact, (3) the bridge propagates the WSGI response back as a
    Django `HttpResponse`. The executor is mocked because the real one
    needs the `mcp_readonly` DB alias, which is out of scope for these
    unit tests (Phase 2 covers it).
    """

    @pytest.mark.parametrize(
        "content_type",
        [
            "application/json",
            # Real HTTP clients commonly send a charset suffix. Pins that
            # `MCPOAuth2Authentication.authenticate`'s body-precache gate's
            # `startswith("application/json")` check is permissive enough.
            "application/json; charset=utf-8",
        ],
    )
    def test_valid_token_reaches_bridge_and_returns_200(  # noqa: PLR0913 — six fixtures + content_type are all distinct and load-bearing
        self,
        mcp_user,
        mcp_access_token,
        mcp_mfa_on,
        mcp_active_session,
        monkeypatch,
        content_type,
    ):
        # Replace the WSGI bridge with a stub that captures the environ
        # and returns 200. This proves the auth class let the request
        # through, the bridge wrapper invoked the ASGI app, and the
        # response is round-tripped back to Django.
        seen_environs: list[dict] = []
        seen_bodies: list[bytes] = []

        def stub_wsgi_app(environ, start_response):
            seen_environs.append(dict(environ))
            seen_bodies.append(environ["wsgi.input"].read())
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"ok": true}']

        class StubASGIMiddleware:
            def __init__(self, asgi_app, loop=None):
                # `loop=` mirrors the real `a2wsgi.ASGIMiddleware` signature:
                # the view passes the process-global loop (see C1) so the
                # bridge stops leaking a loop+thread per request.
                self.asgi_app = asgi_app
                self.loop = loop

            def __call__(self, environ, start_response):
                return stub_wsgi_app(environ, start_response)

        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint.ASGIMiddleware",
            StubASGIMiddleware,
        )
        # Keep the unit hermetic: don't spin up the real process-global loop
        # just to hand it to a stub that ignores it.
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint._get_asgi_loop",
            lambda: None,
        )

        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}")
        payload = b'{"jsonrpc": "2.0", "method": "ping", "id": 1}'
        response = api_client.post(
            reverse("mcp_sql_endpoint"),
            data=payload,
            content_type=content_type,
        )

        assert response.status_code == HTTPStatus.OK
        assert response.content == b'{"ok": true}'
        assert response["Content-Type"] == "application/json"
        # `wsgi.input` was re-seeded with the request body — the bridge
        # saw the payload intact despite DRF having pre-read it.
        assert seen_bodies == [payload]
        # The auth boundary has been crossed; the bearer token must not
        # leak through to the bridged ASGI stack.
        assert "HTTP_AUTHORIZATION" not in seen_environs[0]
        assert "HTTP_COOKIE" not in seen_environs[0]


class TestInvokeWsgiApp:
    """The WSGI bridge helper re-seeds `wsgi.input` and captures headers/status."""

    def _request(self, body: bytes = b""):
        request = MagicMock()
        request.META = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "application/json",
        }
        request.body = body
        return request

    def test_round_trip(self):
        def stub_wsgi(environ, start_response):
            assert environ["wsgi.input"].read() == b"payload"
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"hello"]

        response = _invoke_wsgi_app(stub_wsgi, self._request(body=b"payload"))
        assert response.status_code == HTTPStatus.OK
        assert response.content == b"hello"
        assert response["Content-Type"] == "text/plain"

    def test_status_propagation(self):
        def stub_wsgi(environ, start_response):
            start_response("418 I'm a teapot", [])
            return [io.BytesIO(b"").read()]

        response = _invoke_wsgi_app(stub_wsgi, self._request())
        assert response.status_code == HTTPStatus.IM_A_TEAPOT

    def test_environ_allowlist_drops_unknown_http_headers(self):
        """REVIEW.md H2: switch from strip-list to allowlist so unknown
        HTTP_* (X-Api-Key, X-Token, custom corporate proxy auth, future
        Django-added headers) cannot leak through to the bridged FastMCP
        stack. Tested with a representative grab-bag of attacker-shaped
        headers plus the canonical 5 the old strip-list explicitly named."""
        seen_environs: list[dict] = []

        def stub_wsgi(environ, start_response):
            seen_environs.append(dict(environ))
            start_response("200 OK", [])
            return [b""]

        request = MagicMock()
        request.META = {
            # Allowlisted — must survive.
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "0",
            "SERVER_NAME": "example.test",
            "SERVER_PORT": "443",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "REMOTE_ADDR": "203.0.113.7",
            "HTTP_HOST": "example.test",
            "HTTP_ACCEPT": "application/json",
            "HTTP_MCP_SESSION_ID": "abc123",
            "HTTP_LAST_EVENT_ID": "evt-7",
            "wsgi.url_scheme": "https",
            # Originally-stripped (old strip-list) — must still be dropped.
            "HTTP_AUTHORIZATION": "Bearer leaked-token",
            "HTTP_COOKIE": "sessionid=leaked-cookie",
            "HTTP_X_FORWARDED_FOR": "10.0.0.1",
            "HTTP_X_FORWARDED_USER": "alice@example.com",
            "REMOTE_USER": "alice",
            # New attacker / corporate-proxy shapes — must be dropped by allowlist.
            "HTTP_X_API_KEY": "leak-via-X-Api-Key",
            "HTTP_X_TOKEN": "leak-via-X-Token",
            "HTTP_PROXY_AUTHORIZATION": "Basic leak-via-Proxy-Auth",
            "HTTP_X_REAL_IP": "10.0.0.2",
            "HTTP_X_CORPORATE_SSO": "sso-token",
            "HTTP_X_USER_EMAIL": "bob@example.com",
        }
        request.body = b""

        _invoke_wsgi_app(stub_wsgi, request)

        environ = seen_environs[0]

        # Allowlisted keys preserved (PATH_INFO + SCRIPT_NAME are rewritten
        # by the bridge; the request didn't set them so they show up as
        # `/mcp` / `/mcp/sql` rather than the original META).
        for key in (
            "REQUEST_METHOD",
            "CONTENT_TYPE",
            "REMOTE_ADDR",
            "HTTP_HOST",
            "HTTP_ACCEPT",
            "HTTP_MCP_SESSION_ID",
            "HTTP_LAST_EVENT_ID",
            "wsgi.url_scheme",
        ):
            assert key in environ, f"allowlisted {key!r} was dropped"

        # Auth/PII headers from the old strip-list still gone.
        for key in (
            "HTTP_AUTHORIZATION",
            "HTTP_COOKIE",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED_USER",
            "REMOTE_USER",
        ):
            assert key not in environ, f"{key!r} leaked through to bridge"

        # The whole point of the allowlist flip: unknown / future / custom
        # headers are dropped by default, not by enumeration.
        for key in (
            "HTTP_X_API_KEY",
            "HTTP_X_TOKEN",
            "HTTP_PROXY_AUTHORIZATION",
            "HTTP_X_REAL_IP",
            "HTTP_X_CORPORATE_SSO",
            "HTTP_X_USER_EMAIL",
        ):
            assert key not in environ, f"{key!r} leaked through — allowlist regression"


@pytest.mark.django_db
class TestMcpProfileGuard:
    """The view's guarded `request.mcp_profile` read: exercising the endpoint
    without `MCPOAuth2Authentication` in front (here: DRF force_authenticate
    bypasses the auth class entirely) must fail loudly with the invariant
    named — not as an opaque AttributeError inside FastMCP's async dispatch."""

    def test_missing_mcp_profile_raises_named_runtime_error(self, mcp_user):
        from mcp_sql.views.mcp_endpoint import mcp_endpoint
        from rest_framework.test import APIRequestFactory
        from rest_framework.test import force_authenticate

        request = APIRequestFactory().post(
            reverse("mcp_sql_endpoint"), data=b"", content_type="application/json"
        )
        force_authenticate(request, user=mcp_user)
        with pytest.raises(RuntimeError, match="mcp_profile"):
            mcp_endpoint(request)
