"""A tool surface's MCP transport: DRF bearer-auth for THAT surface →
per-request FastMCP with the consumer's tools (`surfaces.build_surface_server`)
→ the same `a2wsgi.ASGIMiddleware` bridge `/mcp/sql/` uses.

One view per surface, built by `build_surface_endpoint` and mounted by
`urls.py` from `MCP_SQL["TOOL_SURFACES"]`. It shares the SQL transport's
bridge (`views.mcp_endpoint`: the process-global loop, the lifespan wrapper,
the allowlisted environ and body re-seed) and differs from it in two
hardenings a new endpoint can have from day one:

- POST only, refused before DRF: the transport is stateless with JSON
  responses, so the Streamable HTTP GET stream and the session DELETE have
  nothing to serve. Forwarded into the bridge, a GET makes the SDK open an
  SSE stream that never ends, pinning the worker thread. Clients start with
  the `initialize` POST, which gets the 401 challenge.
- Non-atomic for every database alias (`views.mcp_endpoint._EveryAlias`):
  inside a consumer's `ATOMIC_REQUESTS` transaction, DRF's exception handler
  would roll back the gates' `MCPAuthRejectionLog` rows together with the
  401. The tools write their audit rows on pool threads in autocommit
  anyway.
"""

from collections.abc import Callable
from typing import TYPE_CHECKING
from typing import cast

from a2wsgi import ASGIMiddleware
from django.http import HttpRequest
from django.http import HttpResponse
from django.http import HttpResponseNotAllowed
from django.views.decorators.csrf import csrf_exempt
from mcp_sql.auth import surface_authentication
from mcp_sql.surfaces import SurfaceContext
from mcp_sql.surfaces import build_surface_server
from mcp_sql.views.mcp_endpoint import _EveryAlias
from mcp_sql.views.mcp_endpoint import _get_asgi_loop
from mcp_sql.views.mcp_endpoint import _invoke_wsgi_app
from mcp_sql.views.mcp_endpoint import _wrap_lifespan
from rest_framework.decorators import api_view
from rest_framework.decorators import authentication_classes
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated

if TYPE_CHECKING:
    from wsgiref.types import WSGIApplication


def build_surface_endpoint(surface_name: str) -> Callable[[HttpRequest], HttpResponse]:
    """The transport view of the surface named `surface_name`."""

    @api_view(["POST"])
    @authentication_classes([surface_authentication(surface_name)])
    @permission_classes([IsAuthenticated])
    def transport(request):
        # Bound by `SurfaceOAuth2Authentication` once every gate passed. A
        # missing binding is a wiring bug (the auth class dropped from the
        # stack), named here rather than surfacing inside FastMCP.
        surface = getattr(request, "mcp_surface", None)
        if surface is None:
            msg = (
                "request.mcp_surface is not set — it is bound by "
                "SurfaceOAuth2Authentication.authenticate, which must front "
                "this view"
            )
            raise RuntimeError(msg)
        token = request.auth
        ctx = SurfaceContext(
            user=request.user,
            surface=surface,
            token_id=str(token.pk),
            # `REMOTE_ADDR` as the SQL transport records it (the consumer's
            # real-IP middleware, if any, has already rewritten it).
            client_ip=request.META.get("REMOTE_ADDR"),
            client_redirect=token.application.redirect_uris or "",
        )
        server = build_surface_server(ctx)
        wsgi_app = cast(
            "WSGIApplication",
            ASGIMiddleware(
                _wrap_lifespan(server.streamable_http_app()), loop=_get_asgi_loop()
            ),
        )
        return _invoke_wsgi_app(
            wsgi_app, request, script_name="/" + surface.path.rstrip("/")
        )

    @csrf_exempt
    def endpoint(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        response: HttpResponse = transport(request)
        return response

    endpoint._non_atomic_requests = _EveryAlias()  # type: ignore[attr-defined]
    endpoint.surface_name = surface_name  # type: ignore[attr-defined]
    return endpoint
