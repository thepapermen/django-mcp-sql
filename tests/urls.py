"""Standalone root urlconf for the package's test suite.

Mounts the admin (the read-only audit admins and the usage-summary view are
reversed by `test_admin.py`) and the package's own URL surface, plus two stub
"consumer" DRF endpoints. The stubs reproduce the route names an in-tree
consumer exposes (`api:user-list`, `global_search`) so
`test_auth_class.py::TestOAuthTokenIsolationFromGlobalDRF` can pin the
isolation contract: an `mcp:sql` bearer token must stay anonymous on any
endpoint using DRF's default authentication classes — none of which read the
`Bearer` scheme — and only `MCPOAuth2Authentication` on `/mcp/sql/` may
accept it.
"""

from django.contrib import admin
from django.urls import include
from django.urls import path
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class _ConsumerStubView(APIView):
    """A stand-in for an arbitrary consumer DRF endpoint: default
    authentication classes, authenticated-only. An MCP bearer token gets no
    special handling here and must be rejected as anonymous."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"ok": True})


api_patterns = (
    [path("users/", _ConsumerStubView.as_view(), name="user-list")],
    "api",
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include(api_patterns, namespace="api")),
    path("global-search/", _ConsumerStubView.as_view(), name="global_search"),
    path("", include("mcp_sql.urls")),
]
