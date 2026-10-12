"""URL configuration for the example project.

Mounts:
- `/admin/` — Django admin (create users, assign the `mcp_sql.use_mcp_session`
  permission, inspect the audit tables).
- `/` — everything `mcp_sql` exposes: `/o/authorize/`, `/o/token/`,
  `/o/revoke_token/`, `/o/register`, `/mcp/sql/`,
  `/.well-known/oauth-protected-resource/mcp/sql`,
  `/.well-known/oauth-authorization-server/o`.
"""

from django.contrib import admin
from django.urls import include
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("mcp_sql.urls")),
]
