"""URL surface for the MCP read-only SQL pipeline.

Mounted from the project's root urlconf via `include("mcp_sql.urls")`.
Carries the seven routes the subsystem owns:

- 3 curated DOT URLs at `/o/` (authorize gated by `MCPAuthorizationView`,
  token, revoke). `/o/applications/`, `/o/authorized_tokens/`,
  `/o/introspect/`, `/o/userinfo/` are deliberately absent — no admin /
  introspection / userinfo surface is exposed.
- 1 RFC 7591 dynamic client registration endpoint at `/o/register`.
- 1 MCP transport endpoint at `/mcp/sql/` (plus a slash-less alias).
- 2 OAuth 2.0 discovery URLs (RFC 9728 + RFC 8414) at `.well-known/...`
  (the RFC 9728 one likewise served under both spellings of the resource
  path — see the comment on those routes).

Keeping the routes here makes the entire surface mount/unmountable from
the project urlconf in one `include()` line. The URL names are the stable
contract every `reverse(...)` call site depends on.
"""

from django.urls import path
from mcp_sql.decorators import cap_request_body
from mcp_sql.views.discovery import authorization_server_metadata
from mcp_sql.views.discovery import protected_resource_metadata
from mcp_sql.views.mcp_endpoint import mcp_endpoint
from mcp_sql.views.oauth_authorize import MCPAuthorizationView
from mcp_sql.views.registration import register_client
from oauth2_provider import views as oauth2_views

urlpatterns = [
    # Curated subset of django-oauth-toolkit URLs. Each OAuth endpoint is
    # wrapped in `cap_request_body` (64 KiB) — their bodies are sub-KB
    # form/JSON, and `/o/token/` + `/o/register` are anonymous, so the cap
    # closes an anonymous memory-amplification vector the consumer's global
    # upload limit would otherwise leave open. `/mcp/sql/` is capped
    # separately (1 MiB) in the auth class, since its body carries the SQL.
    path(
        "o/authorize/",
        cap_request_body()(MCPAuthorizationView.as_view()),
        name="authorize",
    ),
    path(
        "o/token/", cap_request_body()(oauth2_views.TokenView.as_view()), name="token"
    ),
    path(
        "o/revoke_token/",
        cap_request_body()(oauth2_views.RevokeTokenView.as_view()),
        name="revoke-token",
    ),
    # RFC 7591 dynamic client registration. Required by Claude Code's MCP
    # SDK; anonymous POST gated by loopback-only redirect_uris and
    # `skip_authorization=False` so dynamically-registered clients still
    # hit the consent screen (prevents silent-consent token theft).
    path(
        "o/register",
        cap_request_body()(register_client),
        name="oauth_dynamic_client_registration",
    ),
    # MCP read-only SQL transport endpoint. Bearer-auth via
    # `MCPOAuth2Authentication`; CSRF is exempt via decorator on the view.
    # `/mcp/sql/` is canonical (named — what `reverse()` builds from; the RFC
    # 9728 `resource` echoes whichever spelling the client used, see the
    # discovery routes below); the slash-less alias accepts clients that
    # normalise the trailing slash off the connector URL (Claude.ai's web
    # connector POSTs to `/mcp/sql`). Without it, `APPEND_SLASH` can't
    # 301-redirect a POST (that would drop the body) and Django 500s instead
    # of serving the transport.
    path("mcp/sql/", mcp_endpoint, name="mcp_sql_endpoint"),
    path("mcp/sql", mcp_endpoint),
    # OAuth 2.0 discovery surface (RFC 9728 + RFC 8414). Path layout is
    # spec-mandated: RFC 9728 inserts `.well-known/oauth-protected-resource`
    # after the host, then appends the resource path (`/mcp/sql`); RFC 8414
    # §3.1 suffixes the AS metadata path with the issuer's path component
    # (`/o`, matching DOT's mount).
    #
    # Both spellings of the resource path are served, mirroring the transport
    # alias above, because clients disagree on trailing-slash normalisation
    # and RFC 9728 §3.3 makes that disagreement fatal: the `resource` value
    # must equal the identifier the client built the metadata URL from, or the
    # client MUST discard the document. The view echoes whichever spelling was
    # used (`discovery._resource_identifier`). The named route is the
    # slash-less one; `authenticate_header` reverses it and appends the slash
    # when the request that drew the 401 had one, so the `resource_metadata`
    # pointer always leads to the document whose `resource` equals the URL the
    # client requested (RFC 9728 §3.3's second clause).
    path(
        ".well-known/oauth-protected-resource/mcp/sql",
        protected_resource_metadata,
        name="mcp_sql_protected_resource_metadata",
    ),
    path(
        ".well-known/oauth-protected-resource/mcp/sql/",
        protected_resource_metadata,
    ),
    path(
        ".well-known/oauth-authorization-server/o",
        authorization_server_metadata,
        name="oauth_authorization_server_metadata",
    ),
]
