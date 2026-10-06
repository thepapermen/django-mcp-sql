"""DOT's `TokenView` / `RevokeTokenView` on the narrow `MCPServer`. See
`oauth_server.py` for what the server admits and why."""

from mcp_sql.oauth_server import MCPServerViewMixin
from oauth2_provider.views import RevokeTokenView
from oauth2_provider.views import TokenView


class MCPTokenView(MCPServerViewMixin, TokenView):
    """`/o/token/` (the authorization-code exchange) on `MCPServer`."""


class MCPRevokeTokenView(MCPServerViewMixin, RevokeTokenView):
    """`/o/revoke_token/` (RFC 7009) on `MCPServer`."""
