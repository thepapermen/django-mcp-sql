"""DOT `AuthorizationView` + the Option D session-trust issuance gate
(is_active + is_staff + MFA + an unambiguous single-profile assignment via
`resolve_profile`). See `docs/architecture.md` "OAuth surface" for the
full design rationale."""

from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied
from oauth2_provider.views import AuthorizationView

from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser


class MCPAuthorizationView(AuthorizationView):
    """`AuthorizationView` + the MCP issuance gate."""

    # Package-owned consent template (overrides DOT's
    # `oauth2_provider/authorize.html`). Named under `mcp_sql/` so a
    # consumer can re-theme it via their own template dir regardless of
    # app ordering, and so it never collides with DOT's bundled template.
    template_name = "mcp_sql/authorize.html"

    def render_to_response(self, context, **response_kwargs):
        # `render_to_response` is the single chokepoint for the only two
        # template renders this view performs: the consent page (`get`)
        # and the fatal-client-error page (`error_response` when oauthlib
        # refuses to redirect — unknown `client_id` / untrusted
        # `redirect_uri`). Every other outcome is a redirect (recoverable
        # OAuth errors bounce back to the client, success carries the auth
        # code, login / `prompt=none` 302), and a failed issuance gate
        # raises `PermissionDenied` rendered by the consumer's 403 page —
        # none of those render here. So injecting `resource_name` here
        # reaches every page this view itself shows.
        #
        # DOT's default consent template shows `application.name`, which
        # for every dynamically-registered (RFC 7591) client is the opaque
        # `mcp-sql-<token>` — meaningless to the human approving the grant.
        # `RESOURCE_NAME` is the same identity advertised in the RFC 9728
        # discovery metadata and shown by the MCP client. `setdefault`
        # leaves a preset value (and the error branch, which ignores it)
        # untouched.
        context.setdefault("resource_name", mcp_sql_settings.RESOURCE_NAME)
        return super().render_to_response(context, **response_kwargs)

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            self._enforce_gate(request.user)
        # If the user is NOT authenticated, super().dispatch lets
        # LoginRequiredMixin redirect to the login URL; allauth handles
        # the login + MFA flow there and brings the user back here.
        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def _enforce_gate(user: "AbstractBaseUser") -> None:
        if not (user.is_active and user.is_staff):
            msg = (
                "MCP SQL access requires an active staff account. "
                "Contact an administrator."
            )
            raise PermissionDenied(msg)
        if not mcp_sql_settings.MFA_CHECKER(user):
            msg = (
                "MCP SQL access requires a verified TOTP device. Set up "
                "two-factor authentication and retry."
            )
            raise PermissionDenied(msg)
        outcome = mcp_sql_settings.resolve_profile(user)
        if outcome is ResolutionOutcome.NO_PERM:
            msg = (
                "MCP SQL access requires an MCP profile assignment. Ask an "
                "administrator to add you to an MCP profile group."
            )
            raise PermissionDenied(msg)
        if outcome is ResolutionOutcome.AMBIGUOUS_PROFILE:
            msg = (
                "Your account is assigned to more than one MCP profile, which "
                "is not allowed. Ask an administrator to leave you in exactly "
                "one MCP profile group."
            )
            raise PermissionDenied(msg)
