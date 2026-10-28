"""DOT `AuthorizationView` + the Option D session-trust issuance gate
(is_active + MFA + an unambiguous single-profile assignment via
`resolve_profile` for `mcp:sql`, or the surface's permission for a tool
surface's scope). See `docs/architecture.md` "OAuth surface" for the full
design rationale."""

from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings
from oauth2_provider.scopes import get_scopes_backend
from oauth2_provider.views import AuthorizationView

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.http import HttpRequest
    from mcp_sql.conf import ToolSurface


def _requested_scopes(request: "HttpRequest") -> list[str]:
    """The scopes this authorization asks for, as DOT will issue them.

    The consent POST carries them in the form's `scope` field (what DOT
    hands oauthlib), the GET in the query string; without one, oauthlib
    falls back to the scopes backend's defaults, and so does this. A
    repeated `scope` parameter is refused: Django and oauthlib both keep
    the last value today, but the gate must not depend on two parsers
    agreeing about an ambiguous request. (`MCPOAuth2Validator`'s
    `save_authorization_code` re-checks what is actually issued.)
    """
    params = request.POST if request.method == "POST" else request.GET
    values = params.getlist("scope")
    if len(values) > 1:
        msg = "The scope parameter must be sent once."
        raise PermissionDenied(msg)
    if values:
        return values[0].split()
    return list(
        get_scopes_backend().get_default_scopes(application=None, request=request)
    )


class MCPAuthorizationView(AuthorizationView):
    """`AuthorizationView` + the MCP issuance gate."""

    # Package-owned consent template (overrides DOT's
    # `oauth2_provider/authorize.html`). Named under `mcp_sql/` so a
    # consumer can re-theme it via their own template dir regardless of
    # app ordering, and so it never collides with DOT's bundled template.
    template_name = "mcp_sql/authorize.html"

    # The tool surface this authorization is for (set by `dispatch` for an
    # authenticated user); None for `/mcp/sql/`.
    _surface: "ToolSurface | None" = None

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
        # discovery metadata and shown by the MCP client — the tool
        # surface's own when the authorization is for one. `setdefault`
        # leaves a preset value (and the error branch, which ignores it)
        # untouched.
        resource_name = (
            self._surface.resource_name
            if self._surface is not None
            else mcp_sql_settings.RESOURCE_NAME
        )
        context.setdefault("resource_name", resource_name)
        return super().render_to_response(context, **response_kwargs)

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            self._surface = self._enforce_gate(request.user, _requested_scopes(request))
        # If the user is NOT authenticated, super().dispatch lets
        # LoginRequiredMixin redirect to the login URL; allauth handles
        # the login + MFA flow there and brings the user back here.
        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def _enforce_gate(
        user: "AbstractBaseUser", scopes: list[str] | None = None
    ) -> "ToolSurface | None":
        """Deny (`PermissionDenied`) unless `user` may be issued `scopes`.

        Exactly one tool surface's scope → that surface's gate (returns the
        surface); anything else → the SQL surface's gate (returns None). A
        malformed set (two scopes, an unknown one) therefore takes the SQL
        gate, and the validator's `validate_scopes` refuses it afterwards.
        `scopes=None` is the SQL gate.
        """
        surface = (
            mcp_sql_settings.surface_for_scope(scopes[0])
            if scopes and len(set(scopes)) == 1
            else None
        )
        label = surface.resource_name if surface is not None else "MCP SQL"
        # No `is_staff` requirement: the explicit profile (or surface)
        # assignment below is the access gate, so a staff flag would only
        # duplicate it.
        if not user.is_active:
            msg = (
                f"{label} access requires an active account. Contact an administrator."
            )
            raise PermissionDenied(msg)
        if not mcp_sql_settings.MFA_CHECKER(user):
            msg = (
                f"{label} access requires a verified TOTP device. Set up "
                "two-factor authentication and retry."
            )
            raise PermissionDenied(msg)
        if surface is not None:
            # A surface is granted by its own permission alone — explicit
            # assignment, superuser-blind (`holds_surface`) — independent of
            # any SQL profile.
            if not mcp_sql_settings.holds_surface(user, surface):
                msg = (
                    f"{label} access requires membership in the "
                    f"{surface.group_name!r} group. Ask an administrator."
                )
                raise PermissionDenied(msg)
            return surface
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
        return None
