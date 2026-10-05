"""DOT `AuthorizationView` + the Option D session-trust issuance gate
(is_active + is_staff + MFA + an unambiguous single-profile assignment via
`resolve_profile`). See `docs/architecture.md` "OAuth surface" for the
full design rationale."""

from typing import TYPE_CHECKING
from typing import Any
from urllib.parse import urlparse

from django.core.exceptions import PermissionDenied
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings
from oauth2_provider.views import AuthorizationView

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
        # none of those render here. So injecting here reaches every page
        # this view itself shows.
        #
        # `RESOURCE_NAME` names the thing being accessed — the same identity
        # advertised in the RFC 9728 discovery metadata and shown by the MCP
        # client. `setdefault` leaves a preset value (and the error branch,
        # which ignores it) untouched.
        context.setdefault("resource_name", mcp_sql_settings.RESOURCE_NAME)
        context.setdefault("client_label", self._client_label(context))
        context.setdefault("client_destination", self._client_destination(context))
        return super().render_to_response(context, **response_kwargs)

    @staticmethod
    def _client_label(context: dict[str, Any]) -> str:
        """Trusted display name for the client requesting authorization.

        Only ever operator-authored or package-derived. A declared client
        contributes its `MCP_SQL["CLIENTS"][...]["LABEL"]`; the curated
        Application contributes its configured name. A DCR client gets NO
        label: the `client_name` it sent at registration is attacker-chosen
        free text, and rendering it here would let anyone put "Claude Code"
        (or the name of an internal tool) above the Authorize button. Its
        callback address, shown separately, is the honest identifier.
        """
        application = context.get("application")
        if application is None:
            return ""
        declared = mcp_sql_settings.clients().get(application.name)
        if declared is not None:
            return declared.label
        curated: str = mcp_sql_settings.APPLICATION_NAME
        if application.name == curated:
            return curated
        return ""

    @staticmethod
    def _client_destination(context: dict[str, Any]) -> str:
        """Where the authorization code will actually be delivered.

        The one fact on this page an attacker cannot dress up: oauthlib has
        already validated this `redirect_uri` against the Application, and the
        code is going there. `scheme://host[:port]` — enough to tell
        `https://claude.ai` from `http://localhost:8787` from someone else's
        machine, without a long path pushing the useful part off a narrow
        screen.

        Rebuilt from the parsed parts rather than sliced out of the raw
        string, so a userinfo component can never reach the page: no
        registrable redirect URI may carry one (`validation` and
        `registration._is_loopback_redirect` both refuse it), but
        `https://claude.ai@evil.example/` rendering as "https://claude.ai…"
        is precisely the misreading this line exists to prevent.

        Blank if the URI is unparseable or hostless; the template then shows
        nothing rather than a half-rendered address that could mislead.
        """
        redirect_uri = context.get("redirect_uri") or ""
        try:
            parsed = urlparse(redirect_uri)
            host, port = parsed.hostname, parsed.port
        except ValueError:
            return ""
        if not parsed.scheme or not host:
            return ""
        # `hostname` strips the brackets off an IPv6 literal, so re-add them:
        # `http://[::1]:8787/cb` would otherwise render as `http://::1:8787`,
        # corrupting the one line on this page the user is meant to check.
        # `::1` is an accepted DCR loopback host, so this is reachable.
        # `port is not None` rather than a truth test, so an explicit `:0` is
        # shown rather than silently dropped.
        shown = f"[{host}]" if ":" in host else host
        return f"{parsed.scheme}://{shown}" + (f":{port}" if port is not None else "")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            self._enforce_gate(request.user)
        # If the user is NOT authenticated, super().dispatch lets
        # LoginRequiredMixin redirect to the login URL; allauth handles
        # the login + MFA flow there and brings the user back here.
        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def _enforce_gate(user: "AbstractBaseUser") -> None:
        # `is_staff` lives on `AbstractUser` / the stock user, not the
        # `AbstractBaseUser` base a consumer may subclass directly; read it
        # defensively so a user model without the attribute is treated as
        # non-staff (fail-closed) rather than raising.
        if not (user.is_active and getattr(user, "is_staff", False)):
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
