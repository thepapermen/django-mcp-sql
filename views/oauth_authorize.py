"""DOT `AuthorizationView` on the narrow `MCPServer` + the Option D
session-trust issuance gate (is_active + is_staff + MFA + an unambiguous
single-profile assignment via `resolve_profile`). See `docs/architecture.md`
"OAuth surface" for the full design rationale."""

import re
from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.oauth import has_control_character
from mcp_sql.oauth_server import MCPServerViewMixin
from oauth2_provider.exceptions import FatalClientError
from oauth2_provider.views import AuthorizationView
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.http import HttpRequest

# RFC 7636 §4.2: a code_challenge is 43-128 characters of the unreserved set
# (an S256 challenge is exactly 43). It is stored in DOT's
# `Grant.code_challenge` (varchar(128)); anything longer raised a 500.
_CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
# DOT stores `nonce` in `Grant.nonce` (varchar(255)).
_NONCE_MAX_LENGTH = 255


def _authorize_parameter_problem(request: "HttpRequest") -> str | None:
    """Why this authorize request's parameters cannot reach DOT's `Grant`
    insert, or `None` if they can."""
    if has_control_character(request.GET, request.POST):
        return "Control character in a request parameter."
    for params in (request.GET, request.POST):
        challenges = params.getlist("code_challenge")
        if any(not _CODE_CHALLENGE_RE.fullmatch(c) for c in challenges):
            return "code_challenge must be 43-128 characters of [A-Za-z0-9-._~]."
        if any(len(n) > _NONCE_MAX_LENGTH for n in params.getlist("nonce")):
            return f"nonce must be at most {_NONCE_MAX_LENGTH} characters."
    return None


class MCPAuthorizationView(MCPServerViewMixin, AuthorizationView):
    """`AuthorizationView` + the MCP issuance gate, on `MCPServer` (the
    `code` response type only, `S256` PKCE only)."""

    # Package-owned consent template (overrides DOT's
    # `oauth2_provider/authorize.html`). Named under `mcp_sql/` so a
    # consumer can re-theme it via their own template dir regardless of
    # app ordering, and so it never collides with DOT's bundled template.
    template_name = "mcp_sql/authorize.html"

    def render_to_response(self, context, **response_kwargs):
        # `render_to_response` is the single chokepoint for every template
        # render this view performs: the consent page (`get`), its
        # re-render when the consent POST's form is invalid (DOT's
        # `form_invalid`, whose context has no `application`), and the
        # fatal-client-error page (`error_response` when oauthlib refuses
        # to redirect — unknown `client_id` / untrusted `redirect_uri` —
        # or when `dispatch` screens out a parameter). Every other outcome
        # is a redirect (recoverable
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
        # Parameters DOT would store raw on the `Grant` row (code_challenge,
        # nonce, resource, ...) are screened first, on the query string and
        # the consent POST alike: a NUL or an over-long value otherwise
        # reached the INSERT and raised an uncaught 500 (DataError). The
        # redirect_uri is not validated yet, so this is the fatal error page
        # (400), never a redirect.
        problem = _authorize_parameter_problem(request)
        if problem is not None:
            self.oauth2_data = {}
            return self.error_response(
                FatalClientError(error=InvalidRequestError(description=problem)),
                application=None,
            )
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
