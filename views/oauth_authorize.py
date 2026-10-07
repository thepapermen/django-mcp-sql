"""DOT `AuthorizationView` + the Option D session-trust issuance gate
(is_active + MFA + an unambiguous single-profile assignment via
`resolve_profile`). See `docs/architecture.md` "OAuth surface" for the
full design rationale."""

from typing import TYPE_CHECKING
from typing import Any
from urllib.parse import urlparse

from django.core.exceptions import PermissionDenied
from mcp_sql.audience import foreign_resource
from mcp_sql.audience import invalid_target_error
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings
from oauth2_provider.exceptions import FatalClientError
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.models import get_application_model
from oauth2_provider.views import AuthorizationView
from oauthlib.common import Request as OAuthlibRequest
from oauthlib.oauth2.rfc6749 import errors as oauth2_errors
from oauthlib.uri_validate import is_absolute_uri

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
        # `redirect_uri` — or when this view's own re-validation in
        # `error_response` / `form_valid` does). Every other outcome is a
        # redirect (recoverable OAuth errors bounce back to the client,
        # success carries the auth
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

        The validated redirect's `scheme://host[:port]`, so it cannot be
        dressed up as a different target: oauthlib has already validated this
        `redirect_uri` against the Application, and the code is going there.
        (Who chose it varies: a DCR client picked its own loopback address; a
        declared client's host is the operator's.) Enough to tell
        `https://claude.ai` from `http://localhost:8787` from someone else's
        machine, without a long path pushing the useful part off a narrow
        screen. It names the provider or machine, NOT whose account there: a
        shared provider callback (Claude.ai's, or any ChatGPT connector's)
        renders the same for an attacker's own connector, so the template's
        "Only continue if you started this from there" is the real check.

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

    def form_valid(self, form):
        # DOT's `form_valid` starts with `Application.objects.get(client_id=
        # <hidden field>)`, so a consent POST naming a client that does not
        # exist was a 500 (`DoesNotExist`). Render the fatal-client error
        # page instead, as DOT does for an unknown client on the GET. (A NUL
        # never gets here: Django's form validation rejects it, and
        # `dispatch` refuses it before that.)
        client_id = form.cleaned_data.get("client_id") or ""
        if not self._is_known_client_id(client_id):
            return self._unknown_client_response()
        # The RFC 8707 `resource` check of the GET (see
        # `validate_authorization_request`), again on what the POST carries:
        # the form's hidden field (from DOT 3.4, one whitespace-joined value,
        # blank when the GET had none) and the query string the form posts
        # back to, which oauthlib reads as well. Before anything else DOT
        # does, Cancel included, so no grant is stored for a foreign
        # resource; `error_response` re-validates the form's `redirect_uri`
        # before redirecting the error.
        #
        # From DOT 3.4 the two must also agree. The form's value is what DOT
        # puts on the grant; with that field blank, oauthlib's reading of the
        # query string (one plain string, not a list) reached the grant
        # instead, and DOT's model refused it with a 500 (ledger F55). A
        # browser posts the page's own query back, so a real consent POST
        # always matches. (Below 3.4 the form has no such field and DOT
        # ignores both.)
        query_resources = self.request.GET.getlist("resource")
        resources = query_resources + [
            value
            for field in self.request.POST.getlist("resource")
            for value in field.split()
        ]
        disagree = (
            "resource" in form.fields
            and bool(query_resources)
            and (form.cleaned_data.get("resource") or "").split() != query_resources
        )
        if disagree or foreign_resource(self.request, resources) is not None:
            error = OAuthToolkitError(
                error=invalid_target_error(
                    self.request, state=form.cleaned_data.get("state")
                ),
                redirect_uri=form.cleaned_data.get("redirect_uri"),
            )
            # `filter().first()`, not `get()`: a client deleted since the
            # check above (an operator removing it mid-request) would
            # otherwise be a `DoesNotExist` 500.
            application = (
                get_application_model().objects.filter(client_id=client_id).first()
            )
            if application is None:
                return self._unknown_client_response()
            return self.error_response(error, application)
        return super().form_valid(form)

    def _unknown_client_response(self):
        """The fatal-client error page for a `client_id` that names no
        Application, as DOT renders it for an unknown client on the GET."""
        return super().error_response(
            FatalClientError(error=oauth2_errors.InvalidClientIdError()),
            application=None,
        )

    def validate_authorization_request(self, request):
        """DOT's validation of the authorization request, then the RFC 8707
        `resource` check: every `resource` must be this server's MCP endpoint
        as discovery advertises it (`audience.foreign_resource`), else
        `invalid_target`.

        From DOT 3.4 a `resource` is stored on the grant and the token, and
        DOT audience-checks the token against `/mcp/sql/`: any other value
        minted a token that endpoint always refuses with a bare 401. Refused
        here instead, on every DOT version (below 3.4 DOT ignores
        `resource`; the answer is the same). Raised after oauthlib has
        validated `client_id` and `redirect_uri`, through DOT's own handling
        of a failed validation (`error_response`, which re-validates the
        redirect anyway), so the error goes back to the client's registered
        redirect with its `state`, and no grant exists. Every DOT path that
        validates a request comes through here: `get`, and from DOT 3.4 the
        anonymous `prompt=none` / `prompt=create` handling too.
        """
        scopes, credentials = super().validate_authorization_request(request)
        if foreign_resource(request, request.GET.getlist("resource")) is not None:
            raise OAuthToolkitError(
                error=invalid_target_error(request, state=credentials.get("state")),
                redirect_uri=credentials.get("redirect_uri"),
            )
        return scopes, credentials

    def error_response(self, error, application, **kwargs):
        # DOT redirects every non-fatal error to `error.redirect_uri`. On the
        # consent POST that is the form's hidden `redirect_uri`, and two
        # errors are raised BEFORE oauthlib has validated it: Cancel's
        # `access_denied` (`create_authorization_response(allow=False)`) and
        # an invalid `resource`'s `invalid_target`. A tampered form could so
        # send the user's browser, `state` and all, to any URL. Re-validate
        # the target against the client exactly as oauthlib would before ANY
        # error redirect, and render the error page when it fails. On the
        # paths where oauthlib already validated it this is a no-op.
        if not isinstance(error, FatalClientError):
            target = error.oauthlib_error.redirect_uri
            client_id = (
                application.client_id
                if application is not None
                else self.request.GET.get("client_id", "")
            )
            if not self._is_registered_redirect(client_id, target):
                error = FatalClientError(
                    error=oauth2_errors.MismatchingRedirectURIError()
                )
        return super().error_response(error, application, **kwargs)

    @staticmethod
    def _is_known_client_id(client_id: str) -> bool:
        if not client_id:
            return False
        return bool(
            get_application_model().objects.filter(client_id=client_id).exists()
        )

    def _is_registered_redirect(self, client_id: str, redirect_uri: Any) -> bool:
        """True iff oauthlib would accept `redirect_uri` for `client_id`.

        The same checks, through the configured validator class, that
        oauthlib's `_handle_redirects` runs on the GET: an absolute URI,
        and `validate_redirect_uri` (DOT's registered-URI matching, plus this
        package's declared-client prefix rules), after `validate_client_id`
        has loaded the client. Anything unexpected counts as not registered.
        """
        if (
            not client_id
            or not isinstance(redirect_uri, str)
            or not redirect_uri
            or not is_absolute_uri(redirect_uri)
        ):
            return False
        validator = self.get_validator_class()()
        oauthlib_request = OAuthlibRequest("")
        try:
            return bool(
                validator.validate_client_id(client_id, oauthlib_request)
                and validator.validate_redirect_uri(
                    client_id, redirect_uri, oauthlib_request
                )
            )
        except Exception:  # noqa: BLE001 — fail closed to the error page
            return False

    def dispatch(self, request, *args, **kwargs):
        # Pin DOT's `approval_prompt` to "force", whatever the query string or
        # `OAUTH2_PROVIDER["REQUEST_APPROVAL_PROMPT"]` says. DOT's `get()`
        # reads `request.GET.get("approval_prompt", <setting>)`, and on "auto"
        # it skips the consent page and issues a code on a plain GET whenever
        # the user already holds an unexpired token for the same Application.
        # A declared client is ONE Application shared by every account at the
        # provider (`mcp-sql-cloud.claude`), so a staff user who connected
        # Claude.ai would be redirected, no page shown, to the shared callback
        # with a code bound to an attacker's PKCE challenge and `state` just
        # by opening a link carrying `approval_prompt=auto` (what the provider
        # does with it next is outside this server). `skip_authorization=False` is
        # supposed to make consent an explicit POST every time; this keeps it
        # so, for every client kind (the curated `mcp-sql` row included,
        # since migration 0015). The parameter is DOT-specific and no MCP
        # client is known to send it; what the pin does take away, on
        # purpose, is a consumer-wide `REQUEST_APPROVAL_PROMPT = "auto"` for
        # this view — same-client re-authorization before the token expires
        # now shows the consent page too.
        query = request.GET.copy()
        query["approval_prompt"] = "force"  # replaces every value, if repeated
        request.GET = query
        # A NUL never names a client. On the GET, DOT hands it to Postgres in
        # its client lookup (`validate_authorization_request`), which raises
        # `DataError`: a 500 on every retry. Refuse it here with the
        # fatal-client error page, before any lookup (and before the gate,
        # which queries the DB too). On the consent POST Django's form
        # validation already rejects a NUL (the page is re-rendered, a 200);
        # checking the POST too is defence in depth, and gives both methods
        # the same answer.
        client_ids = request.GET.getlist("client_id")
        if request.method == "POST":
            client_ids += request.POST.getlist("client_id")
        if any("\x00" in value for value in client_ids):
            return super().error_response(
                FatalClientError(error=oauth2_errors.InvalidClientIdError()),
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
        # No `is_staff` requirement: the explicit profile assignment below is
        # the access gate, so a staff flag would only duplicate it.
        if not user.is_active:
            msg = "MCP SQL access requires an active account. Contact an administrator."
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
