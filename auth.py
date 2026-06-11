"""DRF auth class + 413 body cap for the `/mcp/sql/` endpoint.

`MCPOAuth2Authentication` re-runs every issuance-time gate on every
request (scope, application-name match, is_active+is_staff, MFA,
single-profile assignment via `resolve_profile`, live Django session).
Mounted on the MCP
view only — never in DRF's `DEFAULT_AUTHENTICATION_CLASSES`. See
`docs/architecture.md` "OAuth surface" + "Watch out" for
Option D session-trust, the body-cap rationale, and the isolation
contract pinned by `tests/test_auth_class.py::TestOAuthTokenIsolationFromGlobalDRF`.

Every **resolved-user** rejection in `authenticate` (the six defense-
in-depth gates below `super().authenticate(...)` returns a user/token
pair) writes one `MCPAuthRejectionLog` row via `_audit_rejection`.
Anonymous / bad-token traffic is deliberately NOT audited at this
layer — that high-volume noise floor goes through django-axes-on-Redis
(Phase 4), not the default DB, to avoid write amplification and audit-
table bloat under sustained probing. Separate audit table from
`MCPQueryLog` by design: auth rejections happen BEFORE a query is
evaluated, and conflating them would pollute Phase 4's daily-volume
"queries per user" aggregation with rejection counts. The audit write
is best-effort: a DB failure during `MCPAuthRejectionLog.objects.create`
is `logger.exception`-logged but does not mask the underlying
`AuthenticationFailed` — the agent always sees the rejection.
"""

import logging

from django.apps import apps
from django.core.cache import cache
from django.db import DatabaseError
from django.urls import reverse
from django.utils import timezone
from mcp_sql import throttle
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_config
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from mcp_sql.decorators import normalize_content_length
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.schemas import AuthRejectionReason
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

# How long to suppress duplicate "ambiguous profile" WARNINGs per user, so a
# retrying agent (or a hot client) does not respam logs for one misassignment.
# The paging Sentry ERROR already fired once at assignment time (signals.py).
_AMBIGUOUS_WARN_DEDUP_SECONDS = 3600

# `/mcp/sql/` carries JSON-RPC tool calls whose body holds the agent's SQL
# query. Real-world queries are sub-kilobyte, but a pathological literal
# `IN (...)` list can run to several hundred KB, so the cap is set high
# enough never to clip a legitimate query: 1 MiB. It is still a tight,
# package-owned bound — without it the body would be limited only by the
# consumer's global `DATA_UPLOAD_MAX_MEMORY_SIZE`, which the library cannot
# assume is small — so an authenticated-but-compromised token holder cannot
# force a much larger body into a worker via the auth-class body precache.
# Note this cap is also the only bound on parser *input* size — sqlglot
# parses in-worker, before any DB `statement_timeout` applies — so a 1 MiB
# adversarial query (authed) is the accepted tradeoff for SQL headroom; a
# parse-time guard is where to harden if that ever surfaces.
# The anonymous OAuth endpoints carry only sub-KB form/JSON and get their
# own tighter cap via `decorators.cap_request_body`.
MCP_REQUEST_BODY_MAX_BYTES = 1024 * 1024


class PayloadTooLarge(APIException):
    """413 response for oversize bodies on `/mcp/sql/`.

    Defined here so the auth class can raise a typed DRF exception that
    the framework maps to a 413 status (vs. the built-in 401 / 403 / 429).
    Raised BEFORE the body force-cache in `MCPOAuth2Authentication.authenticate`
    so an oversize POST never materialises in memory.
    """

    status_code = 413
    default_detail = (
        f"Request body exceeds the /mcp/sql/ cap of {MCP_REQUEST_BODY_MAX_BYTES} bytes."
    )
    default_code = "payload_too_large"


def _enforce_body_size_cap(django_request) -> None:
    """Raise `PayloadTooLarge` if the declared `CONTENT_LENGTH` exceeds the cap.

    Read the header BEFORE force-caching `request.body` so an oversize POST
    never enters Python memory. `CONTENT_LENGTH` is attacker-controllable, but
    a lying header is self-defeating: over-declaring is 413'd here, and
    under-declaring just truncates the sender's own body via Django's
    `LimitedStream`. Parsing/normalisation is shared with the OAuth-endpoint
    cap via `decorators.normalize_content_length`. Body-less GETs (no header)
    fall through naturally.
    """
    if normalize_content_length(django_request) > MCP_REQUEST_BODY_MAX_BYTES:
        raise PayloadTooLarge


class MCPOAuth2Authentication(OAuth2Authentication):
    """OAuth2 bearer auth + per-request user-state revalidation."""

    def authenticate_header(self, request):
        # MCP authorization spec (and Claude Code's HTTP MCP transport)
        # require the 401 challenge to advertise the RFC 9728 Protected
        # Resource Metadata URL via the `resource_metadata` parameter.
        # Without it the client receives a clean 401 but has nowhere to
        # discover the authorization endpoint and the flow stalls.
        # The absolute URL is built per request so the value is correct
        # behind any reverse proxy / hostname.
        metadata_url = request.build_absolute_uri(
            reverse("mcp_sql_protected_resource_metadata")
        )
        return f'Bearer realm="api", resource_metadata="{metadata_url}"'

    def authenticate(self, request):  # noqa: C901, PLR0912 — linear defense-in-depth chain reads better than extracted helpers
        # DOT's parent class calls `oauthlib_core.verify_request`, which
        # extracts the body via `request.POST.items()`. For application/json
        # request bodies (the MCP wire protocol's content type), DRF's
        # JSONParser consumes the body stream as a side effect, leaving the
        # downstream `request.body` access in `_invoke_wsgi_app` raising
        # `RawPostDataException`. Force-cache the raw bytes on the underlying
        # Django HttpRequest BEFORE super() runs so the MCP view can still
        # re-seed `wsgi.input` from `request.body`. Gated to body-carrying
        # JSON requests: this auth class is mounted ONLY on `/mcp/sql/`,
        # which is JSON-RPC and rejects non-JSON content types via DRF's
        # parser negotiation — so the JSON gate is exhaustive for paths
        # that can actually reach the bridge, and the explicit method
        # whitelist keeps GET/HEAD from flipping `_read_started=True` for
        # free.
        django_request = getattr(request, "_request", request)
        _enforce_body_size_cap(django_request)
        # `/mcp/sql/` is JSON-RPC POST only (DRF parser negotiation rejects
        # non-JSON content types upstream of this code), so we always have
        # a body to materialise. The `hasattr` guard makes the force-cache
        # idempotent — DRF body negotiation re-runs would otherwise raise
        # `RawPostDataException` when the bridged WSGI worker re-reads.
        if not hasattr(django_request, "_body"):
            _ = django_request.body

        # DOT 3.2.0's `OAuth2Authentication.authenticate()` returns `None`
        # on bad / expired / unknown / revoked tokens (it does NOT raise —
        # it sets `request.oauth2_error` and yields the anonymous result).
        # The only paths from super() that DO raise are `SuspiciousOperation`
        # (hex-encoding bug) and re-raised `ValueError` from oauthlib —
        # both indicate malformed transport, not credential probing; we
        # let them bubble.
        #
        # We deliberately do NOT INSERT an `MCPAuthRejectionLog` row on
        # the `result is None` path: anonymous and bad-token traffic are
        # high-volume noise floor that, audited per-request, would write-
        # amplify the default DB and bloat the audit table under sustained
        # probing. The signal lives in a single Redis counter instead
        # (`throttle.record_attempt`, scope `"bad_token"`): the per-IP
        # fixed-window counter that drives the silent IP block below, plus
        # its one-shot threshold-crossing WARNING. No global cross-IP
        # counter is kept — the botnet-probe alert it would have fed was
        # dropped as low-value (the silent block + the WARNING are the whole
        # response). `MCPAuthRejectionLog` is reserved for **resolved-user**
        # denials — every row in it names a real user whose valid-shape
        # token failed a defense-in-depth gate.
        #
        # `has_auth_header` distinguishes "actual bearer-probe attempt"
        # from "anonymous traffic just hitting the endpoint": only the
        # former increments the counter and trips the block, so probe
        # intent is what the noise floor reflects (not health checks,
        # not discovery crawlers).
        #
        # Silent IP block (`throttle`, scope `"bad_token"`): once a probing
        # IP crosses `MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]` within
        # `BAD_TOKEN_IP_WINDOW_SECONDS`, every subsequent bearer-bearing
        # request from it short-circuits BEFORE DOT's DB SELECT. The wire
        # response (`return None` → DRF renders 401) is indistinguishable
        # from "bad token" or "no auth header" — an attacker probing the
        # guessable `/mcp/sql/` URL cannot fingerprint the block, gets no
        # `Retry-After` to optimise against, and pays the same wire cost as
        # any other 401 while we pay roughly 5x less per-request (one Redis
        # GET vs DOT's AccessToken SELECT + a counter INCR). The window TTL
        # is the operator's release mechanism — no admin UI, no manual
        # unblock. The IP is `REMOTE_ADDR` (the proxy-stripped client IP);
        # see `throttle`'s module docstring for the edge-proxy invariant
        # that keying decision rests on.
        has_auth_header = bool(request.headers.get("authorization"))
        ip = request.META.get("REMOTE_ADDR") or "unknown"
        cfg = mcp_sql_config()
        threshold = cfg["BAD_TOKEN_IP_THRESHOLD"]
        if has_auth_header and throttle.is_ip_blocked(
            ip, scope="bad_token", threshold=threshold
        ):
            return None
        result = super().authenticate(request)
        if result is None:
            if has_auth_header:
                throttle.record_attempt(
                    ip,
                    scope="bad_token",
                    window=cfg["BAD_TOKEN_IP_WINDOW_SECONDS"],
                    threshold=threshold,
                )
            return None
        user, token = result

        # Defense-in-depth: re-check every gate the issuance flow checked.
        # A revoked permission, removed MFA device, or deactivated account
        # invalidates outstanding tokens immediately (without waiting for
        # the next 6h expiry).

        # Application binding: the validator pins issuance to the `mcp-sql*`
        # name prefix (the curated `mcp-sql` Application from migration 0005
        # plus any RFC 7591 dynamically-registered `mcp-sql-<token>` clients),
        # but a token minted by any other path (admin UI,
        # `AccessToken.objects.create()` in a shell, a second OAuth use case
        # ever being added) would bypass that gate. Re-verify on every
        # request — `mcp:sql` scope is necessary but not sufficient; the
        # token MUST also be tied to an MCP-purpose Application.
        # DOT enforces a non-nullable FK to `Application` on every token,
        # so `token.application` is always present here. The check below
        # only validates the *identity* of that Application.
        if not is_mcp_application_name(token.application.name):
            msg = "Token was not issued by an mcp-sql Application."
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.BAD_APPLICATION,
                error=msg,
                user=user,
                token=token,
            )
            raise exceptions.AuthenticationFailed(msg)

        scopes = (token.scope or "").split()
        if mcp_sql_settings.SCOPE not in scopes:
            msg = "Token does not carry the mcp:sql scope."
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.BAD_SCOPE,
                error=msg,
                user=user,
                token=token,
            )
            raise exceptions.AuthenticationFailed(msg)
        if not (user.is_active and user.is_staff):
            msg = "User is not an active staff member."
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.INACTIVE_OR_NON_STAFF,
                error=msg,
                user=user,
                token=token,
            )
            raise exceptions.AuthenticationFailed(msg)
        if not mcp_sql_settings.MFA_CHECKER(user):
            msg = "User does not have a verified TOTP device."
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.NO_MFA,
                error=msg,
                user=user,
                token=token,
            )
            raise exceptions.AuthenticationFailed(msg)
        # Profile binding replaces the old single `use_mcp_session` perm gate.
        # `resolve_profile` reads the user's EXPLICIT permission assignments
        # (blind to is_superuser) and binds exactly one profile, or denies.
        outcome = mcp_sql_settings.resolve_profile(user)
        if outcome is ResolutionOutcome.NO_PERM:
            msg = "User holds no MCP profile permission."
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.NO_PERM,
                error=msg,
                user=user,
                token=token,
            )
            raise exceptions.AuthenticationFailed(msg)
        if outcome is ResolutionOutcome.AMBIGUOUS_PROFILE:
            msg = (
                "User is assigned to more than one MCP profile; access is "
                "denied until exactly one remains."
            )
            self._audit_rejection(
                request,
                reason=AuthRejectionReason.AMBIGUOUS_PROFILE,
                error=msg,
                user=user,
                token=token,
            )
            # Deduped WARNING only; the paging Sentry ERROR fired once at
            # assignment time (signals.py). A retrying agent must not respam.
            if cache.add(
                f"mcp_sql:ambiguous_warned:{user.pk}",
                1,
                _AMBIGUOUS_WARN_DEDUP_SECONDS,
            ):
                logger.warning(
                    "MCP profile resolution ambiguous for user %s (pk=%s): "
                    "assigned to >1 profile; denying until resolved.",
                    user.get_username(),
                    user.pk,
                )
            raise exceptions.AuthenticationFailed(msg)
        # Session-existence gate (opt-in): see module docstring for the
        # design rationale. One indexed lookup against the configured
        # session table by `user_id` + `expire_date`. Kept last so the
        # cheaper in-memory checks above short-circuit before the DB
        # round-trip.
        #
        # **Opt-in**: when `MCP_SQL["SESSION_MODEL"]` is set (e.g. to a
        # `django-user-sessions` fork or any session-with-user model),
        # the gate fires. When unset (`None`, the in-package default),
        # the gate is skipped — the OAuth token's 6h expiry plus the
        # `user_logged_out` revocation signal are the only
        # token-lifetime bounds. Stock `django.contrib.sessions.Session`
        # has no `user` FK and would raise `FieldError` here; refusing
        # to default to it is honest about that constraint.
        session_model_name = mcp_sql_settings.SESSION_MODEL
        if session_model_name:
            session_model = apps.get_model(session_model_name)
            if not session_model.objects.filter(
                user=user, expire_date__gt=timezone.now()
            ).exists():
                msg = (
                    "No active web session — re-login at the Django UI to "
                    "re-issue MCP access."
                )
                self._audit_rejection(
                    request,
                    reason=AuthRejectionReason.NO_SESSION,
                    error=msg,
                    user=user,
                    token=token,
                )
                raise exceptions.AuthenticationFailed(msg)

        # All gates passed — bind the resolved profile for the view's tool
        # closures. Set on the underlying HttpRequest; DRF's Request proxies
        # attribute access to it, so the view reads `request.mcp_profile`.
        django_request.mcp_profile = outcome
        return user, token

    def _audit_rejection(
        self,
        request,
        *,
        reason: str,
        error: str,
        user,
        token,
    ) -> None:
        """Write an `MCPAuthRejectionLog` row for a resolved-user rejection.

        Called only after `super().authenticate(request)` returned a
        `(user, token)` pair, so `user` and `token` are always present.
        Anonymous / bad-token rejections take the `throttle.record_attempt`
        path instead and never reach this method.

        Best-effort, mirroring `executor._audit_safely`'s contract: if the
        audit-write itself fails the auth failure still raises with the
        original message (the rejection is visible to the agent regardless
        of audit-table state). The catch is deliberately narrowed to
        `DatabaseError` so non-DB exceptions (a future field-rename bug,
        AttributeError from a malformed `token`) surface as 500s instead
        of being swallowed silently.

        Sentry exposure on the audit-write failure path is bounded by
        construction: only the six resolved-user gates can reach this
        method, all low-volume (a real user with revoked perm / removed
        MFA / dead session / scope drift). The compound "DB unreachable +
        sustained probing" scenario that would flood Sentry through
        `logger.exception` does NOT apply here, because the high-volume
        bad-token path is intercepted earlier and writes to a Redis
        counter instead (see `throttle.record_attempt`).

        Sits inside DRF's request `ATOMIC_REQUESTS=True` transaction on
        the default alias. The row commits when DRF turns the subsequent
        `AuthenticationFailed` into the 401 response (DRF treats 4xx as a
        successful HTTP cycle and commits the request transaction). If a
        future caller ever wraps an explicit `transaction.atomic()` block
        around the gate sequence in `authenticate()` and re-raises inside
        it, the audit write would roll back with the inner block — guard
        such a wrapper with `savepoint=False` or move the audit write to
        `transaction.on_commit` to preserve the invariant.
        """
        try:
            MCPAuthRejectionLog.objects.create(
                user=user,
                token_pk=str(token.pk),
                application_name=token.application.name,
                reason=reason,
                error=error,
                client_ip=request.META.get("REMOTE_ADDR"),
                started_at=timezone.now(),
            )
        except DatabaseError:
            logger.exception("Failed to write MCPAuthRejectionLog (reason=%s)", reason)
