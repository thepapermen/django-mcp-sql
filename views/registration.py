"""RFC 7591 dynamic client registration at `/o/register`. Anonymous
JSON POST mints an `mcp-sql-<token>` Application with
`skip_authorization=False` (so the client hits the consent screen,
preventing silent-consent token theft) and a loopback-only
`redirect_uri`. See `docs/architecture.md` "OAuth surface" + the
`docs/oauth.md` runbook for the full security posture."""

import json
import secrets
from http import HTTPStatus
from urllib.parse import urlparse

from django.conf import settings
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from mcp_sql import throttle
from mcp_sql.conf import mcp_sql_settings
from oauth2_provider.models import Application

# RFC 8252 §7.3 specifies `127.0.0.1` and `[::1]` as the loopback hostnames
# and "SHOULD NOT" `localhost`. In practice Anthropic's MCP SDK, Google's
# native-app OAuth, GitHub's, etc. all use `http://localhost:<port>`, and
# dynamically-registered Applications store the exact URI they provided,
# so DOT's path-exact matching at `/o/authorize/` and `/o/token/` works
# uniformly for any of the three hostnames. We accept all three rather
# than break interop on a SHOULD that the broader OAuth ecosystem
# universally ignores.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _error(
    code: str, description: str, status: int = HTTPStatus.BAD_REQUEST
) -> JsonResponse:
    """RFC 7591 §3.2.2 error response."""
    return JsonResponse(
        {"error": code, "error_description": description},
        status=status,
    )


def _is_loopback_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme != "http":
        # RFC 8252 §7.3 — loopback uses http (no CA issues certs for 127.0.0.1).
        return False
    if parsed.username or parsed.password:
        # Reject a userinfo component (`http://user:pass@127.0.0.1/cb`): the
        # host is still loopback, so the bare hostname check below would pass,
        # but the userinfo is attacker-chosen and would be stored verbatim on
        # the Application. Refuse it so a registered redirect URI is exactly
        # scheme + host + port + path with nothing to smuggle.
        return False
    return parsed.hostname in _LOOPBACK_HOSTS


def _registration_response(
    request, client_id: str, client_name: str, redirect_uris: list[str]
) -> JsonResponse:
    """RFC 7591 §3.2.1 success body.

    Single builder so the real registration and the silent-block paths
    return a byte-shape-identical 201 — the block must not be
    distinguishable from a successful registration.
    """
    return JsonResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(timezone.now().timestamp()),
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "registration_client_uri": request.build_absolute_uri(
                reverse("oauth_dynamic_client_registration")
            ),
        },
        status=HTTPStatus.CREATED,
    )


@csrf_exempt
@require_POST
def register_client(request):  # noqa: PLR0911 — each validation produces a distinct RFC 7591 error code; consolidating would obscure the spec mapping.
    """RFC 7591 §3 client registration endpoint."""
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return _error("invalid_client_metadata", "Request body is not valid JSON")

    if not isinstance(body, dict):
        return _error("invalid_client_metadata", "Request body must be a JSON object")

    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _error(
            "invalid_redirect_uri",
            "redirect_uris must be a non-empty array of URI strings",
        )
    for uri in redirect_uris:
        if not isinstance(uri, str) or not _is_loopback_redirect(uri):
            return _error(
                "invalid_redirect_uri",
                f"redirect_uri {uri!r} is not a loopback URI "
                "(must be http://127.0.0.1, http://[::1], or http://localhost "
                "with an optional port and path)",
            )

    # The client may request a superset of what we actually support
    # (Anthropic's MCP SDK sends `authorization_code` + `refresh_token`,
    # for example). Per RFC 7591 §3.2.1 the server registers the subset
    # it supports and echoes the registered values in the response — the
    # client reads the response and learns what we actually allow.
    # We require `authorization_code` + `code` to be present in the
    # request so a client asking for ONLY `client_credentials` (i.e.
    # not the OAuth 2.1 native-app pattern) is refused outright.
    requested_grant_types = body.get("grant_types", ["authorization_code"])
    if "authorization_code" not in requested_grant_types:
        return _error(
            "invalid_client_metadata",
            "grant_types must include 'authorization_code'",
        )
    requested_response_types = body.get("response_types", ["code"])
    if "code" not in requested_response_types:
        return _error(
            "invalid_client_metadata",
            "response_types must include 'code'",
        )
    # Public client only. We don't accept confidential-client schemes
    # because we don't issue client_secrets. The default `"none"` for
    # native apps is what every MCP SDK sends.
    token_endpoint_auth_method = body.get("token_endpoint_auth_method", "none")
    if token_endpoint_auth_method != "none":  # noqa: S105 — "none" is the RFC 7591 §2 enum value for "public client, no client_secret", not a credential.
        return _error(
            "invalid_client_metadata",
            "Only token_endpoint_auth_method='none' is supported (public client)",
        )

    client_name = body.get("client_name") or "Unnamed MCP client"
    # PREFIX carries the trailing dash; the joined form is
    # `mcp-sql-<urlsafe16>` (no double-dash).
    client_id = f"{mcp_sql_settings.APPLICATION_NAME_PREFIX}{secrets.token_urlsafe(16)}"

    # Silent per-IP block (shared with the bad-token throttle on `/mcp/sql/`;
    # same `BAD_TOKEN_IP_THRESHOLD` / `_WINDOW_SECONDS` knobs, scope-separated
    # keys). Anonymous registration is unbounded `Application`-row creation;
    # once an IP crosses the threshold within the window we return a normal-
    # looking 201 but persist NO row. All validation above already ran, so a
    # blocked-but-malformed request still gets the same RFC 7591 error a non-
    # blocked one would — only well-formed requests reach here, and they get
    # a byte-shape-identical (but inert) 201. The response body + status match
    # a real registration; only timing differs (the blocked path skips the DB
    # INSERT), a side channel that does NOT let an attacker keep creating rows
    # once blocked. A visible 429 would instead let an attacker pace just under
    # the threshold and keep creating rows; silence denies that signal. The
    # synthesized client_id has no Application
    # row, so it fails at `/o/authorize/` exactly like any unknown/cleaned-up
    # client. Bounding row growth to `threshold` per IP per window; the
    # periodic cleanup of stale dynamically-registered Applications is Phase 4.
    # The IP keyed on is `REMOTE_ADDR` (proxy-stripped client IP) — see the
    # `throttle` module docstring for the edge-proxy invariant it rests on.
    ip = request.META.get("REMOTE_ADDR") or "unknown"
    threshold = settings.MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]
    if throttle.is_ip_blocked(ip, scope="register", threshold=threshold):
        return _registration_response(request, client_id, client_name, redirect_uris)

    Application.objects.create(
        name=client_id,
        client_id=client_id,
        client_secret="",
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        # Force the consent screen on every dynamically-registered client.
        # Without this, an attacker who registers their own client via this
        # endpoint and phishes a logged-in victim with a fully-formed
        # `/o/authorize/?client_id=<attacker's>&redirect_uri=http://127.0.0.1:31337/cb&...`
        # link gets the auth code 302'd silently to the (loopback) address
        # they control — any process listening on the victim's machine
        # captures the code, exchanges it at `/o/token/` with the
        # attacker's PKCE verifier, and ends up with a 6h `mcp:sql` token
        # bound to the victim. The consent screen is CSRF-POST-only, so
        # the same phished GET cannot complete the dance. The curated
        # `mcp-sql` Application from migration 0005 still has
        # `skip_authorization=True` — it is operator-provisioned with
        # known redirect URIs and predates this endpoint.
        skip_authorization=False,
        redirect_uris=" ".join(redirect_uris),
        algorithm="",
    )
    throttle.record_attempt(
        ip,
        scope="register",
        window=settings.MCP_SQL["BAD_TOKEN_IP_WINDOW_SECONDS"],
        threshold=threshold,
    )

    return _registration_response(request, client_id, client_name, redirect_uris)
