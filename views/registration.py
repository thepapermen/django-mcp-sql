"""RFC 7591 dynamic client registration at `/o/register`. Anonymous
JSON POST mints an `mcp-sql-<token>` Application with
`skip_authorization=False` (so the client hits the consent screen,
preventing silent-consent token theft) and loopback-only
`redirect_uris` — the request's non-loopback URIs are filtered out and the
registered subset echoed back, per RFC 7591 §3.2.1. See
`docs/architecture.md` "OAuth surface" + the `docs/oauth.md` runbook for the
full security posture."""

import json
import logging
import secrets
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

from django.http import HttpRequest
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from mcp_sql import throttle
from mcp_sql.conf import mcp_sql_config
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import absolute_url
from oauth2_provider.models import Application

logger = logging.getLogger(__name__)

# RFC 8252 §7.3 specifies `127.0.0.1` and `[::1]` as the loopback hostnames
# and "SHOULD NOT" `localhost`. In practice Anthropic's MCP SDK, Google's
# native-app OAuth, GitHub's, etc. all use `http://localhost:<port>`, and
# dynamically-registered Applications store the exact URI they provided,
# so DOT's path-exact matching at `/o/authorize/` and `/o/token/` works
# uniformly for any of the three hostnames. We accept all three rather
# than break interop on a SHOULD that the broader OAuth ecosystem
# universally ignores.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Upper bound on the redirect_uris an anonymous caller may submit. Whatever
# survives the loopback filter is stored verbatim on the Application, so
# without a cap one request could persist an arbitrarily long string. Real
# clients send one to three (Cursor's IDE presents the most, at three).
_MAX_REDIRECT_URIS = 10

# ...and a bound on each STORED one's length, which is the half the count cap
# does not give: `Application.redirect_uris` is an unbounded `TextField`, so
# ten 6 KB URIs still persist ~60 KB inside the 64 KiB body cap. A loopback
# callback is a host, a port and a path; 1024 is already far past anything
# real. Applied inside the loopback filter, so an over-long URI we discard
# anyway drops out of the subset instead of failing the whole registration.
_MAX_REDIRECT_URI_LENGTH = 1024

# Upper bound on the client's self-declared name. It is echoed in the 201 and
# written to the registration log line, so it is caller-controlled text on two
# output paths; the log uses `%r`, which escapes newlines, so a long name is
# the remaining concern rather than a forged log line.
_MAX_CLIENT_NAME = 200


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
    if uri.split() != [uri]:
        # Whitespace smuggling. `Application.redirect_uris` stores the list as
        # `" ".join(...)` and DOT matches with `redirect_uris.split()`, so ONE
        # submitted string containing whitespace becomes TWO registered URIs.
        # `urlparse("http://127.0.0.1/cb http://evil.example/steal")` reports
        # hostname `127.0.0.1` — the host check below passes, the string is
        # stored verbatim, and DOT then exact-matches `http://evil.example/
        # steal` as a valid redirect for this client. That delivers the
        # authorization code off-machine, defeating the whole reason loopback-
        # only registration is safe; PKCE does not help, because the attacker
        # registered the client and holds the verifier.
        #
        # `uri.split() != [uri]` is deliberately the same operation DOT
        # performs, so this cannot drift from it — and it covers tab / newline
        # / CR as well as the space (`str.split()` splits on all whitespace,
        # and `urlparse` silently strips some of it while we store the raw
        # value, which would otherwise hide the payload from the host check).
        return False
    return parsed.hostname in _LOOPBACK_HOSTS


def _registration_response(
    request: HttpRequest,
    client_id: str,
    client_name: str,
    redirect_uris: list[str],
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
            # Same origin as the discovery document's `registration_endpoint`
            # (https forced with DEBUG off) — see `consts.absolute_url`.
            "registration_client_uri": absolute_url(
                request, reverse("oauth_dynamic_client_registration")
            ),
        },
        status=HTTPStatus.CREATED,
    )


def _client_metadata_error(body: dict[str, Any]) -> JsonResponse | None:
    """The non-redirect half of RFC 7591 client metadata: grant / response
    types and the client-authentication method. Returns an error response, or
    None when the request is acceptable.

    The client may request a SUPERSET of what we actually support (Anthropic's
    MCP SDK sends `authorization_code` + `refresh_token`, for example). Per RFC
    7591 §3.2.1 the server registers the subset it supports and echoes the
    registered values back, so the client learns what we allow. We require
    `authorization_code` + `code` to be *present* in the request, so a client
    asking for ONLY `client_credentials` — i.e. not the OAuth 2.1 native-app
    pattern — is refused outright rather than silently downgraded.
    """
    if "authorization_code" not in body.get("grant_types", ["authorization_code"]):
        return _error(
            "invalid_client_metadata",
            "grant_types must include 'authorization_code'",
        )
    if "code" not in body.get("response_types", ["code"]):
        return _error(
            "invalid_client_metadata",
            "response_types must include 'code'",
        )
    # Public client only. We don't accept confidential-client schemes
    # because we don't issue client_secrets. The default `"none"` for
    # native apps is what every MCP SDK sends.
    if body.get("token_endpoint_auth_method", "none") != "none":
        return _error(
            "invalid_client_metadata",
            "Only token_endpoint_auth_method='none' is supported (public client)",
        )
    return None


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

    requested_uris = body.get("redirect_uris")
    if not isinstance(requested_uris, list) or not requested_uris:
        return _error(
            "invalid_redirect_uri",
            "redirect_uris must be a non-empty array of URI strings",
        )
    if len(requested_uris) > _MAX_REDIRECT_URIS:
        return _error(
            "invalid_redirect_uri",
            f"redirect_uris must list at most {_MAX_REDIRECT_URIS} URIs",
        )
    # Register the loopback SUBSET rather than refusing the whole request.
    # RFC 7591 §3.2.1 already has us registering the subset of requested
    # metadata we support and echoing back what we actually registered, and
    # real clients send more than they will use: Cursor's IDE/CLI may present
    # its loopback callback alongside a hosted `https://…/callback` and the
    # legacy `cursor://…` deeplink, none of which we can admit. Rejecting the
    # request outright would lock those clients out of DCR entirely; taking
    # the loopback URIs and echoing only those tells the client exactly what
    # it may use. Nothing is widened — a non-loopback URI is still never
    # registered, and a client that sends none at all is still refused.
    redirect_uris = list(
        dict.fromkeys(
            uri
            for uri in requested_uris
            if isinstance(uri, str)
            # Length is bounded HERE, inside the filter, not over the whole
            # request. The bound exists to cap what gets persisted, and only
            # this subset is persisted — checking it earlier would let a URI
            # we are about to discard fail the whole registration, which is
            # exactly the all-or-nothing behaviour this filter replaced.
            # Cursor sends a hosted callback alongside its loopback one, and
            # that hosted URL can carry a long `state` query.
            and len(uri) <= _MAX_REDIRECT_URI_LENGTH
            and _is_loopback_redirect(uri)
        )
    )
    if not redirect_uris:
        return _error(
            "invalid_redirect_uri",
            "none of the requested redirect_uris is a loopback URI "
            "(must be http://127.0.0.1, http://[::1], or http://localhost "
            "with an optional port and path)",
        )

    metadata_error = _client_metadata_error(body)
    if metadata_error is not None:
        return metadata_error

    client_name = body.get("client_name") or "Unnamed MCP client"
    if not isinstance(client_name, str) or len(client_name) > _MAX_CLIENT_NAME:
        # Bounded and typed before it is echoed in the 201 or written to the
        # log line below. The body cap is 64 KiB, so an unbounded name would
        # otherwise put ~64 KiB of caller-chosen text into both — and a
        # non-string (a nested object) would be reflected verbatim.
        return _error(
            "invalid_client_metadata",
            f"client_name must be a string of at most {_MAX_CLIENT_NAME} characters",
        )
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
    cfg = mcp_sql_config()
    threshold = cfg["BAD_TOKEN_IP_THRESHOLD"]
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
        window=cfg["BAD_TOKEN_IP_WINDOW_SECONDS"],
        threshold=threshold,
    )
    # The only record of who claimed to be registering. `client_name` is
    # UNVERIFIED — anyone may POST here and pick any string — so it is logged
    # and never persisted: `Application.name` holds the minted client_id
    # because that field is the recognition predicate
    # (`consts.classify_application_name`), and a caller who could write it
    # could name themselves into the MCP surface. Audit rows likewise carry
    # the client_id, not this. It is still worth logging: correlating "a
    # client calling itself X registered from this IP" with a later audit row
    # is exactly the triage question, as long as the string is read as a
    # claim rather than an identity.
    logger.info(
        "MCP dynamic client registration: client_id %r for unverified "
        "client_name %r from %s; registered %d of %d requested redirect_uris "
        "(%s).",
        client_id,
        client_name,
        ip,
        len(redirect_uris),
        len(requested_uris),
        ", ".join(redirect_uris),
    )

    return _registration_response(request, client_id, client_name, redirect_uris)
