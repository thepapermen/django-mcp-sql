"""Request-body size cap for the package's OAuth endpoints.

The MCP transport endpoint (`/mcp/sql/`) is capped separately, and higher,
in `auth.MCPOAuth2Authentication` — its body carries the agent's SQL query,
so it needs headroom a tight cap would clip. This decorator caps the *OAuth*
endpoints (`/o/authorize/`, `/o/token/`, `/o/revoke_token/`, `/o/register`),
whose bodies are always sub-kilobyte form/JSON. Two of them (`/o/token/`,
`/o/register`) are anonymous, so without a cap a client could POST a body
bounded only by the consumer's global `DATA_UPLOAD_MAX_MEMORY_SIZE` and
amplify worker memory per request — this refuses that before the body is read.

The CONTENT_LENGTH header check is sufficient; no streaming read is needed.
Django wraps `wsgi.input` in `LimitedStream(CONTENT_LENGTH)`, so an
under-declared length truncates the read to the lie rather than smuggling a
larger body through. A request can only get N bytes read by declaring >= N,
which this rejects — declaring less just truncates the sender's own payload.
"""

import functools
from typing import TYPE_CHECKING

from django.http import HttpRequest
from django.http import HttpResponse

if TYPE_CHECKING:
    from collections.abc import Callable

# OAuth bodies are sub-kilobyte (form grant params; a small `redirect_uris`
# array). 64 KiB is generous headroom while refusing the large POST that the
# consumer's `DATA_UPLOAD_MAX_MEMORY_SIZE` would otherwise allow on these
# (partly anonymous) endpoints.
OAUTH_REQUEST_BODY_MAX_BYTES = 64 * 1024


def normalize_content_length(request: HttpRequest) -> int:
    """Return the request's declared `CONTENT_LENGTH` as an int.

    A missing or malformed (non-integer) header is normalised to 0 — and
    written back as `"0"` to `request.META` — so a later `int(CONTENT_LENGTH)`
    inside Django's own body handling cannot raise `ValueError`. Shared by
    `cap_request_body` (OAuth endpoints) and `auth._enforce_body_size_cap`
    (`/mcp/sql/`) so both gates parse the attacker-controlled header the same
    way.
    """
    raw = request.headers.get("content-length") or "0"
    try:
        return int(raw)
    except (TypeError, ValueError):
        # Write the fix to META, not `request.headers` (read-only + cached):
        # Django's body handling reads CONTENT_LENGTH from `request.META`.
        request.META["CONTENT_LENGTH"] = "0"
        return 0


def cap_request_body(
    max_bytes: int = OAUTH_REQUEST_BODY_MAX_BYTES,
) -> "Callable[[Callable[..., HttpResponse]], Callable[..., HttpResponse]]":
    """Reject (HTTP 413) a request whose declared CONTENT_LENGTH exceeds
    `max_bytes`, before the wrapped view reads the body.

    `functools.wraps` preserves the wrapped view's attributes, including the
    `csrf_exempt` flag that DOT's token/revoke views and our registration
    view carry, so wrapping does not re-arm CSRF on them.
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            if normalize_content_length(request) > max_bytes:
                return HttpResponse(
                    "Request body too large.",
                    status=413,
                    content_type="text/plain",
                )
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
