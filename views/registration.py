"""RFC 7591 dynamic client registration at `/o/register`. Anonymous
JSON POST mints an `mcp-sql-<token>` Application with
`skip_authorization=False` (so the client hits the consent screen,
preventing silent-consent token theft) and loopback-only
`redirect_uris` — the request's non-loopback URIs are filtered out and the
registered subset echoed back, per RFC 7591 §3.2.1. See
`docs/architecture.md` "OAuth surface" + the `docs/oauth.md` runbook for the
full security posture."""

import bisect
import json
import logging
import secrets
import unicodedata
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse
from urllib.parse import urlsplit

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


# --- Characters refused in client metadata -------------------------------
#
# Nothing refused here is stored, echoed or logged. Control (`Cc`: C0, DEL,
# C1) and surrogate (`Cs`) characters fail downstream outright: Postgres
# refuses a NUL in a text column (`DataError`), the driver's UTF-8 encoder a
# lone surrogate (`UnicodeEncodeError`), each an anonymous 500. Line /
# paragraph separators (`Zl`, `Zp`) break the text across lines. And every
# character Unicode marks Default_Ignorable_Code_Point renders as nothing, so
# it would let a registrant make a stored callback (copied into every audit
# row's `client_redirect`) or a logged / echoed client name read as
# something it is not.

# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt; stable
# since Unicode 6.x, the ranges include their unassigned reserves). Python's
# `unicodedata` does not expose the property, hence the table.
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x061C, 0x061C),  # Arabic letter mark
    (0x115F, 0x1160),  # Hangul choseong / jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180F),  # Mongolian free variation selectors, vowel separator
    (0x200B, 0x200F),  # zero-width space / non-joiner / joiner, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x206F),  # word joiner, invisible operators, isolates, ...
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFFF0, 0xFFF8),  # unassigned specials
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical symbol format controls
    (0xE0000, 0xE0FFF),  # tags, variation selectors supplement, reserves
)
_DI_STARTS = [lo for lo, _ in _DEFAULT_IGNORABLE_RANGES]

# Conjoining Hangul jamo. In a name they are ordinary (decomposed, NFD,
# Korean); a vowel or final standing without its leading consonant renders
# as blank or as nothing, so only those orphans are refused there.
_CHOSEONG = ((0x1100, 0x115E), (0xA960, 0xA97C))
_JUNGSEONG = ((0x1161, 0x11A7), (0xD7B0, 0xD7C6))
_JONGSEONG = ((0x11A8, 0x11FF), (0xD7CB, 0xD7FB))
_CONJOINING_JAMO = ((0x1100, 0x11FF), (0xA960, 0xA97F), (0xD7B0, 0xD7FF))

_ZWNJ, _ZWJ = 0x200C, 0x200D
_VS15, _VS16 = 0xFE0E, 0xFE0F
_KEYCAP = 0x20E3
_BLACK_FLAG, _CANCEL_TAG = 0x1F3F4, 0xE007F
_TAGS = (0xE0020, 0xE007E)
_IDEOGRAPHIC_VS = (0xE0100, 0xE01EF)
_CJK_IDEOGRAPHS = (
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xF900, 0xFAFF),
    (0x20000, 0x3FFFF),
)
_INTERLINEAR_ANNOTATION = (0xFFF9, 0xFFFB)
_ALWAYS_REFUSED_CATEGORIES = frozenset({"Cc", "Cs", "Zl", "Zp"})


def _in(cp: int, ranges: Any) -> bool:
    if isinstance(ranges[0], int):
        return ranges[0] <= cp <= ranges[1]
    return any(lo <= cp <= hi for lo, hi in ranges)


def _is_default_ignorable(cp: int) -> bool:
    i = bisect.bisect_right(_DI_STARTS, cp) - 1
    return i >= 0 and cp <= _DEFAULT_IGNORABLE_RANGES[i][1]


def _is_visible_neighbour(c: str | None) -> bool:
    """A character a joiner may sit next to in ordinary text: present, not
    ASCII (no Latin-script word needs a joiner), not whitespace, and not
    itself invisible (VS16, which ends an emoji presentation, excepted)."""
    if c is None or c.isascii() or c.isspace():
        return False
    return not _is_default_ignorable(ord(c)) or ord(c) == _VS16


def _name_allows_ignorable(text: str, i: int) -> bool:  # noqa: PLR0911 — one return per allowance
    """Whether the default-ignorable character at `text[i]` is part of a
    visible sequence ordinary text needs, rather than an invisible insert.

    Allowed in a client name only:
    - the zero-width non-joiner / joiner between two visible non-ASCII
      characters (Persian and Indic spelling, emoji ZWJ sequences);
    - VS15 / VS16 after a symbol (emoji presentation) or after a keycap base
      (`0-9`, `#`, `*`) that is followed by U+20E3;
    - an ideographic variation selector after a CJK ideograph;
    - tag characters in a subdivision-flag sequence: U+1F3F4, tags, U+E007F.
    """
    cp = ord(text[i])
    before = text[i - 1] if i > 0 else None
    after = text[i + 1] if i + 1 < len(text) else None
    if cp in (_ZWNJ, _ZWJ):
        return _is_visible_neighbour(before) and _is_visible_neighbour(after)
    if cp in (_VS15, _VS16):
        if before is None:
            return False
        if before in "0123456789#*":
            return after is not None and ord(after) == _KEYCAP
        return unicodedata.category(before) == "So"
    if _in(cp, _IDEOGRAPHIC_VS):
        return before is not None and _in(ord(before), _CJK_IDEOGRAPHS)
    if _in(cp, _TAGS) or cp == _CANCEL_TAG:
        # Walk back over the tag run to its base: it must be the black flag,
        # and the run must end with the cancel tag.
        j = i
        while j > 0 and _in(ord(text[j - 1]), _TAGS):
            j -= 1
        if j == 0 or ord(text[j - 1]) != _BLACK_FLAG:
            return False
        k = i
        while k < len(text) and _in(ord(text[k]), _TAGS):
            k += 1
        return k < len(text) and ord(text[k]) == _CANCEL_TAG and k > j
    return False


def _is_orphan_jamo(text: str, i: int) -> bool:
    """A conjoining vowel / final Hangul jamo not continuing a syllable."""
    cp = ord(text[i])
    before = ord(text[i - 1]) if i > 0 else None
    if _in(cp, _JUNGSEONG):
        return before is None or not (_in(before, _CHOSEONG) or _in(before, _JUNGSEONG))
    if _in(cp, _JONGSEONG):
        return before is None or not (
            _in(before, _JUNGSEONG) or _in(before, _JONGSEONG)
        )
    return False


def _has_unacceptable_character(value: str) -> bool:
    """True if `value` holds a character no redirect URI may carry.

    Strict: any control, surrogate, separator or format (`Cf`) character,
    any default-ignorable one, and any conjoining Hangul jamo. Nothing
    legitimate in a callback needs one.
    """
    for c in value:
        cp = ord(c)
        if (
            unicodedata.category(c) in _ALWAYS_REFUSED_CATEGORIES
            or unicodedata.category(c) == "Cf"
            or _is_default_ignorable(cp)
            or _in(cp, _CONJOINING_JAMO)
        ):
            return True
    return False


def _has_unacceptable_name_character(value: str) -> bool:
    """True if `value` holds a character no client name may carry.

    Free text, so narrower than for a URI: control, surrogate and separator
    characters; default-ignorable (invisible) ones except where
    `_name_allows_ignorable` finds them part of a visible sequence; the
    interlinear annotation controls; and orphaned conjoining Hangul jamo.
    Ordinary letters, combining accents, emoji and their sequences pass. The
    name is never stored, but it is echoed in the 201 and logged.
    """
    for i, c in enumerate(value):
        cp = ord(c)
        if unicodedata.category(c) in _ALWAYS_REFUSED_CATEGORIES:
            return True
        if _is_default_ignorable(cp) and not _name_allows_ignorable(value, i):
            return True
        if _in(cp, _INTERLINEAR_ANNOTATION) or _is_orphan_jamo(value, i):
            return True
    return False


def _error(
    code: str, description: str, status: int = HTTPStatus.BAD_REQUEST
) -> JsonResponse:
    """RFC 7591 §3.2.2 error response."""
    return JsonResponse(
        {"error": code, "error_description": description},
        status=status,
    )


def _is_parseable_uri(uri: str) -> bool:
    """True if `urllib` parses `uri`, port and host included, without raising.

    `urlsplit` raises `ValueError` for a malformed bracketed host
    (`http://[::1`, `http://[127.0.0.1]/cb`) and for a netloc that changes
    under NFKC normalisation (a fullwidth solidus, U+2100); `.port` raises for a
    port that is not a number in range. A URI that fails this is not
    registered (it drops out of the loopback subset like any other URI we do
    not support). Before, the first two kinds raised inside the loopback
    filter (an anonymous 500), and a loopback URI with a bad port
    (`http://127.0.0.1:99999/cb`), whose port the filter never read, was
    registered verbatim.
    """
    try:
        parsed = urlsplit(uri)
        _ = parsed.port, parsed.hostname, parsed.username, parsed.password
    except ValueError:
        return False
    return True


def _is_loopback_redirect(uri: str) -> bool:
    if not _is_parseable_uri(uri):
        return False
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
    for field in ("grant_types", "response_types"):
        # A list of strings, or absent. `"x" in None` raised (a 500), and a
        # string turned the membership test below into a substring test.
        value = body.get(field, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return _error(
                "invalid_client_metadata", f"{field} must be an array of strings"
            )
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


def _requested_uris_error(requested_uris: Any) -> JsonResponse | None:
    """The whole-request refusals of `redirect_uris`, before the subset filter.

    Returns an `invalid_redirect_uri` error response, or None. Two kinds of
    input refuse the whole request, even beside a clean URI, instead of
    dropping out of the loopback subset:

    - a request of the wrong shape: not a non-empty array, longer than
      `_MAX_REDIRECT_URIS`, or a member that is not a string (the same
      strictness `grant_types` / `response_types` get);
    - a character `_has_unacceptable_character` names, which must never be
      stored, echoed or logged (a NUL or lone surrogate failed at the
      INSERT, an anonymous 500; invisible ones would spoof the audit trail).

    Everything else is judged per URI by the subset filter: a URI that is
    well-formed text but not a valid loopback callback (non-loopback,
    unparseable, over-long) is not registered, and the 201 echoes what was.
    """
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
    if not all(isinstance(uri, str) for uri in requested_uris):
        return _error(
            "invalid_redirect_uri",
            "redirect_uris must be a non-empty array of URI strings",
        )
    if any(_has_unacceptable_character(uri) for uri in requested_uris):
        return _error(
            "invalid_redirect_uri",
            "redirect_uris must not contain control, separator, surrogate, "
            "format or other invisible characters",
        )
    return None


@csrf_exempt
@require_POST
def register_client(request):  # noqa: PLR0911 — each validation produces a distinct RFC 7591 error code; consolidating would obscure the spec mapping.
    """RFC 7591 §3 client registration endpoint."""
    try:
        body = json.loads(request.body)
    except (ValueError, RecursionError):
        # `ValueError` covers `JSONDecodeError`, a body that is not UTF-8
        # (`UnicodeDecodeError`) and an integer past Python's digit limit;
        # `RecursionError` JSON nested past the recursion limit (the 64 KiB
        # body cap allows ~65k levels). Each used to be an anonymous 500.
        return _error("invalid_client_metadata", "Request body is not valid JSON")

    if not isinstance(body, dict):
        return _error("invalid_client_metadata", "Request body must be a JSON object")

    uris_error = _requested_uris_error(body.get("redirect_uris"))
    if uris_error is not None:
        return uris_error
    # A non-empty list from here on (`_requested_uris_error` checked it).
    requested_uris: list[Any] = body["redirect_uris"]
    # Register the loopback SUBSET rather than refusing the whole request.
    # RFC 7591 §3.2.1 already has us registering the subset of requested
    # metadata we support and echoing back what we actually registered, and
    # real clients send more than they will use: Cursor's IDE/CLI may present
    # its loopback callback alongside a hosted `https://…/callback` and the
    # legacy `cursor://…` deeplink, none of which we can admit. Rejecting the
    # request outright would lock those clients out of DCR entirely; taking
    # the loopback URIs and echoing only those tells the client exactly what
    # it may use. Nothing is widened — a non-loopback URI is still never
    # registered, and a client that sends none at all is still refused. The
    # same goes for a URI `urllib` cannot parse (`_is_loopback_redirect` calls
    # `_is_parseable_uri` first): it is not a loopback callback we could
    # register, so it drops out like any other unsupported URI.
    redirect_uris = list(
        dict.fromkeys(
            uri
            for uri in requested_uris
            # Length is bounded HERE, inside the filter, not over the whole
            # request. The bound exists to cap what gets persisted, and only
            # this subset is persisted — checking it earlier would let a URI
            # we are about to discard fail the whole registration, which is
            # exactly the all-or-nothing behaviour this filter replaced.
            # Cursor sends a hosted callback alongside its loopback one, and
            # that hosted URL can carry a long `state` query.
            if len(uri) <= _MAX_REDIRECT_URI_LENGTH and _is_loopback_redirect(uri)
        )
    )
    if not redirect_uris:
        return _error(
            "invalid_redirect_uri",
            "none of the requested redirect_uris is a valid loopback URI "
            "(must be http://127.0.0.1, http://[::1], or http://localhost "
            "with an optional port and path)",
        )

    metadata_error = _client_metadata_error(body)
    if metadata_error is not None:
        return metadata_error

    # Optional (RFC 7591 §2). Absent, `null` or empty gets the default; any
    # other non-string is refused below. A falsy non-string (`0`, `false`,
    # `[]`) used to be swapped for the default silently while a truthy one
    # was refused.
    client_name = body.get("client_name")
    if client_name is None or client_name == "":
        client_name = "Unnamed MCP client"
    if (
        not isinstance(client_name, str)
        or len(client_name) > _MAX_CLIENT_NAME
        or _has_unacceptable_name_character(client_name)
    ):
        # Bounded and typed before it is echoed in the 201 or written to the
        # log line below. The body cap is 64 KiB, so an unbounded name would
        # otherwise put ~64 KiB of caller-chosen text into both — and a
        # non-string (a nested object) would be reflected verbatim. The
        # characters `_has_unacceptable_name_character` names are refused
        # too: the name is never stored, but it is echoed and logged.
        return _error(
            "invalid_client_metadata",
            f"client_name must be a string of at most {_MAX_CLIENT_NAME} "
            "characters, without control, separator, surrogate, "
            "bidirectional-control or invisible characters",
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
