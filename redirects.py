"""The runtime redirect-URI predicates, settings-free.

- `is_loopback_redirect`: a redirect `/o/register` registers (RFC 8252
  §7.3 loopback), and the one `oauth.MCPOAuth2Validator` re-checks for the
  canonical and dynamically registered clients at `/o/authorize/`.
- `redirect_under_prefix`: a callback under a declared client's
  `MATCH: "prefix"` rule (ChatGPT / Codex-cloud's per-instance callbacks).

The view and the validator both import them from here, so the two layers
cannot drift apart. Boot-time validation of the declared rules themselves
(`MCP_SQL["CLIENTS"]`) stays in `validation.py`; `clients.py` only
classifies.
"""

from urllib.parse import unquote
from urllib.parse import urlparse
from urllib.parse import urlsplit

# RFC 8252 §7.3 specifies `127.0.0.1` and `[::1]` as the loopback hostnames
# and "SHOULD NOT" `localhost`. In practice Anthropic's MCP SDK, Google's
# native-app OAuth, GitHub's, etc. all use `http://localhost:<port>`, and
# dynamically-registered Applications store the exact URI they provided,
# so DOT's path-exact matching at `/o/authorize/` and `/o/token/` works
# uniformly for any of the three hostnames. We accept all three rather
# than break interop on a SHOULD that the broader OAuth ecosystem
# universally ignores.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def is_parseable_uri(uri: str) -> bool:
    """True if `urllib` parses `uri`, port and host included, without raising.

    `urlsplit` raises `ValueError` for a malformed bracketed host
    (`http://[::1`, `http://[127.0.0.1]/cb`) and for a netloc that changes
    under NFKC normalisation (a fullwidth solidus, U+2100); `.port` raises for a
    port that is not a number in range. A URI that fails this is not
    registered (it drops out of the loopback subset like any other URI we do
    not support). In 0.1.0b5 the first two kinds raised inside the loopback
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


def is_loopback_redirect(uri: str) -> bool:
    if not uri.isascii() or not uri.isprintable():
        # RFC 3986 URIs are printable ASCII. Anything else is either rewritten
        # before parsing (`urlsplit` silently strips leading C0 controls, so
        # the string we validated is not the one we would store) or rejected
        # by the database on INSERT (NUL, lone surrogates — an uncaught 500).
        # Refuse the whole class rather than enumerate the harmful characters.
        # (`/o/register` refuses the invisible ones for the whole request
        # first, `_requested_uris_error`; this predicate also judges the
        # stored redirects `oauth.MCPOAuth2Validator` re-checks at
        # `/o/authorize/`.)
        return False
    if not is_parseable_uri(uri):
        return False
    parsed = urlparse(uri)
    if parsed.scheme != "http":
        # RFC 8252 §7.3 — loopback uses http (no CA issues certs for 127.0.0.1).
        return False
    if "@" in parsed.netloc:
        # Reject a userinfo component (`http://user:pass@127.0.0.1/cb`): the
        # host is still loopback, so the bare hostname check below would pass,
        # but the userinfo is attacker-chosen and would be stored verbatim on
        # the Application. Refuse it so a registered redirect URI is exactly
        # scheme + host + port + path with nothing to smuggle. Test the raw
        # `@`, not `.username`/`.password`: an EMPTY userinfo
        # (`http://@127.0.0.1/cb`) parses to falsy `""`/`None` and would slip
        # past (DOT 3.4.1+ tests for `@` in the netloc the same way).
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
    return parsed.hostname in LOOPBACK_HOSTS


def redirect_under_prefix(redirect_uri: str, prefix: str) -> bool:
    """True iff `redirect_uri` is a safe https URL sitting under `prefix`.

    Used only for `MATCH: "prefix"` rules (ChatGPT / Codex-cloud), whose
    callback is per-instance — `https://chatgpt.com/connector/oauth/{id}` —
    and so cannot be pre-registered as an exact URI. The match is deliberately
    strict, hardened against the classic redirect-allowlist bypasses so the
    relaxation stays bounded to the provider's own origin:

    - scheme MUST be https (no downgrade),
    - no `@` anywhere in the authority — no userinfo component at all, not even
      an empty one (`https://chatgpt.com@evil.com/...`, `https://@chatgpt.com/`),
    - no query, fragment or `;params` — not even a bare trailing `?` / `#`, which
      parse to an empty `.query` / `.fragment`, so the raw string is tested.
      The callback is a plain path, and DOT 3.4.1+ matches an exact URI the same
      way (RFC 9700 §2.1). `urlsplit` (not `urlparse`) keeps `;params` in the
      path, where they are refused — also percent-encoded (`%3b`), since the
      check runs on the decoded path,
    - host must EXACTLY equal the prefix host (not `endswith`, so
      `chatgpt.com.evil.com` is rejected), and port must match with only a
      MISSING port normalised to the https default (an explicit `:443` equals
      an implicit one; an explicit `:0` stays distinct),
    - no `..` path segment — literal or single/multi-level percent-encoded
      (`%2e%2e`, `%252e%252e`, ...) — above the prefix path,
    - path must start with the prefix path, anchored at a `/` segment boundary
      so a sibling like `.../oauthEVIL` cannot slip past a bare prefix (also
      enforced at config time by `validation._validate_redirect_uri`).

    Mirrors the care in `is_loopback_redirect`.
    """
    try:
        got = urlsplit(redirect_uri)
        want = urlsplit(prefix)
        got_port, want_port = got.port, want.port
    except ValueError:
        # Malformed authority (e.g. a non-numeric port) — reject, fail-closed.
        return False
    # Anchor the prefix to a segment boundary. Validation already requires a
    # trailing slash on a "prefix" REDIRECT_URI; this keeps the predicate
    # correct on its own even if handed a bare prefix.
    want_path = want.path if want.path.endswith("/") else want.path + "/"
    # Fully percent-decode the path (bounded) before the traversal check, so a
    # single- OR multi-encoded `..` (`%2e%2e`, `%252e%252e`, ...) can't slip
    # past. `unquote` is idempotent-converging; 5 layers is far more than any
    # real callback needs. Only the traversal check sees the decoded form —
    # `startswith` stays on the raw path, matched against the raw prefix.
    decoded_path = got.path
    for _ in range(5):
        step = unquote(decoded_path)
        if step == decoded_path:
            break
        decoded_path = step
    # Normalise only a MISSING port to the https default — an explicit `:0` is
    # falsy but not None, so keep it distinct rather than aliasing the default.
    got_port = 443 if got_port is None else got_port
    want_port = 443 if want_port is None else want_port
    return (
        got.scheme == "https"  # no downgrade
        and "@" not in got.netloc  # no userinfo, not even an empty one
        and "?" not in redirect_uri  # no query, not even a bare `?` ...
        and "#" not in redirect_uri  # ... nor a fragment / bare `#`
        and ";" not in decoded_path  # no `;params`, raw or percent-encoded
        and bool(got.hostname)
        and got.hostname == want.hostname  # exact host, never `endswith`
        and got_port == want_port  # exact port (:443 == implicit https)
        and ".." not in decoded_path.split("/")  # no traversal (literal/encoded)
        # ...and no backslash, which a browser's WHATWG parser treats as `/`
        # in an https URL, so `..\` would be traversal by another spelling.
        # oauthlib's absolute-URI check and Django's `iri_to_uri` (`\` ->
        # `%5C`) each already stop it upstream; refused here as well so the
        # path anchor does not depend on either.
        and "\\" not in decoded_path
        and got.path.startswith(want_path)  # under the allowlisted path
    )
