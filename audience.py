"""RFC 8707 resource indicators: the one resource this server issues tokens for.

From DOT 3.4, a `resource` sent to `/o/authorize/` or `/o/token/` is stored
on the grant and the access token, and DOT then audience-checks every bearer
that carries one (`AccessToken.allows_audience`, by default a URL-prefix match
against the request URL). A `resource` naming anything other than this
server's MCP endpoint therefore minted a token `/mcp/sql/` could never
accept: every call a bare 401, indistinguishable from a bad token, no audit
row, and each one counted toward the bad-token IP throttle.

So both halves are pinned to the identifier the RFC 9728 discovery document
advertises (`views/discovery.py`), built here by `mcp_resource_url`:

- issuance: `/o/authorize/` and `/o/token/` accept a `resource` only if it
  names that URL — scheme and host in any case, the default port explicit or
  omitted, the path exactly the endpoint's with or without its trailing
  slash (the two spellings discovery serves) — and answer anything else
  `invalid_target` (`foreign_resource`, `invalid_target_error`). Enforced by
  the package's views before DOT sees the value. Every accepted value is
  then rewritten to ONE spelling, `canonical_resource_url`
  (`canonical_resources`), before DOT reads it, at both steps: DOT compares
  the token request's `resource` with the grant's as a string, and a
  client that sends one spelling to `/o/authorize/` and another to
  `/o/token/` (Cursor: the slashed one, then the slash-less one) was
  otherwise refused. A grant or refresh token stored
  before that rewrite, under another accepted spelling, is matched by
  `use_granted_spelling` (the validator, at token issuance).
- verification: `/mcp/sql/` hands DOT's audience check the request URL built
  the same way (`CanonicalUriOAuthLibCore`), not Django's
  `build_absolute_uri`, so a token bound to the advertised identifier always
  matches it — even behind a TLS-terminating proxy without
  `SECURE_PROXY_SSL_HEADER`, where `request.scheme` is `http` while discovery
  (`consts.absolute_url`) says `https`, or one that forwards the host as
  `<name>:443`, which `absolute_url` spells `<name>` on both sides.
"""

from collections.abc import Iterable
from typing import Any

from django.http import HttpRequest
from django.urls import reverse
from mcp_sql.consts import absolute_url
from mcp_sql.consts import canonical_authority
from oauth2_provider.models import get_grant_model
from oauth2_provider.oauth2_backends import OAuthLibCore
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error


def mcp_resource_url(request: HttpRequest) -> str:
    """The MCP endpoint's RFC 9728 `resource` identifier, trailing slash
    included — the spelling `reverse()` builds; discovery serves it with and
    without the slash."""
    return absolute_url(request, reverse("mcp_sql_endpoint"))


def canonical_resource_url(request: HttpRequest) -> str:
    """The one spelling every accepted `resource` is rewritten to before DOT
    stores or compares it: `mcp_resource_url` without its trailing slash
    (`https://<host>/mcp/sql`, the host canonical).

    Slash-less because that is the form the MCP authorization spec asks
    implementations to use for the server URI, and because it is a prefix
    of both transport spellings: DOT's default audience validator matches it
    on `/mcp/sql` and `/mcp/sql/` (it compares `posixpath.normpath`ed
    parsed paths; so would the slashed form), and so does a validator
    that compares raw strings by prefix (which the slashed form fails on
    `/mcp/sql`). Discovery still echoes the spelling the client asked for
    (RFC 9728 §3.3); both are accepted and stored as this one.
    """
    return mcp_resource_url(request).removesuffix("/")


# The longest port spelling accepted (`65535`, or `0443`/`00443`): the
# package's own cap, not a parser's. Python's `urlsplit` (DOT's parser)
# refuses a port above 65535 and one of more than 4300 digits (`int()`'s
# string limit), but takes any shorter zero-padded spelling (`:000443`);
# the cap keeps this check's `int()` small and every accepted value well
# inside what DOT parses.
_MAX_PORT_DIGITS = 5
_MAX_PORT = 65535


def _has_parseable_port(authority: str) -> bool:
    """False when `authority` ends in `:<ASCII digits>` the package does not
    take as a port: more than five digits (its own cap), or a value above
    65535."""
    _, colon, port = authority.rpartition(":")
    if not (colon and port.isascii() and port.isdigit()):
        return True
    return len(port) <= _MAX_PORT_DIGITS and int(port) <= _MAX_PORT


def _resource_key(value: str) -> tuple[str, str, str] | None:
    """`(scheme, authority, path)` of `value` split as an absolute URL, scheme
    lowercased and authority in `consts.canonical_authority` form; None when
    the authority's port is not one (`_has_parseable_port`).

    Plain slicing at the first `://` and the next `/`, deliberately not
    `urlsplit` (which drops tab / CR / LF and strips leading control
    characters and spaces): nothing is decoded, stripped or resolved, so a
    query, fragment, userinfo, whitespace or control character anywhere
    leaves a part that differs from the endpoint's.
    """
    scheme, _, rest = value.partition("://")
    authority, slash, path = rest.partition("/")
    if not _has_parseable_port(authority):
        return None
    scheme = scheme.lower()
    return scheme, canonical_authority(scheme, authority), slash + path


def foreign_resource(request: HttpRequest, values: Iterable[str]) -> str | None:
    """The first of `values` that is not this server's MCP resource, or None.

    A value is this server's resource when it names the URL discovery
    advertises on this request's host (`mcp_resource_url`) by RFC 3986
    equivalence of the scheme and authority: scheme and host compared
    case-insensitively, an omitted port equal to the scheme's default and an
    explicit default port equal to an omitted one (`canonical_authority`).
    The MCP spec has servers accept uppercase scheme and host, and a client
    that parses discovery's value (the TypeScript SDK's `URL.href`, the
    Python SDK's pydantic URL) sends it back in that canonical form. The
    path is the endpoint's, exactly, with or without its trailing slash (the
    two spellings discovery serves): no case folding, percent-decoding or
    dot segments. A query or fragment (even empty), userinfo, an empty
    value, the bare origin, any other path, host, port or scheme is
    foreign; so is a port the package does not take (two ports or above
    65535, which URL parsers refuse too, or more than five digits, the
    package's own cap — on a request whose own Host carries such a port,
    every value is foreign).

    Every accepted spelling is one DOT (3.4+) parses as a resource indicator
    (else DOT would answer an `invalid_target` of its own, naming the
    client's value) and passes DOT's default bearer audience check
    (`validate_resource_as_url_prefix` compares the parsed scheme, host,
    port and path the same way) against the request URL
    `CanonicalUriOAuthLibCore` builds, which is the canonical one.
    """
    accepted = _accepted_keys(request)
    return next(
        (value for value in values if not _names_the_resource(value, accepted)),
        None,
    )


def _accepted_keys(request: HttpRequest) -> set[tuple[str, str, str]]:
    """The `_resource_key`s of the two spellings `foreign_resource` accepts:
    the advertised identifier with and without its trailing slash. Empty when
    the request's own host carries a port the package does not take."""
    endpoint = _resource_key(mcp_resource_url(request))
    if endpoint is None:
        return set()
    scheme, authority, path = endpoint
    return {endpoint, (scheme, authority, path.removesuffix("/"))}


def _names_the_resource(value: str, accepted: set[tuple[str, str, str]]) -> bool:
    # Non-ASCII first: `str.lower` folds some of it to ASCII (the Kelvin
    # sign U+212A to `k`).
    return value.isascii() and _resource_key(value) in accepted


def canonical_resources(request: HttpRequest, values: Iterable[str]) -> list[str]:
    """`values`, each one that names this server's MCP resource (what
    `foreign_resource` accepts) replaced by `canonical_resource_url`, and
    every other value left exactly as it is — still foreign, so the check
    that follows refuses it: the rewrite never turns a refused value into an
    accepted one, nor the reverse. Order and repeats are kept.

    The views run it on every `resource` before DOT reads one: at
    `/o/authorize/` on the query string and the consent form's field, so
    the grant stores this spelling, and at `/o/token/` on the form body (a
    token POST with a query string is refused by oauthlib), so the token
    request carries the same string as the grant (DOT compares the two as
    strings) and a token minted from a resource-less grant is bound to it
    too.
    """
    accepted = _accepted_keys(request)
    canonical = canonical_resource_url(request)
    return [
        canonical if _names_the_resource(value, accepted) else value for value in values
    ]


def _resource_identity(value: str) -> tuple[str, str, str] | None:
    """`_resource_key` of `value` with one trailing slash dropped from the
    path; None for a non-ASCII value, an unparseable port or no authority."""
    if not value.isascii():
        return None
    key = _resource_key(value)
    if key is None or not key[1]:
        return None
    scheme, authority, path = key
    return scheme, authority, path.removesuffix("/")


def same_resource(first: str, second: str) -> bool:
    """True when `first` and `second` are two spellings of one resource by
    the normalisation `foreign_resource` applies: scheme and host
    case-insensitive, the default port explicit or omitted, the path equal
    up to one trailing slash (nothing else normalised). Without its
    acceptance rule: two spellings of the bare origin match too, so a
    caller passes at least one value `foreign_resource` already accepted
    (`use_granted_spelling`: the token request's, which `MCPTokenView`
    checked)."""
    identity = _resource_identity(first)
    return identity is not None and identity == _resource_identity(second)


def _requested_resources(request: Any) -> list[str]:
    """The token request's `resource` values as DOT reads them in
    `_check_and_set_request_resource`: oauthlib keeps one value (the form
    body's last, else the query string's), and DOT recovers repeated body
    values from `decoded_body`."""
    resource = getattr(request, "resource", None)
    if isinstance(resource, list):
        return resource
    if not isinstance(resource, str) or not resource.strip():
        return []
    body = [
        value
        for key, value in (getattr(request, "decoded_body", None) or [])
        if key == "resource"
    ]
    return body if len(body) > 1 else [resource]


def _stored_resources(request: Any) -> list[str]:
    """The `resource` list DOT holds this token request to: the
    authorization code's grant's (looked up as DOT does), or the refresh
    token's. Empty when it carries none."""
    stored: Any = None
    if request.grant_type == "authorization_code":
        stored = (
            get_grant_model()
            .objects.filter(code=request.code, application=request.client)
            .values_list("resource", flat=True)
            .first()
        )
    elif request.grant_type == "refresh_token":
        instance = getattr(request, "refresh_token_instance", None)
        stored = getattr(instance, "resource", None)
    if not isinstance(stored, list):
        return []
    return [value for value in stored if isinstance(value, str)]


def use_granted_spelling(request: Any) -> None:
    """At token issuance, put each requested `resource` in the grant's (or
    refresh token's) own spelling when it is another spelling of one of
    them (`same_resource`).

    `MCPTokenView` sends DOT `canonical_resource_url`, and a grant or
    refresh token issued since then stores that same string. One issued
    before (an authorization code granted just before the upgrade, a
    refresh token from an earlier build) may store another accepted
    spelling — the slashed one, an uppercase host — and DOT compares the
    two as strings: without this the exchange would get DOT's
    `invalid_target`. Values that name nothing stored are left for DOT to
    refuse; the token is bound to the stored string, which names the same
    resource. Called by `oauth.MCPOAuth2Validator.save_bearer_token`, before
    DOT reads `request.resource`.
    """
    requested = _requested_resources(request)
    if not requested:
        return
    stored = _stored_resources(request)
    if not stored:
        return
    matched = [
        next(
            (
                value
                for value in stored
                if isinstance(wanted, str) and same_resource(wanted, value)
            ),
            wanted,
        )
        for wanted in requested
    ]
    if matched != requested:
        request.resource = matched


def invalid_target_error(request: HttpRequest, **kwargs: Any) -> CustomOAuth2Error:
    """RFC 8707 §2 `invalid_target`, naming the resource that is accepted.

    The description carries only the public discovery value, never the
    client's own (it is echoed into a redirect). `kwargs` go to oauthlib's
    error (`state`, ...).
    """
    return CustomOAuth2Error(
        error="invalid_target",
        description=(
            "resource must be this server's MCP endpoint, "
            f"{mcp_resource_url(request)} (with or without the trailing slash)."
        ),
        status_code=400,
        **kwargs,
    )


class CanonicalUriOAuthLibCore(OAuthLibCore):
    """DOT's form-body `OAuthLibCore`, handing oauthlib the request URL built
    as discovery builds `resource` (`consts.absolute_url`).

    DOT (3.4+) audience-checks a resource-bound token against the request
    URL, made absolute with `request.build_absolute_uri`, whose scheme is
    `request.scheme`: `http` behind a TLS-terminating proxy unless the project
    sets `SECURE_PROXY_SSL_HEADER`, while discovery advertises `https`
    whenever `DEBUG` is off. Returning the URL already absolute here makes
    DOT's `build_absolute_uri` a no-op (an absolute location is kept as is),
    so both sides use one scheme and host rule (the host in canonical form:
    lowercased, default port left out). Below DOT 3.4 the URL is not
    compared with anything. Used for the bearer check on `/mcp/sql/` only.
    """

    def _extract_params(self, request: Any) -> tuple[str, str, str, dict[str, Any]]:
        uri, http_method, body, headers = super()._extract_params(request)
        return absolute_url(request, uri), http_method, body, headers
