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
  the package's views on every DOT version, so DOT below 3.4 (which ignores
  `resource`) answers the same.
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
from oauth2_provider.oauth2_backends import OAuthLibCore
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error


def mcp_resource_url(request: HttpRequest) -> str:
    """The MCP endpoint's RFC 9728 `resource` identifier, trailing slash
    included — the spelling `reverse()` builds; discovery serves it with and
    without the slash."""
    return absolute_url(request, reverse("mcp_sql_endpoint"))


def _resource_key(value: str) -> tuple[str, str, str]:
    """`(scheme, authority, path)` of `value` split as an absolute URL, scheme
    lowercased and authority in `consts.canonical_authority` form.

    Plain slicing at the first `://` and the next `/`, deliberately not
    `urlsplit` (which drops tab / CR / LF and strips leading control
    characters and spaces): nothing is decoded, stripped or resolved, so a
    query, fragment, userinfo, whitespace or control character anywhere
    leaves a part that differs from the endpoint's.
    """
    scheme, _, rest = value.partition("://")
    authority, slash, path = rest.partition("/")
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
    foreign.

    Every accepted spelling passes DOT's default bearer audience check
    (`validate_resource_as_url_prefix` compares the parsed scheme, host,
    port and path the same way) against the request URL
    `CanonicalUriOAuthLibCore` builds, which is the canonical one.
    """
    scheme, authority, path = _resource_key(mcp_resource_url(request))
    accepted = {(scheme, authority, path), (scheme, authority, path.removesuffix("/"))}
    return next(
        (
            value
            for value in values
            # Non-ASCII first: `str.lower` folds some of it to ASCII (the
            # Kelvin sign U+212A to `k`).
            if not value.isascii() or _resource_key(value) not in accepted
        ),
        None,
    )


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
