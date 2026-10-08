"""RFC 9728 Protected Resource Metadata + RFC 8414 Authorization Server
Metadata at `.well-known/...` endpoints. Anonymous GET, CSRF-exempt,
no side effects. See `docs/architecture.md` "OAuth surface"
+ "Watch out" host-trust bullet for the full design rationale."""

from django.http import HttpRequest
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from mcp_sql.audience import mcp_resource_url
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.conf import refresh_tokens_enabled
from mcp_sql.consts import absolute_url


def _grant_types_supported() -> list[str]:
    """`authorization_code`, plus `refresh_token` when the opt-in refresh
    grant is on — shared by the AS metadata and the DCR response."""
    if refresh_tokens_enabled():
        return ["authorization_code", "refresh_token"]
    return ["authorization_code"]


def _issuer(request: HttpRequest) -> str:
    """The AS issuer identity — host + `/o`, no trailing slash.

    The AS is mounted under `/o/` (DOT convention). RFC 8414 §3.1 supports
    issuers with a path component; the metadata URL then becomes
    `/.well-known/oauth-authorization-server/o` (path is appended after
    `.well-known/oauth-authorization-server`). Using a scoped issuer is
    more honest than claiming the bare host is the AS — the host serves
    plenty else (admin, API, the MCP transport itself).

    RFC 8414 §2 requires the issuer to be an https URL except for
    loopback / development; `consts.absolute_url` is what enforces that, and
    every other URL in both discovery documents (and the 401 challenge's
    `resource_metadata` pointer) goes through the same helper so the whole
    surface agrees on one origin.
    """
    return absolute_url(request, "/o")


def _resource_identifier(request: HttpRequest) -> str:
    """The RFC 9728 `resource` value, spelled the way the client asked for it.

    RFC 9728 §3.3 requires the returned `resource` to be *identical* to the
    resource identifier the client inserted the well-known suffix into, and
    says the document "MUST NOT be used" on mismatch. Clients disagree on
    trailing-slash normalisation — Cursor Desktop requests the slash-less
    metadata path and then enforces §3.3 (it aborts the dance after consent,
    before the token exchange); Claude Code requests the same path but does
    not enforce; Claude.ai's web connector strips the slash off the transport
    POST instead. Advertising one fixed spelling therefore breaks whichever
    half of the ecosystem normalises the other way.

    So `urls.py` serves this document at BOTH `.../mcp/sql` and
    `.../mcp/sql/`, and we echo whichever spelling was used. That satisfies
    both clauses of §3.3: a client that built the metadata URL from its own
    identifier gets that identifier back, and a client that followed the 401
    `resource_metadata` pointer gets the URL it sent the request to, because
    `auth.MCPOAuth2Authentication.authenticate_header` picks the pointer's
    spelling from the request path. (A client that requests `/mcp/sql/` but
    then builds a slash-less metadata URL on its own — or vice versa — is
    comparing two different identifiers, and no single document can satisfy
    it.) Both spellings route to the same transport view, so the audience a
    client derives from this value reaches the same endpoint either way.
    Nothing here is attacker-controlled: `request.path` can only be one of the
    two literal routes Django matched.

    The value is built by `audience.mcp_resource_url`, which is also what
    `/o/authorize/` and `/o/token/` compare an RFC 8707 `resource` with and
    how `/mcp/sql/` builds the URL DOT audience-checks a token against, so
    the advertised identifier is the one a token can be bound to.
    """
    canonical = mcp_resource_url(request)
    if request.path.endswith("/"):
        return canonical
    return canonical.removesuffix("/")


def _cors(response: JsonResponse) -> JsonResponse:
    # Public discovery metadata — wildcard origin is appropriate because
    # the payload carries no per-origin secret. `Allow-Methods` matches
    # `@require_safe` (GET + HEAD); OPTIONS is deliberately absent so the
    # advertisement does not lie about a method the view rejects with 405.
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "GET, HEAD"
    return response


@csrf_exempt
@require_safe
def protected_resource_metadata(request):
    """RFC 9728 Protected Resource Metadata for the MCP SQL surface.

    `bearer_methods_supported: ["header"]` is enforced by the package, not by
    DOT's default: oauthlib's stock bearer handler would also take an
    `access_token` from the query string or a form body, but
    `MCPOAuth2Authentication` verifies on `oauth_server.MCPServer`, whose
    `HeaderOnlyBearer` reads the `Authorization` header only.

    Served at two paths; `resource` echoes the one used — see
    `_resource_identifier` for why.
    """
    return _cors(
        JsonResponse(
            {
                "resource": _resource_identifier(request),
                # Sourced from `MCP_SQL["RESOURCE_NAME"]` (defaults to
                # "MCP SQL"; consuming projects typically override this so
                # discovery / `claude mcp add <name> ...` slugs stay
                # env-distinct).
                "resource_name": mcp_sql_settings.RESOURCE_NAME,
                "authorization_servers": [_issuer(request)],
                "scopes_supported": [mcp_sql_settings.SCOPE],
                "bearer_methods_supported": ["header"],
            }
        )
    )


@csrf_exempt
@require_safe
def authorization_server_metadata(request):
    """RFC 8414 Authorization Server Metadata for the DOT-backed AS.

    `response_types_supported`, `grant_types_supported` and
    `code_challenge_methods_supported` are what the package's endpoints
    enforce: they run on `oauth_server.MCPServer`, whose only grant is
    `authorization_code` with the `code` response type, accepting only
    `S256` PKCE (a stored non-S256 grant is refused at /o/token/ by
    `oauth.py::MCPOAuth2Validator.get_code_challenge_method`), plus
    `refresh_token` exactly when `MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]`
    enables it; `MCPTokenView` refuses every other `grant_type`.
    `token_endpoint_auth_methods_supported: ["none"]` reflects the
    public-client setup (no client_secret); same posture applies to the
    revocation endpoint per RFC 8414 §2.
    """
    return _cors(
        JsonResponse(
            {
                "issuer": _issuer(request),
                "authorization_endpoint": absolute_url(request, reverse("authorize")),
                "token_endpoint": absolute_url(request, reverse("token")),
                "revocation_endpoint": absolute_url(request, reverse("revoke-token")),
                "registration_endpoint": absolute_url(
                    request, reverse("oauth_dynamic_client_registration")
                ),
                "scopes_supported": [mcp_sql_settings.SCOPE],
                "response_types_supported": ["code"],
                "grant_types_supported": _grant_types_supported(),
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "revocation_endpoint_auth_methods_supported": ["none"],
            }
        )
    )
