"""RFC 9728 Protected Resource Metadata + RFC 8414 Authorization Server
Metadata at `.well-known/...` endpoints. Anonymous GET, CSRF-exempt,
no side effects. See `docs/architecture.md` "OAuth surface"
+ "Watch out" host-trust bullet for the full design rationale."""

from django.conf import settings
from django.http import HttpRequest
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from mcp_sql.conf import mcp_sql_settings


def _issuer(request: HttpRequest) -> str:
    """The AS issuer identity — host + `/o`, no trailing slash.

    The AS is mounted under `/o/` (DOT convention). RFC 8414 §3.1 supports
    issuers with a path component; the metadata URL then becomes
    `/.well-known/oauth-authorization-server/o` (path is appended after
    `.well-known/oauth-authorization-server`). Using a scoped issuer is
    more honest than claiming the bare host is the AS — the host serves
    plenty else (admin, API, the MCP transport itself).

    RFC 8414 §2 requires the issuer to be an https URL except for
    loopback / development. Stage and prod trust traefik's
    `X-Forwarded-Proto: https` via `SECURE_PROXY_SSL_HEADER`, so
    `request.scheme` is honest after middleware unpacking. As defense
    in depth against a misbehaving reverse proxy, we force `https`
    whenever `DEBUG` is off — under that condition the project is
    unambiguously a non-loopback deploy. Local dev (`DEBUG=True`) keeps
    `request.scheme` so http is honest.
    """
    scheme = request.scheme if settings.DEBUG else "https"
    return f"{scheme}://{request.get_host()}/o"


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

    `bearer_methods_supported: ["header"]` reflects DOT 3.2.0's behavior:
    `oauth2_provider.contrib.rest_framework.OAuth2Authentication` only
    reads bearer tokens from the `Authorization` header. We don't add a
    body/query rejection path because DOT doesn't have a body/query
    acceptance path to override.
    """
    return _cors(
        JsonResponse(
            {
                "resource": request.build_absolute_uri(reverse("mcp_sql_endpoint")),
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

    `code_challenge_methods_supported: ["S256"]` is the canonical
    advertisement of the S256-only PKCE posture; the matching enforcement
    lives in `oauth.py::MCPOAuth2Validator.validate_code_challenge_method`.
    `token_endpoint_auth_methods_supported: ["none"]` reflects the
    public-client setup (no client_secret); same posture applies to the
    revocation endpoint per RFC 8414 §2.
    """
    return _cors(
        JsonResponse(
            {
                "issuer": _issuer(request),
                "authorization_endpoint": request.build_absolute_uri(
                    reverse("authorize")
                ),
                "token_endpoint": request.build_absolute_uri(reverse("token")),
                "revocation_endpoint": request.build_absolute_uri(
                    reverse("revoke-token")
                ),
                "registration_endpoint": request.build_absolute_uri(
                    reverse("oauth_dynamic_client_registration")
                ),
                "scopes_supported": [mcp_sql_settings.SCOPE],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "revocation_endpoint_auth_methods_supported": ["none"],
            }
        )
    )
