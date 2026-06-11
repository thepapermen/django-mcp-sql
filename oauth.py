"""Custom DOT validator pinned to mcp-sql Applications + the single
`mcp:sql` scope. S256-only PKCE enforcement lives here too. See
`docs/architecture.md` "OAuth surface" for the full picture
(consent-screen asymmetry, audience-binding policy, prefix semantics)."""

from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from oauth2_provider.models import Application
from oauth2_provider.oauth2_validators import OAuth2Validator


class MCPOAuth2Validator(OAuth2Validator):
    """Validator pinned to the mcp-sql Application surface + the single scope."""

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Accept the request only if `client_id` resolves to an mcp-sql Application.

        DOT's default looks up by `client_id` and binds the Application onto
        `request.client`. We let it do that, then verify the resulting
        Application is the curated `mcp-sql` row OR a dynamically-registered
        `mcp-sql-<token>` row. An Application whose name doesn't match
        either shape (e.g. some unrelated OAuth client added later) is
        rejected here.
        """
        if not super().validate_client_id(client_id, request, *args, **kwargs):
            return False
        app = (
            getattr(request, "client", None)
            or Application.objects.filter(client_id=client_id).first()
        )
        return app is not None and is_mcp_application_name(app.name)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Reject any token request that asks for scopes other than `mcp:sql`."""
        if not scopes:
            return False
        # Reject anything with extra or different scopes. `scopes` is a list of strings.
        if set(scopes) != {mcp_sql_settings.SCOPE}:
            return False
        return super().validate_scopes(
            client_id, scopes, client, request, *args, **kwargs
        )

    def validate_code_challenge_method(self, request, code_challenge_method):
        """Accept only `S256`; reject `plain` (and any other method).

        oauthlib accepts both `S256` and `plain` at runtime by default. The
        OAUTH2_PROVIDER comment in `settings/base.py` flags this as a known
        gap — `plain` PKCE is equivalent to no PKCE if the verifier ever
        leaks, which gives a weaker guarantee than `S256` for negligible
        client-side cost. The RFC 8414 discovery doc advertises only
        `S256`; this validator ensures the server actually enforces what
        the discovery doc promises.
        """
        return code_challenge_method == "S256"
