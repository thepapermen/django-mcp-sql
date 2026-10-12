# Hand-written data migration: creates the curated OAuth Application that
# Claude Code (and any future MCP client) registers against this server.
# A "never write migrations by hand" convention applies to schema migrations;
# data migrations use RunPython by definition.
#
# Design notes:
# - One Application total. `MCPOAuth2Validator.validate_client_id` rejects
#   any non-MCP Application name, so additional rows here would be unreachable.
# - `client_type=public`: native CLI client (no client_secret). PKCE
#   compensates for the missing secret.
# - `authorization_grant_type=authorization-code` only. No password / client
#   credentials / implicit grants.
# - `skip_authorization=True`: removes the "Allow Claude Code to access
#   mcp:sql?" consent page. The issuance gate in `MCPAuthorizationView`
#   already gated this; the consent page adds friction without security.
# - `redirect_uris="http://127.0.0.1"`: per RFC 8252 §7.3, native-app OAuth
#   uses loopback redirects, and DOT 3.x's `redirect_to_uri_allowed` accepts
#   any PORT at request time on `http://127.0.0.1` (and `::1`) while still
#   requiring path-exact-match. `http://localhost` is deliberately NOT
#   registered: DOT 3.x does not treat `localhost` as a loopback hostname
#   in its matcher, so a registered bare `http://localhost` would only
#   match a literal `http://localhost` (no port, no path) — useless for
#   ephemeral-port clients. Claude Code uses `127.0.0.1` per the
#   RFC 8252 §8.3 recommendation, so the one-URI list is sufficient.
# - `client_id` mirrors the Application name. Public clients don't need an
#   unguessable client_id (the security boundary is PKCE + the issuance
#   gate). Deterministic value keeps env config identical and lets
#   Claude Code's mcp config templates be parametrised cleanly.

from django.db import migrations


def create_application(apps, schema_editor):
    # Application name is sourced from `mcp_sql_settings.APPLICATION_NAME`
    # at APPLY time (default `"mcp-sql"`). A consumer who overrides
    # `MCP_SQL["APPLICATION_NAME"]` AFTER initial deploy must follow up
    # with a rename migration — see mcp_sql_integration.md "Renaming
    # MCP_SQL identifiers after initial deploy".
    from mcp_sql.conf import mcp_sql_settings

    Application = apps.get_model("oauth2_provider", "Application")
    name = mcp_sql_settings.APPLICATION_NAME
    Application.objects.update_or_create(
        name=name,
        defaults={
            "client_id": name,
            "client_secret": "",
            "client_type": "public",
            "authorization_grant_type": "authorization-code",
            "skip_authorization": True,
            "redirect_uris": "http://127.0.0.1",
            "algorithm": "",
        },
    )


def delete_application(apps, schema_editor):
    from mcp_sql.conf import mcp_sql_settings

    Application = apps.get_model("oauth2_provider", "Application")
    Application.objects.filter(name=mcp_sql_settings.APPLICATION_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("mcp_sql", "0004_create_mcp_sql_users_group"),
        ("oauth2_provider", "0013_alter_application_authorization_grant_type_device"),
    ]

    operations = [
        migrations.RunPython(create_application, reverse_code=delete_application),
    ]
