from django.core.management.base import BaseCommand
from mcp_sql.conf import mcp_sql_settings


class Command(BaseCommand):
    help = (
        "Print the declared MCP clients from MCP_SQL['CLIENTS'] — each one's "
        "client_id and callback URLs. The client_id is what an operator pastes "
        "into the provider's connector form (Claude.ai, ChatGPT) or into a "
        "Cursor mcp.json `auth.CLIENT_ID`, always with a blank secret; the "
        "callbacks are what the provider must have registered on its side. "
        "`migrate` logs the same values, but this reads them back on demand "
        "instead of requiring a scroll through deploy output. Reports settings "
        "only — it does not touch the database, so a client listed here that "
        "was never migrated has no Application row yet."
    )

    def handle(self, *args, **options):
        clients = mcp_sql_settings.clients()
        if not clients:
            self.stdout.write(
                "MCP_SQL['CLIENTS'] is empty — no declared clients. The MCP "
                "surface is reachable only by the curated Application and by "
                "clients that self-register at /o/register (loopback only)."
            )
            return

        for client in sorted(clients.values(), key=lambda c: c.name):
            self.stdout.write(self.style.MIGRATE_HEADING(client.label))
            self.stdout.write(f"  kind:      {client.kind.value}")
            self.stdout.write(f"  client_id: {client.client_id}")
            self.stdout.write("  secret:    (leave blank — public PKCE client)")
            for rule in client.redirects:
                self.stdout.write(f"  callback:  {rule.uri} ({rule.match})")
