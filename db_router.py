"""Keep schema off the read-only execution alias.

`MCP_SQL["DB_ALIAS"]` is a read-only *lens* onto a database another alias
owns (or a read replica); the executor reaches it only through an explicit
`connections[DB_ALIAS]`. Django can't tell that two aliases share one
database (or that one is a replica), so left alone it treats the alias as
its own database and tries to build/track schema there — a per-alias
`migrate`, or the test runner's per-alias setup, would re-run DDL against a
database `default` already owns (or fail outright on a read-only role).
This router's one job is to tell Django not to.

Deliberately minimal: it owns a single universal invariant — never migrate
`DB_ALIAS` — and abstains from every other routing decision. Where the audit
models live is left to the consumer's config: with no router opinion Django
uses the `default` alias for the ORM, and the migrate ban already keeps their
tables off `DB_ALIAS`. No consumer-topology assumption (e.g. a literal
`"default"` home for mcp_sql's own tables) is baked in. See `docs/architecture.md`
file-map row for `db_router.py`.
"""

from mcp_sql.conf import mcp_sql_settings


class McpSqlRouter:
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # No app — not mcp_sql's own audit tables, not the consumer's — ever
        # builds or tracks schema through the read-only lens. Returning False
        # is order-independent (any router's False blocks a migration), which
        # is why this, not a `db_for_write` pin, is the real guarantee. The
        # read path is kept on `DB_ALIAS` by the executor's explicit
        # `connections[DB_ALIAS]` + alias assert, which routers can't touch.
        if db == mcp_sql_settings.DB_ALIAS:
            return False
        return None
