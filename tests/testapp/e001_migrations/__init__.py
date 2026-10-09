"""Migration modules for `tests/test_checks.py`'s pending-migration cases
(`mcp_sql.E001` is not raised for an app with migrations still to apply):
`MIGRATION_MODULES` points the test app at one of them per test.

- `creates`: creates the whitelisted relation in `public`, as the
  migration that adds a model does.
- `noop`: changes nothing, so the relation is still only elsewhere after
  `migrate`.
"""
