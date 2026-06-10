# Contributing to django-mcp-sql

## Before anything else

Read `docs/architecture.md`. This package is a security boundary; most
design decisions that look odd (parser check ordering, fenced tool results,
`SET LOCAL`-only, the executor's alias assert) are pinned contracts with
tests and rationale there. PRs that relax one of those without addressing
the documented threat model will be declined.

## Dev setup

```sh
# uv once: curl -LsSf https://astral.sh/uv/install.sh | sh
make test            # creates .venv-test, installs -e .[allauth,test], runs pytest
```

The suite needs a reachable PostgreSQL with `mcp_readonly_role` bootstrapped
(`sql/role_setup.sql`); connection env vars and their defaults are at the
top of `tests/settings.py`. Run against a superuser connection so the
role-isolation tests execute instead of skipping. CI runs the same suite on
Python 3.11–3.13 × PostgreSQL 14.

## Expectations

- **Tests**: every behaviour change comes with a test; the suite must stay
  consumer-agnostic (no imports from any consuming project — override-seams
  in `tests/conftest.py` exist for consumer-specific fixtures).
- **Lint**: ruff (format + lint) for Python; djLint for templates (config in
  `pyproject.toml`).
- **Migrations**: never edit an applied migration; curated-view migrations
  belong in the consumer's owning app, not here.
- **CHANGELOG**: add a line under `## Unreleased` in `CHANGELOG.md`.
- **Dependencies**: floors/caps in `pyproject.toml` carry rationale
  comments — a cap bump needs the CI matrix green and a review of the
  comment's claim.
