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
make typecheck       # mypy + django/DRF stubs over the package (CI's typecheck job)
make hooks           # installs the pre-commit git hook (run ONCE per clone)
```

The hooks are **not** installed automatically by cloning — `make hooks` (i.e.
`pre-commit install`) wires them into `.git/hooks`. It installs two stages:
the fast lint/format gate on every `git commit`, and a **pre-push** `mypy`
hook (`make typecheck`) that type-checks before a push — slower and
venv-dependent, so it runs once per push rather than per commit. Tests are
deliberately not a hook (they need a live PostgreSQL). The same checks run in
CI (the `lint` and `typecheck` jobs), so a PR that skipped the local install
still gets caught; `make lint` / `make typecheck` run them on demand.

The suite needs a reachable PostgreSQL with `mcp_readonly_role` bootstrapped
(`sql/role_setup.sql`); connection env vars and their defaults are at the
top of `tests/settings.py`. Run against a superuser connection so the
role-isolation tests execute instead of skipping. CI runs the same suite
across the Django 4.2/5.2/6.0 lines on their supported interpreters
(Python 3.11–3.13) × PostgreSQL 14 (see the matrix in
`.github/workflows/ci.yml`).

## Expectations

- **Tests**: every behaviour change comes with a test; the suite must stay
  consumer-agnostic (no imports from any consuming project — override-seams
  in `tests/conftest.py` exist for consumer-specific fixtures).
- **Lint**: the pre-commit gate (`.pre-commit-config.yaml`) — ruff (lint +
  format), djLint for templates, django-upgrade (targeted at the 4.2 floor),
  and the standard hygiene hooks; ruff/djLint config live in `pyproject.toml`.
  Run `make lint` (or let the hooks fire on commit).
- **Types**: the package ships `py.typed`, so its annotations are part of the
  published contract — keep `make typecheck` green (mypy with the django-stubs
  + DRF-stubs plugins; config in `[tool.mypy]`). The public surface is
  annotated; you need not annotate every internal helper, but untyped-def
  bodies are still checked.
- **Migrations**: never edit an applied migration; curated-view migrations
  belong in the consumer's owning app, not here.
- **CHANGELOG**: add a line under `## Unreleased` in `CHANGELOG.md`.
- **Dependencies**: floors/caps in `pyproject.toml` carry rationale
  comments — a cap bump needs the CI matrix green and a review of the
  comment's claim.
