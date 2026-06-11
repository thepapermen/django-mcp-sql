# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.1.0b1 - unreleased

### Added

- Django 4.2 LTS and Django 6.0 support, alongside the existing 5.2 LTS line
  (`Framework :: Django` 4.2/5.2/6.0). No source changes were needed — the
  package uses no Django-version-specific APIs.
- CI expanded to a ragged Django × Python matrix (4.2, 5.2, 6.0 against their
  respective supported interpreters), plus a pinned leg verifying the package
  on DRF 3.14 + Django 4.2 — i.e. drop-in into an app that already pins an
  older DRF.
- `py.typed` marker (PEP 561): the package now ships its inline type
  annotations, so a consumer's type checker reads `mcp_sql`'s types instead
  of treating it as untyped. A `typecheck` extra (`mypy` + `django-stubs` +
  `djangorestframework-stubs`), a `[tool.mypy]` config, a `make typecheck`
  target, and a CI `typecheck` job keep those annotations honest (the public
  surface is annotated; untyped-def bodies are still checked).

### Changed

- Promoted from alpha to **Beta** (`Development Status :: 4 - Beta`).
- Dependency floor `django>=4.2,<6.1` (was `>=5.2,<6.0`).
- Dependency floor `djangorestframework>=3.14` (was `>=3.15.2`): 3.14 is the
  lowest DRF supported — what a legacy Django 4.2 app already pins — so the
  package drops into such a stack without forcing a DRF upgrade. Support is a
  staircase (5.x needs DRF ≥3.15, 6.0 needs ≥3.17); a greenfield install
  resolves the newest in-range DRF for whatever Django it runs.

## 0.1.0a1 - unreleased

First alpha. The feature set below has been exercised in production as part
of a larger Django CRM; the standalone distribution itself is pre-release.

### Added

- Three MCP tools over Streamable HTTP at `/mcp/sql/`: `list_tables`,
  `describe_table`, `run_query` (single validated SELECT).
- sqlglot-backed AST parser gate: single SELECT-shaped statement, scope-aware
  table whitelist, system-schema and function deny-lists, no
  `SELECT *` (configurable), no writeable CTEs, no OFFSET/FETCH/locking
  reads, no set-returning functions in the projection.
- Read-only executor: dedicated `mcp_readonly` Django DB alias,
  `SET LOCAL ROLE` into a Postgres NOLOGIN role with statement-level guard
  GUCs, most-restrictive-wins row caps with LIMIT N+1 truncation detection,
  per-cell and total byte caps.
- Append-only audit: one `MCPQueryLog` row per `run_query` call (every code
  path) and one `MCPAuthRejectionLog` row per resolved-user auth rejection;
  read-only Django admin browsers plus a per-user usage-summary view.
- OAuth 2.1 surface via django-oauth-toolkit: authorization-code + PKCE
  (S256 only), public client, 6h tokens, no refresh tokens; RFC 7591
  dynamic client registration (loopback-only redirect URIs), RFC 8414 +
  RFC 9728 discovery documents; issuance gate and per-request re-validation
  (active staff + MFA + unambiguous profile + optional session-existence
  check); logout revokes tokens.
- Multi-profile access tiers: N profiles in `MCP_SQL["PROFILES"]`, each its
  own Postgres role, whitelist, Django permission and group;
  explicit-assignment binding (superuser confers nothing); config-derived
  group/permission provisioning via post_migrate; dormant per-profile
  `SESSION_CONTEXT` hook for per-user row scoping recipes.
- Prompt-injection fencing: `run_query` rows/error wrapped in a per-response
  random-UUID `<untrusted-data-…>` fence with a `data_handling` instruction;
  standing security posture delivered via MCP `initialize` instructions.
- Grants tooling: `mcp_sql_grants` (drift check / `--apply`),
  `mcp_sql_role_setup --emit-sql` (N-role bootstrap SQL),
  `mcp_sql_smoke` (session-contract + end-to-end executor smoke),
  `mcp_sql_lint` (column-add review gate); idempotent
  `sql/role_setup.sql` + Docker init wrapper.
- Observability: per-user query-volume tripwires (alert, never block),
  group-add alerts, silent per-IP throttle on bad-token probing and
  anonymous registration.
- Standalone test suite (`tests/settings.py`, stock Django + Postgres) and
  GitHub Actions CI (Python 3.11–3.13 × PostgreSQL 14).
