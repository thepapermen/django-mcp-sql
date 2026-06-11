# Build / test-install targets for the django-mcp-sql package.
#
# Runs ON THE HOST (not in Docker) — packaging tooling (`uv`, `build`)
# is host-side, not part of the consuming project's container image.
# Install uv once: `curl -LsSf https://astral.sh/uv/install.sh | sh`.
#
# Invoke from this directory (`cd source/mcp_sql && make <target>`) or
# from anywhere via `make -C source/mcp_sql <target>`. Targets ship with
# the package, so after extraction they're at the package repo root.

.PHONY: help build test test-install typecheck clean

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the wheel + sdist into ./dist/ (requires uv).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	rm -rf dist *.egg-info
	uv build
	@echo ""
	@echo "Built artifacts:"
	@ls -la dist/

# `--pyargs` (collect via the installed package name) instead of a path:
# post-extraction the package contents ARE the repo root, whose checkout
# basename (`django-mcp-sql`) is not a valid module name for path-based
# collection.
test: ## Run the package test suite standalone (requires uv + a reachable PG; see tests/settings.py for the MCP_SQL_TEST_PG_* env vars).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	uv venv .venv-test --python python3 --allow-existing
	uv pip install --python .venv-test/bin/python -e '.[allauth,test]'
	.venv-test/bin/python -m pytest --pyargs mcp_sql.tests --create-db --nomigrations

hooks: ## Install the pre-commit git hook (run once per clone).
	@command -v pre-commit >/dev/null || { echo "pre-commit not found — install with: pipx install pre-commit (or pip install pre-commit)"; exit 1; }
	pre-commit install

lint: ## Run every pre-commit hook across all files (same gate as CI's lint job).
	@command -v pre-commit >/dev/null || { echo "pre-commit not found — install with: pipx install pre-commit (or pip install pre-commit)"; exit 1; }
	pre-commit run --all-files

cov: ## Run the suite with coverage; write term-missing + coverage.xml (same config CI uploads to Codecov).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	uv venv .venv-test --python python3 --allow-existing
	uv pip install --python .venv-test/bin/python -e '.[allauth,test]'
	.venv-test/bin/python -m pytest --pyargs mcp_sql.tests --create-db --nomigrations --cov=mcp_sql --cov-report=term-missing --cov-report=xml

typecheck: ## Type-check the package with mypy + django/DRF stubs (same gate as CI's typecheck job; requires uv).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	uv venv .venv-test --python python3 --allow-existing
	uv pip install --python .venv-test/bin/python -e '.[allauth,test,typecheck]'
	# `package-dir = {"mcp_sql" = "."}` self-roots the package, but its
	# checkout dir is named `django-mcp-sql`; expose the tree under its real
	# import name so `mypy -p mcp_sql` resolves it (config: [tool.mypy]).
	mkdir -p .mypy-pkg && ln -sfn .. .mypy-pkg/mcp_sql
	.venv-test/bin/python -m mypy -p mcp_sql

test-install: ## Build the wheel, install into a fresh venv, run import smoke (ephemeral; requires uv).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	rm -rf /tmp/mcp_sql_dist /tmp/mcp_sql_test_venv *.egg-info
	uv build --out-dir /tmp/mcp_sql_dist
	@set -e; \
	SDIST=$$(ls /tmp/mcp_sql_dist/django_mcp_sql-*.tar.gz | head -1); \
	echo "--- Sdist contents (package data in, tests out) ---"; \
	tar -tzf $$SDIST | grep -q 'templates/mcp_sql/authorize.html' || { echo "sdist missing templates"; exit 1; }; \
	tar -tzf $$SDIST | grep -q 'docs/architecture.md' || { echo "sdist missing docs"; exit 1; }; \
	tar -tzf $$SDIST | grep -q 'sql/role_setup.sql' || { echo "sdist missing sql"; exit 1; }; \
	! tar -tzf $$SDIST | grep -q '/tests/' || { echo "sdist leaks tests/ (MANIFEST.in prune broken)"; exit 1; }; \
	WHEEL=$$(ls /tmp/mcp_sql_dist/django_mcp_sql-*.whl | head -1); \
	echo "Verifying wheel install: $$WHEEL"; \
	uv venv /tmp/mcp_sql_test_venv --python python3; \
	VENV_PY=/tmp/mcp_sql_test_venv/bin/python; \
	uv pip install --python $$VENV_PY $$WHEEL; \
	echo "--- Import smoke (Django-independent modules only) ---"; \
	$$VENV_PY -c 'import mcp_sql, importlib.metadata as m; assert m.version("django-mcp-sql") == mcp_sql.__version__, (m.version("django-mcp-sql"), mcp_sql.__version__)'; \
	$$VENV_PY -c 'from mcp_sql.conf import mcp_sql_settings, DEFAULTS, IMPORT_STRINGS'; \
	$$VENV_PY -c 'from mcp_sql.consts import is_mcp_application_name'; \
	$$VENV_PY -c 'from mcp_sql.schemas import OutcomeReason, QueryResult, HINTS, AuthRejectionReason'; \
	$$VENV_PY -c 'from mcp_sql.validation import validate_mcp_sql_settings, McpSqlSettings, McpSqlLimits'; \
	$$VENV_PY -c 'from mcp_sql.parser import parse_and_validate, inject_limit, extract_limit, QueryRejectedError'; \
	$$VENV_PY -c 'from mcp_sql.session import enter_readonly_session, session_drift, EXPECTED_SESSION_GUCS'; \
	echo "--- Package data ships ---"; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "py.typed").is_file(), "py.typed missing (PEP 561 marker not shipped)"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "sql/role_setup.sql").is_file(), "role_setup.sql missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "sql/10_mcp_role.sh").is_file(), "10_mcp_role.sh missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "docs/role-setup.md").is_file(), "role-setup.md missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "docs/oauth.md").is_file(), "oauth.md missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "docs/architecture.md").is_file(), "architecture.md missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "templates/mcp_sql/authorize.html").is_file(), "authorize.html missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "templates/admin/mcp_sql/usage_summary.html").is_file(), "usage_summary.html missing"'; \
	$$VENV_PY -c 'import importlib.resources as r; assert (r.files("mcp_sql") / "templates/admin/mcp_sql/mcpquerylog_change_list.html").is_file(), "mcpquerylog_change_list.html missing"'; \
	echo "--- All checks passed ---"; \
	echo "Wheel install + import smoke + package-data check: OK"; \
	echo "(Django-coupled modules — auth, executor, views, urls, signals, models, admin — require apps-registry setup; verified by the example-app integration tests.)"

clean: ## Remove build + coverage + typecheck artifacts (dist/, build/, *.egg-info, .venv-test/, coverage.xml, .coverage, htmlcov/, .mypy-pkg/, .mypy_cache/).
	rm -rf dist build *.egg-info .venv-test coverage.xml .coverage htmlcov .mypy-pkg .mypy_cache
