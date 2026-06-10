# Example project: stock-Django consumer of django-mcp-sql.
#
# Runs entirely on the host using a uv-managed venv, against any reachable
# PostgreSQL cluster — point the `EXAMPLE_PG_*` env vars at one. (In the
# pre-extraction monorepo, `make start` at the repo root provides a cluster
# on localhost:5432.)
#
# Connection defaults are baked in via env-var fallbacks in
# `example/settings.py` (host 127.0.0.1, port 5432, db
# `mcp_sql_example_local`, role `mcp_sql_example`, password
# `mcp_sql_example`). Override any of them via `EXAMPLE_PG_HOST`,
# `EXAMPLE_PG_PORT`, `EXAMPLE_PG_DB`, `EXAMPLE_PG_USER`,
# `EXAMPLE_PG_PASSWORD`.
#
# See `./README.md` for the full runbook.

VENV := .venv
PY := $(VENV)/bin/python

.PHONY: help install createdb migrate roles grants bootstrap_demo runserver shell clean

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Create venv + install example deps (incl. editable mcp_sql via uv.sources).
	@command -v uv >/dev/null || { echo "uv not found on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	uv sync

createdb: ## Create the example PG database (run once; fails loudly if the DB already exists or PG is unreachable).
	PGPASSWORD=$${EXAMPLE_PG_PASSWORD:-mcp_sql_example} createdb -h $${EXAMPLE_PG_HOST:-127.0.0.1} -p $${EXAMPLE_PG_PORT:-5432} -U $${EXAMPLE_PG_USER:-mcp_sql_example} $${EXAMPLE_PG_DB:-mcp_sql_example_local}

migrate: ## Apply all migrations to the example DB (also runs the post_migrate profile provisioning).
	$(PY) manage.py migrate

roles: ## Create the per-profile Postgres roles from MCP_SQL[PROFILES] (DBA step; see ROLES_PG_USER below).
	# Pipes the generated bootstrap SQL into psql. The CONNECTING role
	# (ROLES_PG_USER, defaulting to EXAMPLE_PG_USER) needs to be able to
	# CREATE/ALTER the profile roles and grant their membership: on a fresh
	# cluster a CREATEROLE login suffices (PG16+ gives the creator ADMIN on
	# roles it creates); when any profile role ALREADY exists cluster-wide
	# (e.g. a DBA bootstrapped `mcp_readonly_role` earlier), run as a
	# superuser instead: `ROLES_PG_USER=<superuser> ROLES_PG_PASSWORD=<...>
	# make roles`. `-v app_role=` stays EXAMPLE_PG_USER regardless — it is
	# the role the readonly roles are granted TO (the role the app connects
	# as), matching role_setup.sql's contract; that is why the connecting
	# role is a separate variable.
	$(PY) manage.py mcp_sql_role_setup --emit-sql | PGPASSWORD=$${ROLES_PG_PASSWORD:-$${EXAMPLE_PG_PASSWORD:-mcp_sql_example}} psql -v ON_ERROR_STOP=1 -h $${EXAMPLE_PG_HOST:-127.0.0.1} -p $${EXAMPLE_PG_PORT:-5432} -U $${ROLES_PG_USER:-$${EXAMPLE_PG_USER:-mcp_sql_example}} -d $${EXAMPLE_PG_DB:-mcp_sql_example_local} -v app_role=$${EXAMPLE_PG_USER:-mcp_sql_example}

grants: ## Reconcile each profile role's SELECT grants against its ALLOWED_MODELS.
	$(PY) manage.py mcp_sql_grants --apply

bootstrap_demo: ## Create demo users: demo/demo (default profile) and second/second (second_profile profile).
	@$(PY) manage.py shell -c "\
from django.contrib.auth import get_user_model; \
from django.contrib.auth.models import Group; \
U = get_user_model(); \
d, _ = U.objects.get_or_create(username='demo', defaults={'is_staff': True, 'is_active': True, 'email': 'demo@example.com'}); \
d.set_password('demo'); d.is_staff = True; d.is_active = True; d.save(); \
d.groups.add(Group.objects.get(name='mcp_sql_users')); \
s, _ = U.objects.get_or_create(username='second', defaults={'is_staff': True, 'is_active': True, 'email': 'second@example.com'}); \
s.set_password('second'); s.is_staff = True; s.is_active = True; s.save(); \
s.groups.add(Group.objects.get(name='mcp_sql_second_profiles')); \
print('Demo users ready: demo/demo (default profile), second/second (second_profile profile).')"

runserver: ## Run the dev server on http://127.0.0.1:8001/ (port 8001 to avoid the project's 8000).
	$(PY) manage.py runserver 127.0.0.1:8001

shell: ## Django shell.
	$(PY) manage.py shell

clean: ## Remove the venv.
	rm -rf $(VENV)
