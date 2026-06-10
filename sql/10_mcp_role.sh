#!/bin/sh
# TIC-554: kartoza/postgis init wrapper for role_setup.sql.
#
# Mounted at /docker-entrypoint-initdb.d/10_mcp_role.sh on local/test compose.
# `make mcp_sql_role_setup_local` also invokes this file inside the running
# db container to re-apply against an existing cluster.
#
# The wrapper substitutes the environment's POSTGRES_USER as the psql
# variable `app_role`, which role_setup.sql references in the membership
# GRANT. This keeps the SQL portable across environments whose app role
# names differ (the role is whatever each environment's POSTGRES_USER is)
# without forcing the DBA to edit the SQL by hand.
#
# role_setup.sql is mounted at /mcp_sql/role_setup.sql (outside the init
# dir) so the entrypoint does not also auto-run it without the -v
# substitution. The path is hard-coded here so both the entrypoint auto-run
# and `make mcp_sql_role_setup_local` exercise the same code path.
#
# **Important: kartoza/postgis SOURCES `.sh` init scripts (`. "$f"`) rather
# than executing them as subprocesses.** That means any shell state we touch
# (`set -e`, `exec`, `exit`, `cd`) leaks into the parent entrypoint and
# breaks the post-init `kill_postgres → exec su - postgres` transition.
# Keep this file additive: no `set -e`, no `exec`, no `exit`. psql's
# `ON_ERROR_STOP=1` is the failure signal; the entrypoint's enclosing
# `... || true` swallows a non-zero status (intentional — a partial init
# is still better than a stuck container).
#
# Connection details: explicit TCP (-h localhost) + PGPASSWORD. Local-socket
# auth in this cluster is `peer`, which would require running as the
# postgres OS user; kartoza runs init in a `root`-owned shell. TCP works
# uniformly in both fresh-init and re-apply contexts.

PGPASSWORD="$POSTGRES_PASSWORD" psql -v ON_ERROR_STOP=1 \
    -h localhost \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -v app_role="$POSTGRES_USER" \
    -f /mcp_sql/role_setup.sql
