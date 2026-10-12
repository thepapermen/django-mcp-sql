-- TIC-554: mcp_readonly_role and its session-level guards.
--
-- This file is the single source of truth for creating the dedicated Postgres
-- role used by the MCP read-only SQL surface. On stage and prod a DBA applies
-- it manually via psql; on local/test the kartoza/postgis init runs a
-- companion shell wrapper (`10_mcp_role.sh`) that calls psql with the
-- environment's `POSTGRES_USER` substituted for the `app_role` psql variable.
--
-- The script is idempotent: re-running it must not fail.
--
-- The membership grant at the bottom takes the app role name from the psql
-- variable `app_role`, so the file is portable across environments whose
-- app role names differ (the connecting user is whatever each environment's
-- POSTGRES_USER is). Callers MUST pass `-v app_role=<role>` matching the
-- connected user's role name. The compose init wrapper, the
-- `make mcp_sql_role_setup_local` target, and the DBA examples in
-- `docs/role-setup.md` all do this. Membership lets the app role connect
-- via the `mcp_readonly` Django alias and SET ROLE into mcp_readonly_role.
-- The app role itself cannot issue this GRANT (it lacks admin option), so
-- the script must be
-- run by a superuser.
--
-- Implementation note: psql variables (`:'name'`, `:"name"`) are NOT
-- substituted inside `DO $$ ... $$` blocks (that's a documented psql
-- behaviour). The membership grant therefore moves the app role name onto
-- a server-side custom GUC via `SET LOCAL` inside an explicit
-- `BEGIN ... COMMIT` (which psql DOES substitute into at the call site),
-- then reads it inside the DO block via `current_setting('mcp_sql.app_role')`
-- and issues the GRANT via `EXECUTE format(... %I ...)` for proper
-- identifier quoting. `SET LOCAL` (not bare `SET`) is deliberate: the
-- runtime read path on stage/prod is fronted by transaction-mode pgbouncer,
-- and the library-wide invariant is that no session-scope SET ever appears
-- in mcp_sql code, even on bootstrap paths that don't run through the
-- pooler today. The DO block runs inside the same explicit transaction, so
-- `current_setting` sees the LOCAL value; `COMMIT` reverts it.

DO $$
BEGIN
    CREATE ROLE mcp_readonly_role NOLOGIN;
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
END
$$;

ALTER ROLE mcp_readonly_role SET default_transaction_read_only = on;
ALTER ROLE mcp_readonly_role SET statement_timeout = '5s';
ALTER ROLE mcp_readonly_role SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE mcp_readonly_role SET lock_timeout = '1s';

BEGIN;

SET LOCAL mcp_sql.app_role = :'app_role';

DO $$
DECLARE
    target_role text := current_setting('mcp_sql.app_role');
BEGIN
    EXECUTE format('GRANT mcp_readonly_role TO %I', target_role);
EXCEPTION
    WHEN undefined_object THEN
        -- The app role passed via `-v app_role=<role>` does not yet exist
        -- in this cluster. The standard kartoza/postgis init runs
        -- `POSTGRES_USER` creation BEFORE this file (10_*.sh) on a fresh
        -- cluster, so this branch is only reached on unusual setups. Surface
        -- a NOTICE so the DBA sees that membership was NOT granted —
        -- silently swallowing this error masks a misconfiguration that only
        -- manifests later as "permission denied to set role" when the
        -- executor tries SET ROLE.
        RAISE NOTICE 'mcp_readonly_role created, but app role "%" does not yet exist in this cluster. Once the app role is created, run: GRANT mcp_readonly_role TO <app_role>; otherwise the executor''s SET ROLE will fail.', target_role;
END
$$;

COMMIT;
