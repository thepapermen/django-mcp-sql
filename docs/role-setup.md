# MCP SQL Role Setup Runbook

The `mcp_readonly_role` is the actual access boundary the MCP read-only SQL
surface enforces: the layers above it (parser, auth, transport) narrow what
reaches the database, but the role's `SELECT` grants are what ultimately bound
which tables are readable. If the role is missing or its grants are wrong, that
boundary is gone. This runbook covers applying the role and reconciling its
`SELECT` grants against `MCP_SQL["ALLOWED_MODELS"]`.

## Quick Reference

| Operation | When | Command | Verify |
|---|---|---|---|
| Install role on fresh local | New dev cluster | Mount `sql/10_mcp_role.sh` in the Postgres image's `/docker-entrypoint-initdb.d/` (see below) | `\du mcp_readonly_role` shows `Cannot login` |
| Install role on running local | Existing cluster, no rebuild | `psql ... -v app_role=<role> -f sql/role_setup.sql` (idempotent) | Same as above |
| Install role on stage/prod | First deploy, or after `role_setup.sql` changes | DBA `psql ... -v app_role=<role> -f role_setup.sql` | Same as above |
| Reconcile grants (deploy step) | Every deploy, after `migrate` | `python manage.py mcp_sql_grants --apply` | `mcp_sql_grants` exits 0 |
| Reconcile grants in CI | Every PR | Wire `mcp_sql_grants --apply` against your CI's ephemeral test cluster | CI step exits 0 |
| Detect grants drift (advisory) | Every `migrate` | `python manage.py migrate` — the `post_migrate` signal in `mcp_sql.signals` LOGs a WARNING when grants drift from `MCP_SQL["ALLOWED_MODELS"]`. Does NOT apply. | WARNING line absent from migrate output |
| Audit grants drift | Pre-deploy verification on stage/prod | `python manage.py mcp_sql_grants` | exit 0 = in sync |
| End-to-end smoke (Phase 1) | After role + grants applied | `python manage.py mcp_sql_smoke` | "Write attempt rejected as expected" |
| Executor smoke (Phase 2) | After Phase 2 lands, with whitelisted table | `python manage.py mcp_sql_smoke --run-query "SELECT id FROM auth_permission LIMIT 5"` | `QueryResult` printed, audit row created |
| Add user to MCP cohort | Onboarding / role change | Admin: add user to `mcp_sql_users` group | `user.has_perm("mcp_sql.use_mcp_session")` returns True |
| Revoke a user's MCP tokens | Incident / off-boarding | `AccessToken.objects.filter(user=user).delete()` (or user logs out) | `AccessToken.objects.filter(user=user).count() == 0` |
| Register Claude Code as MCP client | Once per developer per env | `claude mcp add --transport http <slug-of-RESOURCE_NAME> https://<host>/mcp/sql/` (e.g. `local-my-app`, `stage-my-app`, `my-app`) | First `claude` chat invokes a tool from this surface |

OAuth-specific incident playbooks live in
[`oauth.md`](oauth.md). This runbook covers the DB-role
layer only.

---

## When to Run

- **First deploy** to stage or prod — the role does not exist yet.
- **Whenever `sql/role_setup.sql` changes** — new GUC,
  new alter, etc. The script is idempotent so re-applying is safe.

After any change to `MCP_SQL["ALLOWED_MODELS"]`, your deploy pipeline
should run `python manage.py mcp_sql_grants --apply` as an explicit step
(right after `migrate`). The `post_migrate` signal in `mcp_sql.signals` will
ALSO run on every `migrate`, but only to **detect** drift and log a
WARNING — never to mutate. Keeping detection in code and apply in the
deploy pipeline separates two genuinely orthogonal concerns: ORM
migration lifecycle and DBA-grant-deployment. The WARNING in `migrate`
output is the developer's local cue that "you forgot to apply" or "the
deploy script didn't run apply" — either way, your deploy's
explicit `mcp_sql_grants --apply` step is where reconciliation actually
happens.

The role install is a one-time DBA action per environment; grants
reconcile on every deploy via the explicit pipeline step.

---

## Install role on a fresh local cluster

For a Docker-based dev cluster, mount `sql/10_mcp_role.sh` at
`/docker-entrypoint-initdb.d/10_mcp_role.sh`, plus the SQL file itself at
`/mcp_sql/role_setup.sql` (outside the init dir, so the entrypoint does not
auto-run it without the `-v app_role` substitution). The standard Postgres
(and postgis-derived) image entrypoints run the `.sh` wrapper in lexical
order on first initialization of the data volume; the wrapper calls psql
with `-v app_role="$POSTGRES_USER"`. The role is then created automatically
before the app starts.

Verify with the [sanity-check trio](#sanity-checks) below.

---

## Install role on a running local cluster

If the cluster already exists (the data volume is initialized), the
`/docker-entrypoint-initdb.d/` mount is silently skipped by Postgres. Apply
the SQL idempotently to the running cluster:

```sh
psql -h <host> -U <superuser> -d <dbname> \
    -v app_role=<app_role_name> -f sql/role_setup.sql
```

Re-running is safe — both the `CREATE ROLE` and the membership `GRANT` are
wrapped in `DO $$ ... EXCEPTION WHEN duplicate_object|undefined_object THEN
NULL ... $$`. If you prefer a clean slate, wipe the data volume and recreate the
cluster — the init mount from the previous section rebuilds the role.

---

## Install role on stage / prod (DBA action)

The role install is **not** part of the deploy pipeline — `CREATE ROLE`
requires superuser, which the deploy user does not have.

**`-v app_role=<role>` is mandatory.** The membership GRANT references
the psql variable `:"app_role"`, which the DBA must set to the cluster's
app role name (match `POSTGRES_USER` for the target cluster).

```sh
# As a DBA with superuser on the target cluster — note -v app_role=<role>:
psql -h <host> -U postgres -d <dbname> \
    -v app_role=<app_role_name> \
    -f sql/role_setup.sql
```

Verify with the [sanity-check trio](#sanity-checks) below, substituting the
DBA's connection (`-h <host> -U postgres -d <dbname>`) for the
`docker exec` invocation.

Forgetting `-v app_role=<role>` leaves psql with an unset variable; the
membership GRANT will fail with `unrecognized configuration parameter
"app_role"` or `syntax error at or near ":"`. The role itself is still
created (the `CREATE ROLE` block runs before the GRANT), but the app role
is not a member and the executor's `SET ROLE` will fail at runtime. The
`EXCEPTION WHEN undefined_object` clause inside the GRANT block catches
the case where the named role does not yet exist on the cluster (unusual
bootstrap orders) and raises a NOTICE so the DBA sees the GRANT was
skipped — manually re-issue it after the app role is created.

For DBA copy-paste, the canonical SQL lives at
`sql/role_setup.sql` — read it directly:

```sh
cat sql/role_setup.sql
```

There is no management command for this. Role creation requires
superuser, which the deploy pipeline does not have; the SQL has to be
applied by a DBA via `psql` regardless, so a Django wrapper would add
indirection without value.

---

## Sanity checks

After installing the role on any environment, run these three checks. They
verify the three properties the executor depends on: the role exists with
the right login attribute, its session-level GUCs are set, and the app role
is a member of it (so `SET ROLE mcp_readonly_role` will succeed at runtime).

The checks below need a psql connection to your cluster. From a containerized
local setup that is typically
`docker exec -e PGPASSWORD=<password> <db_container> psql -h localhost -U <role> -d <db_name> ...`
— the `-h localhost` forces a TCP connection, because `docker exec` runs as root
inside the container and would otherwise hit `Peer authentication failed` on the
unix socket. On stage / prod, the DBA uses their own connection
(`psql -h <host> -U postgres -d <dbname> ...`). Substitute `<role>` /
`<password>` / `<db_container>` / `<db_name>` for your environment throughout
this section.

**1. Role exists and cannot log in:**

```sh
docker exec -e PGPASSWORD=<password> <db_container> psql -h localhost -U <role> -d <db_name> \
    -c "\du mcp_readonly_role"
```

Expected:

```
        List of roles
    Role name     | Attributes
-------------------+--------------
 mcp_readonly_role | Cannot login
```

**2. Role-level GUCs are set:**

```sh
docker exec -e PGPASSWORD=<password> <db_container> psql -h localhost -U <role> -d <db_name> \
    -c "SELECT rolname, rolconfig FROM pg_roles WHERE rolname = 'mcp_readonly_role';"
```

Expected (one row, four GUCs):

```
      rolname      |                              rolconfig
-------------------+----------------------------------------------------------------------
 mcp_readonly_role | {default_transaction_read_only=on,statement_timeout=5s,idle_in_transaction_session_timeout=10s,lock_timeout=1s}
```

**3. App role is a member of `mcp_readonly_role`:**

This is the critical check — without membership, the executor's `SET ROLE`
fails at runtime regardless of how the parser was configured. Note that
`\du <role>` collapses the "Member of" column for superusers, and
`pg_has_role(...)` returns `t` for superusers even without an explicit GRANT
(superusers bypass membership checks). Query `pg_auth_members` directly for
the truthful answer:

```sh
docker exec -e PGPASSWORD=<password> <db_container> psql -h localhost -U <role> -d <db_name> \
    -c "
SELECT member.rolname AS member, role.rolname AS member_of
FROM pg_auth_members am
JOIN pg_roles member ON member.oid = am.member
JOIN pg_roles role ON role.oid = am.roleid
WHERE role.rolname = 'mcp_readonly_role';
"
```

Expected: at least one row whose `member` matches the cluster's app role.

```
 member |     member_of
--------+-------------------
 <role> | mcp_readonly_role
```

If this query returns zero rows, `role_setup.sql` was applied without
`-v app_role=<role>` (or with the wrong value). Re-run with the correct
variable.

---

## Reconcile grants

### Deploy step (the only path that mutates)

```sh
python manage.py mcp_sql_grants --apply
```

Strict mode — raises `CommandError` if the role is missing or membership
is absent. **Wire this into the deploy pipeline right after `migrate`** so
every deploy reconciles `mcp_readonly_role`'s SELECT grants against
`MCP_SQL["ALLOWED_MODELS"]`. It is the only code path that issues
`GRANT SELECT` / `REVOKE SELECT` statements; the `post_migrate` signal
in `mcp_sql.signals` only DETECTS drift and logs a WARNING.

Sample output:

```
Grants already in sync; no action.
```

Or, after adding `auth.Permission` to the whitelist:

```
GRANT SELECT ON "auth_permission" TO mcp_readonly_role;
Applied: +1 grant(s), -0 revoke(s).
```

### Drift detection on every `migrate` (advisory)

Every `python manage.py migrate` invocation fires the `post_migrate`
receiver `audit_grants_drift_after_migrate` in `mcp_sql.signals`.
The receiver runs `compute_drift(strict=False)` — pure read against PG.
On drift it logs a single WARNING line that names the +N/-M to-grant /
to-revoke counts and points at the apply command. It does **not** issue
GRANT / REVOKE statements; reconciliation happens only via the deploy
step above.

The receiver is **lenient** about environment state: if the role is
missing (fresh env, DBA hasn't applied `role_setup.sql`) or membership
is absent, it logs a WARNING and returns rather than crashing `migrate`.

### Pre-deploy drift check

```sh
python manage.py mcp_sql_grants
```

Read-only — never issues `GRANT` / `REVOKE`. Exits non-zero if there's
any drift between declared whitelist and actual grants. Useful as a
verification step in the deploy pipeline AFTER `mcp_sql_grants --apply`
runs (to confirm the apply succeeded), and as a manual sanity check on
stage/prod. Not useful in CI test runs — the test settings have an
empty whitelist, so `grants_check` would trivially pass and prove
nothing.

### Sanity checks (post-apply)

Three complementary checks to confirm a fresh `mcp_sql_grants --apply` run
landed as expected. The first two go through the management commands; the
third bypasses Django and asks Postgres directly, which is the truthful
answer if you ever suspect a routing bug.

**1. Idempotency** — re-run apply, expect the no-op branch:

```sh
python manage.py mcp_sql_grants --apply
# Expected: "Grants already in sync; no action."
```

If the second run emits another GRANT / REVOKE, something is mutating the
DB between invocations (or the grants resolver has a bug); investigate
before continuing.

**2. Drift check** — exits 0 when in sync:

```sh
python manage.py mcp_sql_grants
echo "exit: $?"
# Expected: "Grants in sync." / exit: 0
```

**3. DB-side ground truth** — `information_schema.role_table_grants`
lists every grant on `mcp_readonly_role`, sourced directly from PG's
catalog. The set of tables here must match
`MCP_SQL["ALLOWED_MODELS"]`'s `_meta.db_table` resolutions exactly:

```sh
docker exec -e PGPASSWORD=<password> <db_container> psql -h localhost -U <role> -d <db_name> -c "
SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'mcp_readonly_role'
ORDER BY table_name;
"
```

Expected (with `auth.Permission` whitelisted):

```
   table_name    | privilege_type
-----------------+----------------
 auth_permission | SELECT
```

A divergence between this query and `MCP_SQL["ALLOWED_MODELS"]` means
`grants_check` would report drift; the apply step has not run (or has not
caught up) since the whitelist changed.

---

## End-to-end smoke

After the role is installed and grants are applied, verify the full
pipeline. There are two modes.

### Phase 1 (default mode)

Asserts the role/grants contract without the parser or executor:

```sh
# Env: the `mcp_readonly` DATABASES alias configured; ALLOWED_MODELS
# committed in your settings (e.g. auth.Permission for a first smoke).
python manage.py mcp_sql_smoke
```

Expected output:

```
Read path ok: SET LOCAL ROLE + 4 GUCs verified, SELECT FROM auth_permission ok
Audit table mcp_sql_mcpquerylog unreadable (pgcode=42501) — 0002_revoke_audit_grants is in effect.
Write attempt rejected as expected: ReadOnlySqlTransaction (pgcode=25006)
```

If the third line shows `pgcode=42501 (insufficient_privilege)`, that is
also healthy — it means the readonly guard did not catch the write but the
grants did. If it shows any other pgcode, the smoke command exits with a
security alarm. See the command's source for the diagnostic message.

If `MCP_READONLY_DATABASE_URL` is not set, the command writes a friendly
"skipping smoke check" message and exits 0.

### Phase 2 (--run-query)

Drives the full parser + executor + audit pipeline against a real query.
Useful for sanity-checking the LIMIT-N+1 truncation contract, the per-cell
byte cap, and the audit-row shape before opening MCP transport in Phase 3.

```sh
# On stage / prod, pass --as-user so the audit row attributes to a
# dedicated mailbox (e.g. `mcp-smoke@example.com`) rather than the first
# staff user found in the DB. The user must already exist.
python manage.py mcp_sql_smoke --as-user mcp-smoke@example.com \
    --run-query "SELECT id, codename FROM auth_permission LIMIT 5"
```

Expected output (abridged):

```
run_query attributed to: <staff user>
  columns: ['id', 'codename']
  row_count: 5
  truncated: False
  duration_ms: 3
  hint: ''
  rejection_reason: ''
  error: ''
  rows (5):
    [1, 'add_logentry']
    ...
```

Try the rejection paths too — each writes one `MCPQueryLog` row with
`decision='rejected'` and a short-code `rejection_reason`:

```sh
python manage.py mcp_sql_smoke --run-query "SELECT * FROM auth_permission"
# rejection_reason: 'select_star'

python manage.py mcp_sql_smoke --run-query "INSERT INTO auth_permission(name) VALUES ('x')"
# rejection_reason: 'non_select_root'

python manage.py mcp_sql_smoke --run-query "SELECT pg_read_file('/etc/passwd')"
# rejection_reason: 'disallowed_function'
```

---

## Phase 4 scope status

Phases 1–4 are operational. What ships today:

- **Phase 1**: SQL role (`mcp_readonly_role`), audit table
  (`mcp_sql_mcpquerylog`), grants reconcile/check tooling, lint, smoke
  (default mode), the `mcp_readonly` DB alias.
- **Phase 2**: sqlglot AST parser with the full reject vocabulary, the
  `run_query` executor with LIMIT-N+1 truncation and per-cell byte caps,
  audit writes on every code path, `mcp_sql_smoke --run-query`.
- **Phase 3**: OAuth issuance at `/o/authorize/` + `/o/token/`, the
  `MCPOAuth2Authentication` DRF auth class with per-request user-state
  re-validation, the `mcp_sql_users` group, the `mcp-sql` OAuth
  Application, MCP Streamable HTTP transport at `/mcp/sql/`, logout
  token revocation. Operational playbooks live in
  [`oauth.md`](oauth.md).
- **Phase 4**: per-user query-volume tripwires (hourly + daily, allowed +
  rejected) emitting one Sentry `ERROR` per window crossing; an `ERROR` when
  a user is added to the `mcp_sql_users` group; tool-level audit attribution
  (`MCPQueryLog.tool`); read-only admin browsers for both audit tables + a
  per-user usage-summary view. Curated PG views for sensitive tables
  (defined in the owning app) ship via `MCP_SQL["ALLOWED_MODELS"]`.

What is still pending:

- **Out of scope by design**: per-token / per-minute / concurrent rate
  limits (the DB role + volume tripwire are the enforcement/alerting
  layers); periodic cleanup of stale dynamically-registered Applications and
  audit-table retention.
- **Phase 5**: independent security hardening review.

---

## Post-incident

- If a `mcp_sql_grants` failure made it into prod: `mcp_sql_grants --apply`
  brings the cluster back into sync, no migration needed.
- If `role_setup.sql` is reverted in code: the role still exists on the
  cluster (PG does not auto-clean), but new clusters spun up from the
  current code will not have it. Re-add the script before the next env
  rebuild.
- Update this runbook if a new failure mode appears.
