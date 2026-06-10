# MCP SQL OAuth & Transport Runbook

OAuth issuance and MCP transport for the `/mcp/sql/` read-only SQL
surface. Companion to [`role-setup.md`](role-setup.md),
which covers the DB-role layer. This runbook covers what an on-call
operator needs to know when onboarding a user, revoking access, or
responding to an incident.

## Architecture in five lines

- Single OAuth Application `mcp-sql`; single scope `mcp:sql`; PKCE
  required; `authorization_code` grant only.
- Token lifetime: 6 h access, no refresh tokens, 60 s authorization code.
- Custom DRF auth class `MCPOAuth2Authentication` mounted **only** on
  `/mcp/sql/` — never in `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`.
- Issuance gate at `/o/authorize/`: `is_active AND is_staff AND
  is_mfa_enabled AND has_perm("mcp_sql.use_mcp_session")`.
- Per-request re-validation: the same gate runs on every `/mcp/sql/`
  request; revoked permission or removed MFA invalidates outstanding
  tokens immediately.

## Discovery surface

The MCP authorization handshake starts with the client probing the
resource endpoint and getting a 401. That 401 must carry enough
information for the client to find the authorization server. The
discovery surface comprises two anonymous-GET endpoints plus the
`WWW-Authenticate` challenge that points clients at them.

| URL | RFC | What it says |
|---|---|---|
| `/.well-known/oauth-protected-resource/mcp/sql` | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected Resource Metadata: `resource` (the MCP endpoint URL), `resource_name` (the env's human-readable identity, from `MCP_SQL["RESOURCE_NAME"]`), `authorization_servers`, `scopes_supported=["mcp:sql"]`, `bearer_methods_supported=["header"]`. |
| `/.well-known/oauth-authorization-server/o` | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata: `issuer` (`https://<host>/o`, scoped to DOT's mount per RFC 8414 §3.1), `authorization_endpoint=/o/authorize/`, `token_endpoint=/o/token/`, `revocation_endpoint=/o/revoke_token/`, `scopes_supported`, `response_types_supported=["code"]`, `grant_types_supported=["authorization_code"]`, `code_challenge_methods_supported=["S256"]` (SHA-256 PKCE; enforced by `MCPOAuth2Validator`), `token_endpoint_auth_methods_supported=["none"]` (public client). |

The `/mcp/sql/` 401 response advertises the RFC 9728 URL:

```
WWW-Authenticate: Bearer realm="api", resource_metadata="https://<host>/.well-known/oauth-protected-resource/mcp/sql"
```

A compliant MCP client follows this chain end to end without any
out-of-band configuration:

```
1. POST <host>/mcp/sql/
   → 401, WWW-Authenticate: Bearer realm="api", resource_metadata="<PRM>"
2. GET  <PRM>      (i.e. <host>/.well-known/oauth-protected-resource/mcp/sql)
   → 200, JSON document, authorization_servers=["<issuer>"]
3. GET  <issuer>/.well-known/oauth-authorization-server  (path-suffixed per
   RFC 8414 §3.1: actually <host>/.well-known/oauth-authorization-server/o)
   → 200, AS metadata with authorization_endpoint=/o/authorize/, etc.
4. Browser-launch /o/authorize/ with PKCE; complete auth; exchange code at
   /o/token/; retry the MCP request with the bearer.
```

Sanity-check the chain against any environment with:

```sh
curl -s https://<host>/.well-known/oauth-protected-resource/mcp/sql | jq
curl -s https://<host>/.well-known/oauth-authorization-server/o | jq
curl -i https://<host>/mcp/sql/ | grep -i www-authenticate
```

Pinned by `tests/test_discovery.py`.

Both discovery endpoints return `Access-Control-Allow-Origin: *` so a
future browser-based MCP client can `fetch()` them without CORS preflight
trouble. The wildcard is appropriate because the payloads carry no
per-origin secret — they describe public endpoints by spec. The
companion `Access-Control-Allow-Methods: GET, HEAD` matches the actual
`@require_safe` posture; OPTIONS is deliberately absent so the
advertisement does not lie about a method the view rejects.

## Dynamic Client Registration (RFC 7591)

Claude Code's MCP SDK requires the AS to advertise a `registration_endpoint`
and refuses to authenticate against an AS that doesn't. The AS metadata
exposes `/o/register` at this slot; the view at
`views/registration.py` accepts anonymous JSON POST,
validates that every `redirect_uris` entry is an RFC 8252 §7.3 loopback URI
(`127.0.0.1` or `[::1]`, http only), and creates a public-client
Application named `mcp-sql-<urlsafe-token>`.

**What Claude Code does on first `claude mcp add` + tool use**:

```
1. claude probes /mcp/sql/ → 401 + WWW-Authenticate.resource_metadata=<URL>
2. claude GETs the RFC 9728 + RFC 8414 metadata
3. claude POSTs to /o/register with its loopback redirect_uri
   ← 201 with a fresh client_id
4. claude redirects the browser to /o/authorize/?client_id=<fresh>&...
5. user completes login + MFA + (skipped consent)
6. /o/authorize/ → 302 to claude's loopback callback with ?code=...
7. claude POSTs code + code_verifier to /o/token/ with the fresh client_id
   ← 200 with bearer
8. claude retries the MCP request with the bearer; tools work.
```

Each `claude mcp add` creates one Application row. The rows live forever
today (Phase 4 has periodic cleanup planned). Inspect:

```sh
python manage.py shell -c "
from oauth2_provider.models import Application
for a in Application.objects.filter(name__startswith='mcp-sql').order_by('-created'):
    print(a.created, a.name, a.client_id, '->', a.redirect_uris)
"
```

Manual registration probe (no auth, no client tooling):

```sh
curl -s -X POST https://<host>/o/register \
    -H 'Content-Type: application/json' \
    -d '{"redirect_uris":["http://127.0.0.1:8765/cb"],"client_name":"manual probe"}' \
    | jq
```

**Security**: the structural mitigations are the loopback-only
`redirect_uris` restriction (a rogue registered client can only redirect to
its own machine — useless for cross-machine token theft) and the
`/o/authorize/` issuance gate (real user with is_staff + MFA + perm
required to consent). On top of those, a **silent per-IP block** (shared
with the `/mcp/sql/` bad-token throttle; same
`MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]`)
bounds registration spam: once an IP crosses the threshold within the
window it gets a normal-looking 201 that persists **no** `Application` row
— byte-shape-identical to a real success (body + status), so an attacker
can't pace just under the threshold to keep creating rows. (Response timing
differs slightly — the blocked path skips the DB INSERT — but that side
channel doesn't change the outcome: once blocked, no rows are created.) The
synthesized `client_id`
is inert (no row), so it fails at `/o/authorize/` like any unknown client.
A blocked operator's only signal is one `WARNING` at the threshold
crossing; clear early with `cache.delete('mcp_sql:register:ip:<ip>')`.
Periodic cleanup of stale dynamically-registered Applications is Phase 4.
See `views/registration.py`'s module docstring for the
full threat-model analysis.

> **Proxy hardening is load-bearing for the per-IP blocks.** Both the
> registration block and the `/mcp/sql/` bad-token block key on the
> `REMOTE_ADDR`. The package does nothing to derive the real client IP —
> behind a reverse proxy you need a real-IP middleware (e.g. ipware-based)
> rewriting `REMOTE_ADDR` from `X-Forwarded-For`, and that value is only
> the *genuine* client IP if the edge proxy discards client-supplied
> `X-Forwarded-*` and the app port is unreachable except through the proxy
> (for Traefik: `forwardedHeaders.insecure: false`, no `trustedIPs`, app
> port never published; other proxies have equivalents).
> **Do not** publish the app port directly, loosen forwarded-header
> handling, or front
> the app with a proxy that appends rather than replaces forwarded
> headers: any of those makes the block key attacker-controllable (evade
> by rotating fake IPs; lock a victim out by spoofing theirs). Keying on
> the TCP peer instead is not a fix — behind a proxy that is the proxy's
> IP for every request, which would collapse the whole cohort onto one
> counter.

## Onboarding a user to the MCP cohort

1. **Pre-flight**: the user must be `is_staff=True` and have MFA
   configured (allauth TOTP). If not, sort that first via the user admin.
2. **Add to `mcp_sql_users`**: in Django admin, open the user, attach the
   `mcp_sql_users` group. The group carries `mcp_sql.use_mcp_session`.
   (One-off permission attach via `user.user_permissions.add(...)`
   also works but is not the recommended path.)
3. **Register Claude Code as MCP client**: name the server after the
   environment so a developer connected to two envs at once does not
   conflate them. The recommended convention is `slugify(resource_name)`
   — the per-env display name the server advertises as `resource_name` in
   the RFC 9728 discovery document (see [Discovery surface](#discovery-surface)),
   which comes from `MCP_SQL["RESOURCE_NAME"]`.

   ```sh
   # Local — RESOURCE_NAME="Local My App"
   claude mcp add --transport http local-my-app http://app.localhost/mcp/sql/

   # Stage — RESOURCE_NAME="Stage My App"
   claude mcp add --transport http stage-my-app https://<stage-host>/mcp/sql/

   # Prod — RESOURCE_NAME="My App"
   claude mcp add --transport http my-app https://<prod-host>/mcp/sql/
   ```

   `--transport http` is required — without it Claude Code defaults to
   stdio and treats the URL as a binary path.

4. **First chat**: the user opens `claude`. Claude Code probes the MCP
   endpoint, receives the 401 with the `resource_metadata` parameter in
   `WWW-Authenticate`, fetches the RFC 9728 document, follows the linked
   AS metadata, POSTs to `/o/register` to mint its own RFC 7591 client_id,
   then launches the default browser to `/o/authorize/`. After login +
   MFA, the page renders a one-click consent screen (`"<client_id>
   wants access to the mcp:sql scope"` + Authorize / Cancel buttons).
   The user clicks **Authorize** and the page redirects to Claude
   Code's loopback URI with the auth code. Tool calls work from this
   point.

   **The consent click recurs every 6 h** for the same user. Token TTL
   is 6 h and refresh tokens are disabled (see "Token lifetime / freshness
   FAQ"), so Claude Code re-OAuths whenever the token expires; DOT's
   default consent template has no "remember my choice" mechanism, so
   the user sees the page each time. This is deliberate: see
   "DCR-minted clients require consent" below.

### Run the connecting client safely (untrusted data)

`run_query` returns production database content — email subjects, contact
names, and other free-text fields authored by external parties — straight into
the agent's context. That content can carry prompt-injection payloads. The
server defends the boundary two ways: every response wraps the untrusted
fields in a random-per-response `<untrusted-data-…>` fence with a
`data_handling` note, and the MCP `initialize` response carries standing
`instructions` telling the agent to treat fenced content strictly as data.
Both are advisory — **a server cannot force a client's UI or its permission
decisions.**

The residual risk is not the SQL surface (it is read-only and hardened); it
is injected content trying to steer the agent's **other** tools — the shell,
file edits, web access — which this server does not control. Those
mitigations are therefore client-side, and operators onboarding a user
should pass them on:

- **Keep a human in the loop.** Run the client in its default
  ask-before-acting mode. Do **not** enable blanket auto-accept or
  `--dangerously-skip-permissions` while this server is connected, so an
  injected instruction cannot silently drive a destructive action.
- **Bound the blast radius.** Prefer running the agent against an isolated
  working copy (a throwaway git worktree or a container) rather than your
  primary checkout, so even an approved-by-mistake action is contained.

The tools carry honest `readOnlyHint=True` / `openWorldHint=False`
annotations, so a client may auto-approve `list_tables` / `describe_table` /
`run_query` themselves — that is fine, they only read whitelisted tables.
The annotations say nothing about the agent's other tools, which is exactly
why the two mitigations above matter.

### DCR-minted clients require consent

Every Application created via `/o/register` (i.e. every Claude Code
install) has `skip_authorization=False`. This forces the OAuth consent
screen on every `/o/authorize/` call for these clients. The curated
`mcp-sql` Application from migration 0005 keeps `skip_authorization=True`
because operators provisioned its redirect URI in the migration — there
is no rogue-client path to that row.

The asymmetry exists because of the attack chain the consent screen
breaks:

1. Attacker discovers `/o/register` from the public `/.well-known/...`
   discovery doc (RFC 8414 requires the field — anonymous-readable by
   design).
2. Attacker POSTs `{"redirect_uris": ["http://127.0.0.1:31337/cb"]}`
   anonymously (RFC 7591 §3 permits anonymous registration). Server
   creates `Application(name="mcp-sql-<token>",
   skip_authorization=False, ...)` and returns the `client_id`.
3. Attacker phishes a logged-in MCP-cohort victim with a fully-formed
   `https://<host>/o/authorize/?response_type=code&client_id=mcp-sql-<attacker's>&redirect_uri=http%3A%2F%2F127.0.0.1%3A31337%2Fcb&code_challenge=...&scope=mcp:sql`
   link.
4. Victim's browser follows the link. Victim is logged in → DOT's
   `LoginRequiredMixin` passes. `MCPAuthorizationView._enforce_gate`
   passes (victim is a real MCP-cohort user). Validator passes.
5. **With `skip_authorization=True`**: DOT 302s silently to
   `http://127.0.0.1:31337/cb?code=<C>`. Any process listening on the
   victim's `127.0.0.1:31337` (malicious browser extension, npm/pip dep
   with a local server, Electron app, etc.) captures the code. Attacker
   then exchanges the code at `/o/token/` with their own PKCE verifier
   and obtains a 6 h `mcp:sql` token bound to the victim.
6. **With `skip_authorization=False`**: DOT renders the consent page.
   Authorize is a CSRF-protected POST — a phished GET cannot complete
   the dance. Victim has to click Authorize themselves, which gives
   them a chance to notice they did not initiate the flow.

The defense is not complete (a victim who clicks Authorize without
reading is still phishable) but it converts the silent attack into one
that requires the victim's active participation. Adding the explicit
"Application bound to creating user" defense (the reviewer's Option 3)
is deferred to a future follow-up — closes the gap fully at the cost
of a schema change on `oauth2_provider_application`.

## Revoking access

Three paths by urgency:

| Urgency | Action | Effect |
|---|---|---|
| User-driven | The user logs out of the web app | `user_logged_out` signal deletes the user's `mcp-sql` Application tokens (`AccessToken.objects.filter(user=user, application__name="mcp-sql").delete()`) |
| Operator, keep cohort | `python manage.py shell -c "from oauth2_provider.models import AccessToken; AccessToken.objects.filter(user__email='alice@example.com').delete()"` | Outstanding tokens dropped in < 1 s; user can re-OAuth |
| Operator, kick out | Remove from `mcp_sql_users` group (admin) | Outstanding tokens still exist in DB but `MCPOAuth2Authentication` re-checks the perm on every request and rejects. Combine with the token-delete shell snippet for a clean state. |

The 6 h hard cap on `access_token` lifetime is the worst-case fallback:
even with no other action, a leaked or no-longer-needed token expires
within 6 h.

## Incident playbooks

### "The agent is hammering the database"

1. **Immediate**: revoke the user's tokens via the shell snippet
   (operator-keep-cohort row above). Effect is immediate.
2. **Diagnose** with the audit table:

   ```python
   from mcp_sql.models import MCPQueryLog
   for log in (
       MCPQueryLog.objects
       .filter(user__email="alice@example.com")
       .order_by("-started_at")[:20]
   ):
       print(
           log.started_at,
           log.decision,
           log.rejection_reason or "ok",
           f"{log.duration_ms} ms",
           f"{log.row_count} rows",
           repr(log.raw_sql[:80]),
       )
   ```

3. **Long-term**: if the behaviour was abuse rather than honest noise,
   remove the user from `mcp_sql_users` until the investigation completes.

### "I lost my laptop / TOTP device"

- Standard allauth MFA recovery (out of scope of this runbook) is the
  primary path.
- Outstanding MCP tokens remain valid until expiry (6 h hard cap).
  Force-delete via the shell snippet if the device is suspected to be
  compromised. The `is_mfa_enabled` re-check inside
  `MCPOAuth2Authentication` will not catch this scenario until the user
  explicitly removes the now-lost MFA device through allauth.
- **Important**: setting up MFA on a new device does **not** revoke the
  old tokens — `is_mfa_enabled(user)` returns True as long as ANY
  registered Authenticator exists. The old tokens keep working until the
  6 h cap expires them, even if the original device is gone. Force-delete
  is therefore the only mechanism that invalidates outstanding tokens
  immediately for a suspected-compromised user. Re-MFA alone is not enough.

### "Group membership changed and I want to confirm old tokens are dead"

Group changes do not delete tokens. But the per-request
`MCPOAuth2Authentication` rechecks `has_perm("mcp_sql.use_mcp_session")`
on every call, so a user who lost group membership is locked out of
`/mcp/sql/` at the next request without waiting for token expiry. If you
also want the audit / `oauth2_provider_accesstoken` table to reflect
reality, run the token-delete shell snippet.

### "I got an MCP-group-grant Sentry alert"

The cohort-change receiver fires when a user is added to the `mcp_sql_users`
group — the canonical way MCP access is granted — and names the user(s).
Confirm the grant was intended (an administrator onboarding the user). If it
was NOT expected, treat it as privilege escalation: remove them from the
group (admin, or `user.groups.remove(group)` — the per-request perm recheck
then locks them out at the next call) and revoke any tokens they already
minted (see [Revoking access](#revoking-access)).

### "I got a query-volume tripwire Sentry alert"

The volume tripwire fires when a user crosses an hourly/daily allowed- or
rejected-query threshold (`MCP_SQL["VOLUME_ALERT_THRESHOLDS"]`). It is an
ALERT only — the query was not blocked. Open the [usage summary](#auditing-usage)
to see the user's recent volume, then either revoke their tokens if the
activity looks abusive, or raise the threshold if it is legitimate heavy use
(MCP agents are greedy; the defaults are deliberately generous).

## Auditing usage

The fastest read is the **admin usage summary** at *MCP query logs → Usage
summary* (`/admin/mcp_sql/mcpquerylog/usage-summary/`): per-user allowed /
rejected query counts and auth-rejection counts per rolling window
(1h / 24h / 7d) — the instrument for tuning
`MCP_SQL["VOLUME_ALERT_THRESHOLDS"]`. Both audit tables also have read-only
admin browsers (filter by decision / tool / reason, `date_hierarchy` on
`started_at`).

For ad-hoc work, all `/mcp/sql/` activity attributes to a `MCPQueryLog` row
with `user`, `tool`, `token_id`, `client_ip`, `decision`,
`rejection_reason`, `duration_ms`, `row_count`, and `truncated`.

Per-user audit (paste into Django shell):

```python
from mcp_sql.models import MCPQueryLog
qs = (
    MCPQueryLog.objects
    .filter(user__email="alice@example.com")
    .order_by("-started_at")[:50]
)
for log in qs:
    print(
        log.started_at,
        log.decision,
        log.rejection_reason or "ok",
        log.duration_ms,
        log.row_count,
        repr(log.raw_sql[:80]),
    )
```

Per-day volume:

```python
from datetime import date
from django.db.models import Count
from mcp_sql.models import MCPQueryLog
(
    MCPQueryLog.objects
    .filter(started_at__date=date.today())
    .values("user__email")
    .annotate(n=Count("id"))
    .order_by("-n")
)
```

The per-user volume tripwires (`MCP_SQL["VOLUME_ALERT_THRESHOLDS"]`)
already emit a Sentry `ERROR` on each hourly/daily threshold crossing;
these manual queries are for ad-hoc investigation of a user's recent
volume.

## Token lifetime / freshness FAQ

- **Why 6 h?** Bounded blast radius on a leaked token; comfortably spans
  a typical workday so users don't re-OAuth mid-session.
- **Why no refresh tokens?** Adds lifecycle complexity not worth it for
  internal use. Users re-OAuth silently (the session-trust gate at
  `/o/authorize/` runs without re-prompting MFA so long as the Django
  session is still valid) every 6 h, mediated by Claude Code. Technical
  note: DOT 3.2.0 still emits a `refresh_token` field in the `/o/token/`
  response, but `REFRESH_TOKEN_EXPIRE_SECONDS=0` sets its lifetime to
  zero — it cannot actually be used to refresh. Effective behavior is
  no-refresh; the field is cosmetic.
- **Why no idle timeout?** Phase 3 defers this. The 6 h hard cap +
  logout revocation + 16 h `SESSION_COOKIE_AGE` + per-request
  session-existence check (see next item) + Phase 4 daily-volume Sentry
  alerts already bound exposure. Revisit in Phase 4 if abuse patterns
  appear.
- **Why does MCP stop working when my web session ends?** Every MCP
  request re-checks that the user holds at least one live Django
  session (`MCPOAuth2Authentication.authenticate`). This is the
  *runtime* half of the design's "Option D session-trust" model:
  issuance trusts a fresh login + MFA, and runtime trusts that the
  same operator still has at least one live web session somewhere. If
  the session expires naturally (16 h), an admin deletes it,
  `clearsessions` cron sweeps an expired row, the operator clears
  their browser cookies, or a server restart wipes session state, the
  token immediately stops being honored even though it's not yet at
  its 6 h hard cap. Recovery: log back in at the Django UI; the next
  MCP call goes through. No re-OAuth needed if the AccessToken row is
  still alive — the gate only checks "does any session for this user
  exist", not "is this token tied to THE session that issued it".
- **Why "session-trust" and not "fresh 2FA every authorize"?** The 8 h
  Django session lifetime already requires login + MFA at the boundary,
  so an active session is itself proof of recent-enough MFA — a separate
  fresh-TOTP challenge at every issuance would be redundant.
  Promote the gate to require a `session["mfa_authenticated_at"]`
  freshness check if the threat model ever expands (e.g. whitelist
  grows to include PII tables, the user base grows beyond the
  internal team).

## Error-message verbosity

`MCPOAuth2Authentication.authenticate` raises distinct
`AuthenticationFailed` messages for each gate it fails:

- `"Token was not issued by the mcp-sql Application."`
- `"Token does not carry the mcp:sql scope."`
- `"User is not an active staff member."`
- `"User does not have a verified TOTP device."`
- `"User no longer holds the mcp_sql.use_mcp_session permission."`

These reach the MCP client (typically Claude Code) as the body of a 401
response, and from there the user sees them. The verbosity is **deliberate**:
the consumers are internal staff members onboarding to the surface, and
"your MFA device was removed, re-set it up" is faster to act on than a
generic "Token is no longer valid." If the threat model ever changes —
the surface gets opened to external partners, or token-holders need to be
treated as potential attackers — collapse the five branches into a single
generic message and rely on server logs for the granular reason.

## Token isolation contract

An OAuth token issued for `/mcp/sql/` **does not** authenticate against
any other DRF endpoint (`/api/...`, `/admin/...`, etc.).

**Structural reason**: DRF's global `DEFAULT_AUTHENTICATION_CLASSES` is
`SessionAuthentication + TokenAuthentication`. `TokenAuthentication`
reads `Authorization: Token <key>`, not `Authorization: Bearer <key>`;
`SessionAuthentication` ignores the `Authorization` header entirely. The
OAuth bearer therefore yields anonymous on any endpoint that hasn't
explicitly opted into `MCPOAuth2Authentication`. Only the `/mcp/sql/`
view does so.

**Verification**: pinned by
`tests/test_auth_class.py::TestOAuthTokenIsolationFromGlobalDRF`,
which exercises `/api/users/` and `/api/global-search/` with a valid
`mcp:sql` token (expected: 401/403) and a positive-control on the same
token against the MCP auth class (expected: `(user, token)` returned).

## Manual end-to-end smoke

The following sequence verifies the full Phase 3 path against a running
local deployment (substitute your own start command and hostname):

```sh
python manage.py createsuperuser
# Add the user to mcp_sql_users in /admin/auth/user/<id>/
# Enroll MFA via your consumer's flow (e.g. allauth's /accounts/2fa/)

claude mcp add --transport http local-my-app http://<local-host>/mcp/sql/
claude
> "How many entries in auth_permission table?"
# Expect: Claude Code invokes run_query; result returned; one MCPQueryLog
# row written with decision='allowed'.
```

If the flow stalls at the browser redirect, check the
`oauth2_provider_application` row matches the migration's expected
values (`mcp-sql`, public, PKCE, `skip_authorization=True` **for the
curated row only** — DCR-minted `mcp-sql-<token>` rows have
`skip_authorization=False`, see "DCR-minted clients require consent"
above), loopback redirect URIs:

```sql
SELECT name, client_id, client_type, authorization_grant_type,
       skip_authorization, redirect_uris
FROM oauth2_provider_application
WHERE name LIKE 'mcp-sql%';
```

Expected: exactly one row with `name='mcp-sql'` and
`skip_authorization=true`, plus zero or more `name='mcp-sql-<token>'`
rows with `skip_authorization=false` (one per `claude mcp add`
invocation across all developers).

If the curated row is missing, the `0005_create_mcp_sql_application`
migration did not run — re-apply with `python manage.py migrate mcp_sql`.
If a DCR-minted row has `skip_authorization=true` despite this guidance,
it predates the security fix; delete it and have the developer
re-register via `claude mcp add`.

## Post-incident notes

- Token-table cleanup is **not** automatic beyond expiry. Operators may
  prune expired tokens periodically; the DB load is negligible until the
  cohort grows substantially. Phase 4 may add a celery beat task.
- If the `mcp_sql_users` group is deleted, every user loses MCP access.
  Recreate via the data migration's reverse if needed:

  ```python
  from django.contrib.auth.models import Group, Permission
  perm = Permission.objects.get(
      codename="use_mcp_session",
      content_type__app_label="mcp_sql",
      content_type__model="mcpquerylog",
  )
  group, _ = Group.objects.get_or_create(name="mcp_sql_users")
  group.permissions.add(perm)
  ```

- Update this runbook if a new failure mode appears.
