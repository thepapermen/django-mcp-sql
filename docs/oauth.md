# MCP SQL OAuth & Transport Runbook

OAuth issuance and MCP transport for the `/mcp/sql/` read-only SQL
surface. Companion to [`role-setup.md`](role-setup.md),
which covers the DB-role layer. This runbook covers what an on-call
operator needs to know when onboarding a user, revoking access, or
responding to an incident.

## Architecture in five lines

- Single OAuth Application `mcp-sql`; single scope `mcp:sql`; PKCE
  required, `S256` only (whatever `PKCE_REQUIRED` says);
  `authorization_code` grant only, bearer token in the `Authorization`
  header only — enforced by the package's own OAuth server (see "The OAuth
  server" below), not by the consumer's `OAUTH2_SERVER_CLASS`.
- Token lifetime: 6 h access, 60 s authorization code; no refresh tokens
  unless `MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]` opts in to rotating
  refresh tokens hard-capped from the consent (see "Refresh tokens
  (opt-in)").
- Custom DRF auth class `MCPOAuth2Authentication` mounted **only** on
  `/mcp/sql/` — never in `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`.
- Issuance gate at `/o/authorize/`: `is_active AND
  is_mfa_enabled AND resolve_profile(user) binds exactly one profile`
  (the profile gate reads the user's EXPLICIT permission assignments —
  see [Profiles](architecture.md#profiles-access-tiers); 0 → denied,
  >1 → denied as ambiguous).
- Per-request re-validation: the same gate runs on every `/mcp/sql/`
  request; a revoked profile assignment or removed MFA invalidates
  outstanding tokens immediately.

## Discovery surface

The MCP authorization handshake starts with the client probing the
resource endpoint and getting a 401. That 401 must carry enough
information for the client to find the authorization server. The
discovery surface comprises two anonymous-GET endpoints plus the
`WWW-Authenticate` challenge that points clients at them.

| URL | RFC | What it says |
|---|---|---|
| `/.well-known/oauth-protected-resource/mcp/sql` (and `…/mcp/sql/`) | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected Resource Metadata: `resource` (the MCP endpoint URL), `resource_name` (the env's human-readable identity, from `MCP_SQL["RESOURCE_NAME"]`), `authorization_servers`, `scopes_supported=["mcp:sql"]`, `bearer_methods_supported=["header"]` (enforced: an `access_token` query or form parameter is not a credential, so a request carrying its token only there gets the ordinary 401). Served under **both** spellings of the resource path — see below. |
| `/.well-known/oauth-authorization-server/o` | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata: `issuer` (`https://<host>/o`, scoped to DOT's mount per RFC 8414 §3.1), `authorization_endpoint=/o/authorize/`, `token_endpoint=/o/token/`, `revocation_endpoint=/o/revoke_token/`, `scopes_supported`, `response_types_supported=["code"]`, `grant_types_supported=["authorization_code"]` (plus `refresh_token` when the opt-in refresh grant is on), `code_challenge_methods_supported=["S256"]` (SHA-256 PKCE), `token_endpoint_auth_methods_supported=["none"]` (public client). The response type, grant type and PKCE method lists are enforced, see "The OAuth server". |

The `/mcp/sql/` 401 response advertises the RFC 9728 URL (a request to the
slash-less `/mcp/sql` gets the slash-less `…/oauth-protected-resource/mcp/sql`
instead — see "Trailing slashes in the resource identifier" below):

```
WWW-Authenticate: Bearer realm="api", resource_metadata="https://<host>/.well-known/oauth-protected-resource/mcp/sql/"
```

A compliant MCP client follows this chain end to end without any
out-of-band configuration:

```
1. POST <host>/mcp/sql/
   → 401, WWW-Authenticate: Bearer realm="api", resource_metadata="<PRM>"
2. GET  <PRM>      (i.e. <host>/.well-known/oauth-protected-resource/mcp/sql/)
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

### Trailing slashes in the resource identifier

RFC 9728 §3.3 requires the `resource` value in the metadata document to be
**identical** to the resource identifier the client inserted the well-known
suffix into, and says a client MUST NOT use the document when they differ.
Clients disagree about trailing-slash normalisation, so the protected-resource
document is served at **both** `…/oauth-protected-resource/mcp/sql` and
`…/oauth-protected-resource/mcp/sql/`, and `resource` echoes whichever
spelling was requested. Both spellings also route to the transport, so the
audience a client derives either way reaches the same endpoint.

§3.3 has a second clause for a client that found the document through the
401's `resource_metadata` pointer rather than by building the URL itself: the
`resource` must then equal the URL the client sent its request to. So the
pointer follows the request — a 401 drawn by `/mcp/sql/` points at
`…/oauth-protected-resource/mcp/sql/`, one drawn by `/mcp/sql` at
`…/oauth-protected-resource/mcp/sql` — and either way the document it leads to
names the URL that was requested. Pinned by
`test_discovery.TestResourceIdentifierMatchesMetadataPath::test_challenge_pointer_leads_back_to_the_requested_url`.

Observed client behaviour (recorded while the 401 pointer was still always the
slash-less URL, so "requests the slash-less path" cannot be told apart from
"follows the pointer"):

| Client | Metadata path it requests | Enforces §3.3? |
|---|---|---|
| Cursor Desktop | the slash-less one | **yes** — aborts after consent, before the token exchange |
| Cursor CLI | the slash-less one | no — ignored the mismatch |
| Claude Code | the slash-less one | no |
| Claude.ai web connector | not directly observed | no — it connects fine to a deployment with the mismatch |

(Claude.ai separately strips the trailing slash off the *transport* POST, which
is why the slash-less `/mcp/sql` transport alias exists — a different
normalisation from the metadata path, and unaffected by any of this.)

Before this was fixed the document advertised `…/mcp/sql/` while being served
only at `…/mcp/sql`, so Cursor Desktop aborted the dance after the consent
screen and before the token exchange — the surface was unreachable from it,
and the path implied by the advertised identifier 404'd for everyone.
Pinned by `test_discovery.TestResourceIdentifierMatchesMetadataPath`.

### The `resource` parameter (RFC 8707)

MCP clients send the protected resource they want a token for as `resource`
on `/o/authorize/` and `/o/token/` (RFC 8707). DOT (3.4.1 is the floor) stores it on
the grant and the access token and audience-checks every bearer that carries
one against the URL of the request it arrives on. So the package accepts
exactly one resource: the `resource` the protected-resource document above
advertises — `https://<host>/mcp/sql/` or `https://<host>/mcp/sql` (`http`
only when `DEBUG` is on), on the host the request arrives at. Scheme and
host are compared case-insensitively and the scheme's default port may be
spelled out (`https://<HOST>:443/mcp/sql/` is the same resource, as RFC 3986
§6.2 has it and the MCP spec asks servers to accept); the path must be the
endpoint's exactly, with or without the trailing slash. Repeating it is
fine; omitting it is fine (the token is then not resource-bound, as before).

Equivalent spellings are equivalent at each step, not across steps. When
the grant carries a `resource`, `/o/token/` also requires each
`resource` sent there to be one of the grant's, compared as strings:
exchange the code with the same `resource` string the authorization request
carried, or with none (the token then carries the grant's). Another
spelling, even an equivalent one, passes the package's check and then gets
DOT's own `invalid_target`, whose `error_description` names the value sent;
the code is not consumed, so the client can retry. When the grant carries
none (the authorization request sent no `resource`), DOT compares nothing
and stores the token request's value on the token as sent — which the
package's check has already limited to the advertised identifier. The MCP
SDKs send the same value at both steps.

Anything else — the bare origin `https://<host>`, another path, host, port
or scheme, a port the package does not take (two ports or above 65535,
which URL parsers refuse too; more than five digits, the package's own cap,
although `urlsplit` and DOT take a zero-padded `:000443`), a query, a
fragment, userinfo, an empty value — is refused
with **`invalid_target`** (RFC 8707 §2), naming the accepted value in
`error_description` (the package's answer never names the value the client
sent):

| Where | Answer |
|---|---|
| `/o/authorize/` GET | 302 to the client's registered `redirect_uri` with `error=invalid_target` and its `state`; no consent page, no authorization code |
| consent POST | the same, for the form's `resource` field or one in the URL's query string (the two must agree); a tampered `redirect_uri` still gets the error page, never a redirect |
| `/o/token/` | 400 JSON `{"error": "invalid_target", ...}` with `Cache-Control: no-store`; the code is not consumed, so the client can retry |

A NUL or any other control character in `resource` never reaches this check:
the OAuth views' control-character screen answers `invalid_request` first
(the error page at `/o/authorize/`, GET and consent POST alike; a 400 JSON
at `/o/token/`).

Typical causes: a client configured with a URL other than the one discovery
returns (another host or alias, `http` for `https`, a different path), or a
hand-written OAuth client. Fix the client's server URL; the discovery
document shows the exact value expected.

The host in that value (and in every other URL discovery advertises) is the
request's host in canonical form: lowercased, without the scheme's default
port. A proxy that forwards `Host: <name>:443` (nginx
`proxy_set_header Host $host:$server_port`, or an `X-Forwarded-Host` that
carries the port, under `USE_X_FORWARDED_HOST`) or an uppercase name
therefore still yields `https://<name>/mcp/sql/` — the spelling clients
that parse the URL (the MCP TypeScript and Python SDKs) send back. A
non-default port stays (`https://<name>:8443/mcp/sql/`).

`/o/token/` reads its parameters from the form body only, whatever
`OAUTH2_PROVIDER["OAUTH2_BACKEND_CLASS"]` says: with DOT's deprecated
`JSONOAuthLibCore` a JSON body's `resource` would bypass the check, so a JSON
token request is refused.

Before this check, DOT issued a token for any `resource` and then
refused it at `/mcp/sql/` on every call with a bare 401 — no audit row, and
each call counted toward the bad-token IP throttle
(`MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]`), so a shared egress IP could end up
silently blocked. The same happened to the correct `https` value behind a
TLS-terminating proxy without `SECURE_PROXY_SSL_HEADER`, because DOT built
the request URL from `request.scheme` (`http`). `/mcp/sql/` now hands DOT's check the request URL
built the same way discovery builds `resource` (https whenever `DEBUG` is
off, the host canonical), so a token bound to the advertised value always
passes, with or without `SECURE_PROXY_SSL_HEADER`. A token bound to another
accepted spelling (uppercase, `:443`) passes DOT's default audience
validator, which compares parsed URLs; a custom
`RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR` that compares strings would
accept only the canonical one. DOT's check is not switched off: a token
bound to a URL that is not a prefix of the endpoint's (one issued before
this release) still gets a 401 until it expires. DOT's default validator
is a URL-prefix match, so a token bound to a prefix of the endpoint URL —
the origin, `https://<host>/mcp` — passes; the package no longer issues
one (those values are `invalid_target`). Pinned by
`tests/test_resource_audience.py`.

Both discovery endpoints return `Access-Control-Allow-Origin: *` so a
future browser-based MCP client can `fetch()` them without CORS preflight
trouble. The wildcard is appropriate because the payloads carry no
per-origin secret — they describe public endpoints by spec. The
companion `Access-Control-Allow-Methods: GET, HEAD` matches the actual
`@require_safe` posture; OPTIONS is deliberately absent so the
advertisement does not lie about a method the view rejects.

## The OAuth server

DOT runs its views on `OAUTH2_PROVIDER["OAUTH2_SERVER_CLASS"]`, by default
oauthlib's all-grants `Server` (password, client credentials, refresh token,
device code and implicit, besides the authorization code). The package's own
OAuth views — `/o/authorize/`, `/o/token/`, `/o/revoke_token/` — and
`MCPOAuth2Authentication` on `/mcp/sql/` instead run on
`oauth_server.MCPServer`, whatever `OAUTH2_SERVER_CLASS` is set to, and
always parse the request with DOT's form-body `OAuthLibCore`, whatever
`OAUTH2_BACKEND_CLASS` is set to:

- `/o/authorize/` serves the `code` response type only. A request is first
  screened, query string and consent POST alike: a control character in any
  parameter, a `code_challenge` outside RFC 7636 §4.2's shape (43–128
  characters of `[A-Za-z0-9-._~]`) or an over-long `nonce` gets the error
  page (400 `invalid_request`, no redirect, nothing stored). Then a
  `response_type` without `code` in it (`token`, `id_token`, ...) is
  redirected back as `unsupported_response_type`; `none` and values that
  contain `code` but are not exactly `code` (`code token`, `code id_token`,
  `codex`, ...) are redirected back as `unauthorized_client`. Either way no
  code and no token are issued. PKCE is mandatory and `S256` only: a
  missing challenge, `plain`, or an omitted `code_challenge_method` (which
  oauthlib would default to `plain`) is redirected back as
  `invalid_request`, on the authorize GET and on the consent POST.
- `/o/token/` accepts exactly one `grant_type=authorization_code` (and
  `refresh_token` when refresh tokens are enabled). With refresh off, a
  `grant_type=refresh_token` request gets a constant 400 `invalid_grant`
  with no token lookup — the error that makes an MCP client drop its
  refresh token and re-authorize. Anything else — `password`,
  `client_credentials`, the device-code grant, `openid`, an unknown,
  missing or repeated value — is a 400 `unsupported_grant_type`. Both run
  before DOT's own token handling or the server, so a password grant cannot
  test a password and DOT's device-code branch is unreachable. Only then is
  a control character in any other parameter (query or body) a 400
  `invalid_request` (one inside `grant_type` is already refused by the
  checks above). With refresh off the response never carries a
  `refresh_token`.
- `/mcp/sql/` takes the bearer token from the `Authorization` header only.
  An `access_token` query or form-body parameter is not a credential: a
  request carrying its token only there gets the ordinary 401 (never looked
  up, not counted by the bad-token throttle), and beside a header the
  parameter is ignored. **Recommended:**
  `OAUTH2_PROVIDER["COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT"] = True`
  (DOT 3.4.1+; scheduled to become DOT 4.0's default). It makes DOT refuse
  any request with an `access_token` query parameter itself, before the
  server runs — also a 401, and then even beside a valid header — and stops
  DOT logging an RFC 9700 deprecation warning for every such request, an
  unthrottled log line anyone can trigger.
- `/o/revoke_token/` is DOT's RFC 7009 token revocation.

`OAUTH2_PROVIDER["OAUTH2_VALIDATOR_CLASS"]` must be
`mcp_sql.oauth.MCPOAuth2Validator` or a subclass: the app refuses to boot
otherwise (`ImproperlyConfigured`), because the client pinning, the
`mcp:sql`-only scope, mandatory PKCE and the redirect rules live there.
Being the install's validator, it also serves any stock DOT view a consumer
mounts for another purpose (e.g. `include("oauth2_provider.urls")`) on the
stock server. There it keeps backstops, not the narrowing above: PKCE stays
required and a non-`S256` code cannot be exchanged (`invalid_grant`, though
such a view still accepts `plain` at authorize); password grants are refused
with `invalid_grant` (the password is never checked, so a correct and a
wrong one get the same answer); with refresh off no refresh token is stored
or returned and refresh grants are refused with `invalid_grant` (with
refresh on, the same hard cap applies as on the package's endpoints); and a
`client_id` carrying a control character is never looked up. Pinned by
`tests/test_oauth_server.py` and `tests/test_refresh_tokens.py`.

## Refresh tokens (opt-in)

Off by default: `ACCESS_TOKEN_EXPIRE_SECONDS` (6 h in the documented
settings) is then the re-consent interval. Set
`MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]` to a positive number of seconds
to turn them on:

- The authorization-code exchange returns a `refresh_token`; every refresh
  rotates it (the presented token is spent, a new one is issued in the same
  chain), whatever DOT's `ROTATE_REFRESH_TOKEN` says.
- **Hard cap from the consent.** The package records when each chain
  started (the authorization-code exchange; `MCPRefreshTokenFamily`) and
  refuses a refresh once `REFRESH_TOKEN_MAX_AGE_SECONDS` has passed since
  then, however often the token was rotated. This is not DOT's
  `REFRESH_TOKEN_EXPIRE_SECONDS`, a window that slides with every new access
  token (`0` there means no limit). The last access token minted before the
  cap still lives its `ACCESS_TOKEN_EXPIRE_SECONDS`, so access ends at most
  that long after the cap.
- A refresh token with no recorded consent — minted by 0.1.0b5 or earlier,
  or written by any path that bypassed `MCPOAuth2Validator.save_bearer_token`
  — is refused.
- `MCPRefreshTokenFamily` rows past the cap are pruned at each new exchange.
  Rows whose refresh tokens are gone (revoked, removed by `cleartokens`, or
  refresh switched off again) are inert and safe to delete, e.g. next to
  `cleartokens`:
  `MCPRefreshTokenFamily.objects.exclude(token_family__in=RefreshToken.objects.filter(token_family__isnull=False).values("token_family")).delete()`
  (keep the `isnull` filter: `NOT IN` over a list holding a NULL matches
  nothing, so without it the snippet deletes no rows).
- The discovery document and the DCR response (when the client asked for
  it) list `refresh_token`.
- Logout and a password change delete the user's MCP refresh tokens with
  the access tokens (see "Revoking access").

Consider DOT's `REFRESH_TOKEN_REUSE_PROTECTION = True` as well: replaying a
rotated-out refresh token then revokes the whole chain.

## Security posture: what each optional layer adds

The OAuth and SQL boundaries hold on their own; three layers are optional and
each adds one bound. CI runs the whole suite a second time with an allow-all
`MFA_CHECKER` and no `SESSION_MODEL` (`MCP_SQL_TEST_POSTURE=minimal`, `make
test-minimal`) to prove the first column.

| Control | Without the optional layers | MFA (`MFA_CHECKER`) adds | Session gate (`SESSION_MODEL`) adds | Refresh cap (`REFRESH_TOKEN_MAX_AGE_SECONDS`) |
|---|---|---|---|---|
| Who can get a token | Active user holding exactly one MCP profile, through `/o/authorize/` (consent screen for every client) | A verified second factor, at issuance and on every request | — | — |
| How long a token works | 6 h access token; no refresh | — | Only while the user has a live web session (`SESSION_COOKIE_AGE`) | Opt-in: refresh for at most the cap after consent (access then ends ≤ 6 h later) |
| What ends access early | Losing active / the profile (checked every request); logout; password change; deleting the tokens | Removing the MFA device | Expiry or deletion of every web session | — |
| What the token can do | Read-only `SELECT` on the profile's whitelisted tables, in a read-only, rolled-back transaction, through the checked SQL only | — | — | — |

## Dynamic Client Registration (RFC 7591)

Claude Code's MCP SDK requires the AS to advertise a `registration_endpoint`
and refuses to authenticate against an AS that doesn't. The AS metadata
exposes `/o/register` at this slot; the view at
`views/registration.py` accepts anonymous JSON POST,
registers the `redirect_uris` entries that are RFC 8252 §7.3 loopback URIs
(`127.0.0.1`, `[::1]` or `localhost`, http only, no userinfo, printable
ASCII) and echoes that subset back (RFC 7591 §3.2.1; nothing left is a 400,
and whitespace or an invisible character in any entry refuses the whole
request), and creates a public-client Application named
`mcp-sql-<urlsafe-token>` that shows the consent screen
(`skip_authorization=False`).

**What Claude Code does on first `claude mcp add` + tool use**:

```
1. claude probes /mcp/sql/ → 401 + WWW-Authenticate.resource_metadata=<URL>
2. claude GETs the RFC 9728 + RFC 8414 metadata
3. claude POSTs to /o/register with its loopback redirect_uri
   ← 201 with a fresh client_id
4. claude redirects the browser to /o/authorize/?client_id=<fresh>&...
5. user completes login + MFA + the consent click
6. /o/authorize/ → 302 to claude's loopback callback with ?code=...
7. claude POSTs code + code_verifier to /o/token/ with the fresh client_id
   ← 200 with bearer
8. claude retries the MCP request with the bearer; tools work.
```

Each `claude mcp add` creates one Application row. The rows live forever
today — periodic cleanup of stale DCR clients is a known unimplemented gap
(see [Roadmap / known gaps](#roadmap--known-gaps)). Inspect:

```sh
python manage.py shell -c "
from oauth2_provider.models import Application
for a in Application.objects.filter(name__startswith='mcp-sql').order_by('-created'):
    print(a.created, a.name, a.client_id, '->', a.redirect_uris)
"
```

Releases up to and including 0.1.0b5 could store a DCR row whose
`redirect_uris` holds an off-machine entry smuggled in through whitespace
(see `CHANGELOG.md`). Since the fix such an entry is refused at
`/o/authorize/`, but the rows are not deleted automatically. List the
canonical and DCR rows holding any entry the current registration check
would refuse (print-only; review before deleting). Cloud-client rows
(`mcp-sql-cloud.<name>`, including ones whose entry was since removed from
settings) are skipped — an `https` callback is expected there:

```sh
python manage.py shell -c "
from django.db.models import Q
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.views.registration import _is_loopback_redirect
from oauth2_provider.models import Application
prefix = mcp_sql_settings.APPLICATION_NAME_PREFIX
qs = Application.objects.filter(
    Q(name=mcp_sql_settings.APPLICATION_NAME) | Q(name__startswith=prefix)
).exclude(name__startswith=prefix + 'cloud.')
for a in qs:
    if not all(_is_loopback_redirect(u) for u in a.redirect_uris.split()):
        print(a.created, a.client_id, '->', repr(a.redirect_uris))
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
its own machine — useless for cross-machine token theft; enforced at
registration and re-checked on the requested redirect at `/o/authorize/`,
see the "DOT stores redirect URIs whitespace-joined" entry in
`docs/architecture.md`; the `django-oauth-toolkit>=3.4.1` floor also keeps
out DOT releases that redirected an unauthenticated `prompt=none` request to
the supplied `redirect_uri` before any of this ran, DOT #1719, and ones whose
redirect matching was not exact) and the
`/o/authorize/` issuance gate (real, active user with MFA + an MCP profile
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
Periodic cleanup of stale dynamically-registered Applications is not yet
implemented (see [Roadmap / known gaps](#roadmap--known-gaps)).
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

1. **Pre-flight**: the user must be active and satisfy your
   configured `MCP_SQL["MFA_CHECKER"]` (MFA is opt-in — the default
   `deny_unconfigured_mfa` denies everyone until you wire a real predicate,
   e.g. `allauth.mfa.utils.is_mfa_enabled`). If not, sort that first via the
   user admin. Staff status (`is_staff`) is not required: the profile
   assignment in step 2 is what grants access.
2. **Add to the profile group**: in Django admin, open the user, attach the
   group for the access tier you're granting. Each `MCP_SQL["PROFILES"]`
   entry has its own `GROUP_NAME` / `PERMISSION_CODENAME`; the in-package
   `default` profile's group is `mcp_sql_users` (carrying
   `mcp_sql.use_mcp_session`). A user must belong to **exactly one** profile
   group — 0 → denied (`NO_PERM`), >1 → denied as ambiguous
   (`AMBIGUOUS_PROFILE`). (One-off permission attach via
   `user.user_permissions.add(...)` also works but is not the recommended
   path.)
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
   is 6 h and there are no refresh tokens by default (see "Token lifetime /
   freshness FAQ" and "Refresh tokens (opt-in)"), so Claude Code re-OAuths whenever the token expires; DOT's
   default consent template has no "remember my choice" mechanism, so
   the user sees the page each time. This is deliberate: see
   "Every client requires consent" below.

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

### Every client requires consent

Every Application this package creates has `skip_authorization=False`: each
one created via `/o/register` (every Claude Code install), each declared
client, and, since migration 0016, the curated `mcp-sql` row. This forces the
OAuth consent screen on every `/o/authorize/` call — including repeat visits
by a user who already holds a live token for the client, because
`MCPAuthorizationView` pins DOT's `approval_prompt` to `force` (on `auto`, DOT
skips consent for such a user).

The curated row used to skip consent, on the reasoning that its redirect URI
is fixed in the migration so no attacker can mint a rogue copy. That does not
hold: its registered redirect is `http://127.0.0.1`, and DOT accepts any port
on a loopback IP at request time, so the attacker does not need a rogue
client at all. A phished `/o/authorize/?client_id=mcp-sql&redirect_uri=
http://127.0.0.1:31337&...` link gets the same silent code delivery as step 5
below. Migration 0016 flips existing rows (its reverse restores the old
posture); 0005 creates new ones requiring consent.

The consent page exists because of the attack chain it breaks (shown with a
DCR client; with the curated client, skip steps 1–2):

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

## Clients

Four kinds of client can hold an `mcp:sql` token, and every audit row records
which one did:

| Kind | `client_id` | How it gets registered | Consent |
|---|---|---|---|
| `curated` | `mcp-sql` | migration 0005, by the operator | forced (since migration 0016) |
| `dcr` | `mcp-sql-<22 chars>` | anonymous RFC 7591 self-registration at `/o/register`, loopback callbacks only | forced |
| `cloud` | `mcp-sql-cloud.<slug>` | `MCP_SQL["CLIENTS"]`, https callback | forced |
| `local` | `mcp-sql-local.<slug>` | `MCP_SQL["CLIENTS"]`, `http://localhost:<port>` callback | forced |

**The kind is derived, never declared.** A `CLIENTS` entry whose redirect
rules are all `https` lands in the `cloud` namespace; all-loopback lands in
`local`; an entry that mixes the two **refuses to boot**. That rule exists so
one `client_id` can never serve both a provider-hosted and a machine-local
surface — if it could, `client_kind` on an audit row would be a guess, and
"was that query from a hosted agent or from someone's laptop?" would have no
answer. Two surfaces means two entries, two client_ids, two audit identities.

### Declared clients

Cloud-brokered MCP clients complete the OAuth dance against a
**provider-hosted HTTPS callback** and store the token in the provider's
cloud, not on the user's device — the RFC 8252 loopback rule that governs
`/o/register` rejects them by construction. `MCP_SQL["CLIENTS"]` is the
allowlist that admits *specific, operator-blessed* ones **without** loosening
`/o/register`. Three ship by default:

```python
MCP_SQL = {
    # ... your other settings ...
    "CLIENTS": {
        "claude": {"LABEL": "Claude.ai", "REDIRECTS": [
            {"MATCH": "exact", "URI": "https://claude.ai/api/mcp/auth_callback"}]},
        "chatgpt": {"LABEL": "ChatGPT", "REDIRECTS": [
            {"MATCH": "prefix", "URI": "https://chatgpt.com/connector/oauth/"}]},
        "cursor": {"LABEL": "Cursor", "REDIRECTS": [
            {"MATCH": "exact",
             "URI": "https://www.cursor.com/agents/mcp/oauth/callback"}]},
    },
}
```

Shipping them ON costs nothing until someone uses one: each is an
`Application` row that no one can authorize against without logging in,
passing the MFA and profile gates, and clicking through a consent screen —
and the provider side needs the operator to paste a client_id before it can
connect at all. **To turn them off**, declare a smaller `CLIENTS` (a declared
key replaces its default wholesale) — `"CLIENTS": {}` runs loopback-only.

> **The client ID to paste into the provider.** It is **derived and stable**,
> not random: `<APPLICATION_NAME_PREFIX><kind>.<slug>` — e.g. the `claude`
> entry above yields **`mcp-sql-cloud.claude`**. Paste it as the connector's
> *OAuth Client ID* and leave the secret blank. Read them all back with
> **`python manage.py mcp_sql_clients`**, which prints each client_id next to
> its callbacks. (`migrate` logs the same lines, if your `LOGGING` surfaces
> INFO from `mcp_sql`.)

**What each entry does.** On `migrate`, a `post_migrate` receiver
(`provision_mcp_clients`, mirroring `provision_mcp_profiles`) materializes one
curated `Application` per entry: public / PKCE, `authorization_code`, **no
secret**, every rule's URI in `redirect_uris`, and — like every other
client — `skip_authorization=False` (consent required; the callback is fixed
and shared, so the same phishing surface applies). The `mcp-sql-` prefix on the `client_id` means
logout revocation already covers these tokens; the `.` after the kind keeps
the id disjoint from DCR's `mcp-sql-<22 url-safe chars>` shape (a `.` is not
in the url-safe-base64 alphabet).

**Recognition is settings-gated (fail-closed).** A declared client is accepted
only while its entry is present in `CLIENTS`. Remove the entry (and redeploy)
and the same `client_id` is denied at the very next `/o/authorize/` **and**
`/mcp/sql/` request — outstanding tokens included — even though its
`Application` row still exists. Provisioning never deletes rows (that would
cascade live tokens mid-`migrate`); it names orphaned ones in a WARNING so you
can clean up deliberately. De-authorizing a client is a settings edit, not DB
surgery.

**So are its redirects.** A declared client's callbacks are checked against
its `CLIENTS` entry on every request, never against the `redirect_uris` stored
on its row (provisioning still writes them there, but refreshes them only on
`migrate`, and nothing reads that copy for a declared client — the audit
trail's `client_redirect` comes from the entry too). Change or remove a rule and
redeploy: the new callback is accepted and the old one refused at the next
`/o/authorize/` request, without a `migrate`. When a request omits
`redirect_uri`, the default is the entry's callback if it declares exactly one
rule and that rule is `"exact"`; otherwise there is none and the request gets
the error page (a prefix is not a callback).

**Recognition also requires `client_id == name`.** Every check that reads
settings keys on the `client_id`, while recognition reads the `Application`'s
`name`; every row this package writes (migration 0005, `/o/register`,
provisioning) carries the same string in both. A row whose two differ — say,
one named `mcp-sql-cloud.claude` created by hand with another `client_id` — is
not an MCP client at all: refused at `/o/authorize/`, and its tokens get a
`bad_application` 401 at `/mcp/sql/`. This applies to the curated and DCR rows
too: a curated `mcp-sql` row whose `client_id` was edited away from its name
stops working until the two match again.

**Exact vs. prefix redirect matching.**

- `"exact"` (Claude, Cursor): a fixed callback, matched by DOT's own exact
  matcher (`redirect_to_uri_allowed`, the function behind
  `Application.redirect_uri_allowed`) run on the entry's exact URIs from
  settings — so "exact" means what it means for any DOT application on the
  installed DOT version, only the list comes from `CLIENTS`.
- `"prefix"` (ChatGPT / Codex-cloud): the callback is
  **per-connector-instance** — `https://chatgpt.com/connector/oauth/{callback_id}`
  — so no single exact URI can be pre-registered. One override
  (`MCPOAuth2Validator.validate_redirect_uri` → `_redirect_under_prefix`)
  accepts a redirect **iff** it is `https`, has no `@` anywhere in its
  authority (no userinfo, not even an empty one), carries no query, fragment
  or `;params` (not even a bare `?` / `#`), its host **exactly equals** the
  prefix host (never `endswith`, so `chatgpt.com.evil.com` is rejected), its
  port matches, it has no `..` segment and no backslash (which a browser
  reads as `/`, so `..\` is traversal too), and its path starts with the
  allowlisted prefix path — anchored at a `/` boundary, so `.../oauthEVIL`
  cannot pass as `.../oauth`. A client may carry both kinds of rule; each is
  matched by its own check, both from settings. A redirect that matches
  neither is refused — a declared client never falls back to the row-backed
  matching. The canonical row and every loopback DCR client keep DOT's stock
  matching against their own rows. Every client that is not a declared cloud
  client (the canonical row, every DCR client, every declared local client)
  is checked only after the requested redirect passes the `/o/register`
  loopback predicate (`_is_loopback_redirect`), and its default (used when a
  request omits `redirect_uri`) is held to the same predicate. So for such a
  client, the validator refuses a non-loopback redirect whether it was
  requested or stored.

### Cursor: three surfaces, two paths

Cursor is the case that motivates the derived-namespace rule, so it is worth
spelling out. It uses **fixed** redirect URLs, one per surface:

| Surface | Callback | How it reaches us |
|---|---|---|
| Web + Cursor Agents | `https://www.cursor.com/agents/mcp/oauth/callback` | the shipped `cursor` entry |
| Desktop app | `http://localhost:8787/callback` | DCR at `/o/register` |
| CLI | `http://localhost:8787/callback` | DCR at `/o/register` |

Cursor performs DCR automatically, so **the desktop app and CLI need no
configuration here** — they self-register and get their own
`mcp-sql-<token>` identity, distinct in the audit trail from the hosted
agents. `/o/register` registers the loopback subset of whatever a client
presents and echoes back what it registered (RFC 7591 §3.2.1), which is what
lets Cursor register at all: it may present the hosted https callback and the
legacy `cursor://anysphere.cursor-mcp/oauth/callback` deeplink alongside the
loopback one.

**We do not support the `cursor://` deeplink.** Admitting a custom scheme
means adding it to `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]`, which is
install-global — it would relax redirect handling for every OAuth application
in your project to accommodate one client's fallback path. Current Cursor
builds use the loopback callback; if a build falls back to the deeplink, that
authorization fails against this server.

**If you need the static-credentials path** (Cursor's `mcp.json` `auth`
block, where the operator pins a `CLIENT_ID` instead of letting Cursor
register), declare the desktop surface as its **own entry** rather than adding
a second URI to `cursor`:

```python
"CLIENTS": {
    # ... claude, chatgpt, cursor ...
    "cursor-desktop": {"LABEL": "Cursor Desktop", "REDIRECTS": [
        {"MATCH": "exact", "URI": "http://localhost:8787/callback"}]},
},
```

That yields `mcp-sql-local.cursor-desktop`, classified `local`, and it needs
`"http"` in `ALLOWED_REDIRECT_URI_SCHEMES`. Note that **port 8787 is
hardcoded in Cursor today and there is an open request to make it dynamic**
(per RFC 8252, a loopback client may use any port) — an exact rule pinned to
8787 breaks the day that lands, whereas the DCR path above keeps working
untouched. Prefer DCR; treat this entry as a stopgap.

Note that `"http"` in `ALLOWED_REDIRECT_URI_SCHEMES` is required
**unconditionally**, not because of this entry: `/o/register` is always
mounted and only mints http loopback callbacks, so the package refuses to boot
without it regardless of which clients you declare.

That puts it at odds with DOT ≥ 3.4's opt-in
`OAUTH2_PROVIDER["COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME"]`. The gate has
no runtime effect; it decides how `manage.py check --deploy` reports `"http"`
in the scheme list — warning `oauth2_provider.W008` while it is `False` (the
default, so you will see that warning under `--deploy`), error
`oauth2_provider.E003` when `True`. With the gate on, no configuration passes
both that check and this package's boot validation. Leave the gate off, or
turn it on and add `"oauth2_provider.E003"` to `SILENCED_SYSTEM_CHECKS` —
Django silences errors as well as warnings. (DOT's own hint for E003 says to
keep `http` if you support RFC 8252 loopback callbacks, which this package
does.)

Loopback entries are held to narrower rules than https ones: `localhost` only
(never `127.0.0.1` / `::1`, which DOT port-wildcards — that would silently
widen an exact rule into "any port on the user's machine"), an explicit port,
a non-root path, and `MATCH: "exact"` (prefix-matching a loopback URI would
admit any path on that port). While a `local` entry is declared, the package
also refuses to boot with DOT ≥ 3.4's
`OAUTH2_PROVIDER["ALLOW_LOCALHOST_LOOPBACK"] = True`: that flag port-wildcards
`localhost` the way DOT already treats `127.0.0.1` / `::1`, which would turn
the exact rule into "any port on the user's machine". Without a `local` entry
the flag is left alone — DCR and the curated Application already accept any
port on the loopback IPs, so it changes nothing this package promises.

https entries carry a host rule of their own: the host must be a
**fully-qualified ASCII DNS name** (an internationalised domain in its
punycode `xn--` form) — never an IP literal of any kind, never a single-label
name (`localhost4`, a machine's own hostname: those resolve only locally), and
never under a special-use suffix that only resolves locally (`.localhost`,
`.local`, `.home.arpa`, `.internal`, `.localdomain*`). The kind is derived from the scheme, so an https
callback that actually pointed at the user's machine would be namespaced and
audited as provider-hosted; refusing every non-DNS host is simpler, and harder
to get wrong, than recognising every spelling of loopback. (A public DNS name
that happens to resolve to loopback is beyond any syntactic check — this is
your own config, so don't declare one.)

### Onboarding a declared client (operator + user)

**Before you start.** Unlike a loopback client, a cloud client is driven by the
*provider's* servers — they fetch your discovery documents and open the
transport. Your server must therefore be reachable at a **public HTTPS URL**; a
`localhost` dev server will not work. Put it behind a real deployment or a
tunnel (ngrok / cloudflared), and make sure the discovery documents advertise
that public `https` origin (if a proxy terminates TLS, set
`SECURE_PROXY_SSL_HEADER` and `USE_X_FORWARDED_HOST` — see `example/settings.py`).
The token's RFC 8707 audience does not depend on them: the accepted
`resource` and the URL a token is checked against are built by the same rule
(see "The `resource` parameter (RFC 8707)").

1. Run `migrate`. Provisioning is a `post_migrate` receiver — it runs on any
   deploy that migrates and is idempotent, but a plain web-process restart does
   **not** provision it. If you added an entry without migrating, run
   `python manage.py migrate` (a no-op run still fires the receiver). A new
   entry needs its row (DOT's grants and tokens point at one); a changed or
   removed callback on an existing entry does not — it applies at the next
   request, and `migrate` only refreshes the row's unread copy. A slug
   must be short enough for `<prefix><kind>.<slug>` to fit DOT's
   `Application.client_id` and `name` columns (255 characters); a longer one
   refuses to boot.
2. Ensure `"https"` is in `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]` —
   with any https client declared the app **refuses to boot** without it. DOT's
   default already includes `https`; you only hit this if you narrowed the list
   (e.g. to `["http"]` for loopback DCR).
3. In the provider's connector UI, add a custom MCP connector pointing at
   `https://<host>/mcp/sql/`, open its **Advanced / manual client_id** field,
   and paste the derived `client_id`. Leave the client secret **blank** (these
   are public/PKCE clients).
4. The user connects: login + MFA + the one-click consent screen, then tool
   calls work. As with loopback clients, **consent recurs every 6 h** — token
   TTL is 6 h and there are no refresh tokens by default, so the user
   re-consents each time the token expires (unless the install opts in to
   capped refresh tokens). There is no "remember me"; this is deliberate (same
   rationale as [DCR-minted clients require
   consent](#every-client-requires-consent)).

**Strongly recommended: a cloud-tolerant `SESSION_MODEL`.** A cloud client's
token lives in the provider's cloud, and a tool call can arrive minutes after
the user last touched a browser. If you set `MCP_SQL["SESSION_MODEL"]`, the
runtime gate passes only while the user has an unexpired session row (it keys on
*user*, not device, so multiple devices are already fine). The pitfall is a
session model whose rows are torn down the moment the browser tab closes: a
cloud tool-call arriving later then 401s despite a valid token. Prefer a session
that outlives the originating tab, or leave `SESSION_MODEL` unset for
cloud-heavy deployments. This is a recommendation only — the package neither
warns nor errors on the combination.

**The consent screen names the client.** It shows the operator-authored
`LABEL` for a declared client and, for every client, the **destination** the
authorization code will be delivered to (`scheme://host[:port]`, taken from
the validated `redirect_uri`). A self-registered DCR client gets no label: the
`client_name` it sent at registration is attacker-chosen free text, so
rendering it would let anyone label themselves "Claude Code". Its callback
address is its only identifier, which is the honest one — that address is
where the code actually goes.

Be clear about what the destination line can and cannot tell a user. It names
the **provider or machine** the code goes to (`https://claude.ai`,
`https://chatgpt.com`, `http://localhost:8787`) — never **whose account** at
that provider. Claude.ai's callback is one URL shared by every Claude.ai
account, and every ChatGPT connector's `/connector/oauth/<id>` callback renders
as `https://chatgpt.com`. So an attacker who adds their own connector against
your server, starts the flow and sends the resulting authorization link to a
user with an MCP profile produces a page that looks exactly like a legitimate one; if the
user approves, their browser is sent to the shared callback with a code bound
to the attacker's PKCE challenge and carrying the attacker's `state` (the
shared-callback phishing surface noted under "What each entry does"). Whether
the provider then completes that callback for the attacker's connector is the
provider's behaviour, outside this server, and was not tested — assume it
might. Showing
the connector id would not help — the user cannot tell theirs from an
attacker's. The page's real defence is its instruction, **"Only continue if
you started this from there"**: approving is an explicit, CSRF-protected POST,
and an approval the user did not initiate *is* the attack. That holds on every
visit, including for a client the user has already authorized:
`MCPAuthorizationView` pins DOT's `approval_prompt` to `force`, because on
`auto` DOT would skip the page and issue a code on a plain GET to anyone
holding a live token for that (shared) Application. Behind the page: every
`/mcp/sql/` request whose bearer token resolves to a user re-runs the issuance
gate (active account, MFA, one profile); every tool call is audited in
`MCPQueryLog` under that user with the client's id and kind, and every gate
denial for a token that resolved to a user — handshake requests included —
in `MCPAuthRejectionLog` with the application name (`client_kind` is blank
when the Application no longer classifies); a *successful* handshake
(`initialize`, `tools/list`) writes no row and does not count toward the
volume tripwire; a token lives only as
long as `ACCESS_TOKEN_EXPIRE_SECONDS` (6 h in the recommended config); and
logging out (or a password change) deletes the user's MCP access tokens,
refresh tokens and pending MCP authorization codes, so a code approved a
moment ago — say, on a link the user now realises they did not start —
cannot be exchanged afterwards. Not reached: a code or refresh exchange
already in progress at that instant. Refresh tokens exist only when
`MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]` opts in (see "Refresh tokens
(opt-in)"); one obtained before logout then gets `invalid_grant` (pinned by
`test_oauth.py::TestLogoutKillsPendingCode`). If you re-theme
`mcp_sql/authorize.html`, keep both the destination and that instruction.

**Audit.** Every `MCPQueryLog` and `MCPAuthRejectionLog` row carries three
attribution columns: `application_name` (the client_id), `client_kind` (the
derived `curated` / `dcr` / `cloud` / `local`), and `client_redirect` — the
callbacks the client may use, truncated to the column width: for a declared
client the URIs its `CLIENTS` entry declares at request time (what its
redirects are checked against, not the row's copy, which lags until
`migrate`), for any other Application its **registered** `redirect_uris`
(including a declared client removed from `CLIENTS`, whose row is all that
is left).
Read `client_redirect` as "one of these", not "this one": DOT does not persist
which redirect a given authorization used, so the allowed set is the
closest attribution available at request time. `client_kind` is blank when the
Application classifies as nothing, which is the de-recognised case (DOT
resolved the token; the client is no longer part of the MCP surface). The
query-volume tripwire names the client too: its alert names the client whose
query crossed a per-user threshold. Counting is per user across clients, so a
burst spread over several clients (say Claude.ai and a self-registered client
on a laptop) still alerts — once, naming the client that tipped it over; the
audit rows above give the per-client breakdown.

**Troubleshooting — "your account was authorized, but … returned an error
when connecting".** If the OAuth dance succeeds (you logged in + consented)
but the connector then fails, the usual cause is the **trailing slash**:
Claude.ai's web connector normalises the URL and POSTs to `/mcp/sql` (no
slash), while `/mcp/sql/` is the advertised path. Django's `APPEND_SLASH`
cannot 301-redirect a POST — that would drop the body — so a server routing
*only* `/mcp/sql/` raises a 500 (`RuntimeError: … you have APPEND_SLASH set`)
the instant the transport opens, and the client reports a generic connect
error. The package routes **both** `/mcp/sql/` (canonical — what `reverse()`
builds from) **and** `/mcp/sql`, so this works out
of the box. The RFC 9728 `resource` advertises whichever spelling the client
asked the metadata for (see "Trailing slashes in the resource identifier"). If you mount the endpoint under a different path, or front it with
a proxy / CDN that rewrites trailing slashes, make sure the slash-less POST
still reaches the view. (Pinned by `tests/test_mcp_endpoint.py::TestEndpointRouting`.)

**References** (this section is the how-it-works runbook the implementation
docstrings point back to):

- Code: `mcp_sql/clients.py` (the taxonomy — kinds, `DeclaredClient`,
  namespace derivation, `ClientIdentity`), `mcp_sql/conf.py` (`clients()`),
  `mcp_sql/signals.py` (`provision_mcp_clients`), `mcp_sql/oauth.py`
  (`MCPOAuth2Validator.validate_redirect_uri` / `_redirect_under_prefix`),
  `mcp_sql/consts.py` (settings-gated recognition + classification),
  `mcp_sql/validation.py` (`_validate_clients`).
- Provider setup — paste the derived client_id (no secret): **Claude.ai** →
  Settings → Connectors → *Add custom connector* → Advanced → *OAuth Client
  ID*; **ChatGPT** → Settings → Connectors → *Create* (advanced OAuth);
  **Cursor** → `mcp.json` `auth.CLIENT_ID` (only needed for the hosted-agent
  surface; the desktop app and CLI use DCR).
- Provider callbacks: Claude `https://claude.ai/api/mcp/auth_callback` (one,
  unified across web/desktop/mobile/Cowork), ChatGPT
  `https://chatgpt.com/connector/oauth/{id}` (per-instance — the reason
  ChatGPT needs `MATCH: "prefix"`), Cursor
  [`https://www.cursor.com/agents/mcp/oauth/callback` and
  `http://localhost:8787/callback`](https://cursor.com/docs/context/mcp).
- MCP authorization model: <https://modelcontextprotocol.io/specification> (the
  Authorization section — OAuth 2.1 + PKCE + protected-resource discovery).
- Governing specs: PKCE — [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636);
  protected-resource metadata — [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728);
  AS metadata — [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414); native-app /
  loopback redirects — [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252);
  dynamic client registration — [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591).


## Revoking access

Paths by urgency:

| Urgency | Action | Effect |
|---|---|---|
| User-driven | The user logs out of the web app | `user_logged_out` signal deletes the user's MCP-purpose access **and refresh** tokens and pending authorization codes — the canonical `mcp-sql` Application, every DCR-minted `mcp-sql-<token>` client, **and** every settings-declared `mcp-sql-{cloud,local}.<slug>` client (all covered by `Q(application__name="mcp-sql") \| Q(application__name__startswith="mcp-sql-")`) |
| User- or admin-driven | The password changes (the user's own change, an admin reset, `set_unusable_password`; proxies of the user model included) | Same deletion, from a `pre_save`/`post_save` pair on the user model (after the change commits, on the database the user was saved to); an `MCPAuthRejectionLog` row with reason `password_change` when it deleted anything (as for logout: a user with no MCP token or pending code gets no row, so the table records only changes that ended MCP access). Needs no session table. The stored hash is compared through the model's base manager on that database, so a default manager that filters rows (active users only, soft delete) cannot hide the user — reactivating a user with a new password revokes like any other change. Django's login-time hash upgrade is not a change: the package wraps `AbstractBaseUser.check_password` / `acheck_password` (in `ready()`) to mark the save they make while they run, and only that save is exempt — when the hash checked is the one stored (a legacy hash for a new password assigned in memory and then checked is a change). Any other new hash revokes, even one saved the same way (`set_password(...)` + `save(update_fields=["password"])`, as an SSO / LDAP sync does). A user model that overrides `check_password` without calling `super()` loses the exemption (its hash upgrades revoke too). **Multi-database installs:** the deletes and the audit row commit together in a transaction of their own on the database DOT keeps its tokens on; a transaction the request has open there (`ATOMIC_REQUESTS`) does not undo them when it rolls back — they run on a separate connection, which does not see tokens that transaction has written and not committed, and gives up after 5 s waiting for a row lock it holds (logged, no audit row; delete those tokens by hand). A failure to write the audit row is logged and never undoes the deletes (a connection lost while writing it ends the deletes' transaction too: logged as a failed revocation, not as "Revoked"), and nothing the revocation raises reaches the logout or the save. Logout's revocation waits for the default database's commit. **Not seen:** bulk `User.objects.filter(...).update(password=...)` and `User.objects.bulk_update(users, ["password"])` send no model signals — delete the tokens explicitly (row below) when changing passwords that way. |
| Operator, keep cohort | `python manage.py shell -c "from oauth2_provider.models import get_access_token_model, get_grant_model, get_refresh_token_model; u='alice@example.com'; get_grant_model().objects.filter(user__email=u).delete(); get_refresh_token_model().objects.filter(user__email=u).delete(); get_access_token_model().objects.filter(user__email=u).delete()"` | Pending codes, refresh tokens (they exist only with the opt-in refresh grant) and outstanding tokens dropped in < 1 s (codes first, so a just-approved code cannot be exchanged afterwards; this snippet covers every OAuth Application the user holds, not only MCP's); user can re-OAuth |
| Operator, kick out | Remove from `mcp_sql_users` group (admin) | Outstanding tokens still exist in DB but `MCPOAuth2Authentication` re-checks the perm on every request and rejects. Combine with the token-delete shell snippet for a clean state. |

The 6 h hard cap on `access_token` lifetime is the worst-case fallback:
even with no other action, a leaked or no-longer-needed token expires
within 6 h.

**What logout cannot revoke.** Revoking on logout needs to know who is
logging out. A logout from a web session that has already ended
(`SESSION_COOKIE_AGE` elapsed, swept by `clearsessions`, a cache session store
restarted) or with no session cookie at all arrives anonymous: Django sends
`user_logged_out` with `user=None` and django-allauth sends nothing, so no
token or pending code is deleted and no audit row is written. The stale cookie
cannot name the user either, since an expired session no longer loads. Those
tokens live until they expire unless something else ends them: the operator
rows above, or, with `SESSION_MODEL` set, the per-request session gate, which
refuses them once the user holds no live session. A user who wants their MCP
access gone should log in and log out again (a logout from a live session
revokes every MCP token and pending code they hold, not only that session's),
or ask an operator. A password change revokes them too (row above), whatever
the session state.

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
`MCPOAuth2Authentication` re-runs `resolve_profile(user)` on every call —
a user who lost their profile group (or landed in two) no longer resolves
to exactly one profile and is locked out of `/mcp/sql/` at the next request
without waiting for token expiry. If you
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
ALERT only — the query was not blocked. The `client=` in the alert is only the
client whose query crossed the per-user threshold, and a declared `cloud`
client_id (`mcp-sql-cloud.claude`, …) is one Application shared by every
account at that provider — a connector the user approved from a phished link
looks exactly like their own. So "Alice uses Claude.ai" does not explain the
alert by itself. Open the [usage summary](#auditing-usage) and the user's
`MCPQueryLog` rows (per-client breakdown, `client_ip`, the SQL) and **ask the
user** whether the volume is theirs. If it is not, or you cannot tell, revoke
their MCP tokens (logging them out does it) before anything else; raise the
threshold only for activity the user confirms as legitimate heavy use (MCP
agents are greedy; the defaults are deliberately generous).

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
- **Why no refresh tokens by default?** They would make the 6 h
  access-token TTL meaningless as a re-consent interval: a refresh token
  keeps renewing access without the user. Users instead re-OAuth every 6 h
  (the session-trust gate at `/o/authorize/` runs without re-prompting MFA
  so long as the Django session is still valid; DCR and cloud clients show
  the consent screen each time), mediated by the client. Enforcement is the
  package's OAuth server (see "The OAuth server"): its authorization-code
  grant generates no refresh token (so `/o/token/` returns none and no
  `RefreshToken` row is created), `MCPOAuth2Validator.save_bearer_token`
  drops one a stock DOT token view would mint, and `/o/token/` answers every
  `grant_type=refresh_token` request with a constant `invalid_grant` —
  including refresh tokens minted by releases up to and including 0.1.0b5,
  which did emit them. `REFRESH_TOKEN_EXPIRE_SECONDS` is not what disables
  refresh: DOT reads `0` as *no age limit*, and on those releases such a
  token renewed access indefinitely. An install that wants fewer consent
  prompts can opt in to refresh tokens with a hard cap measured from the
  consent (see "Refresh tokens (opt-in)").
- **Why no idle timeout?** Out of scope. The 6 h hard cap + logout
  revocation + the daily-volume Sentry alerts bound exposure for **every**
  consumer. A consumer that enables the **opt-in** session-existence gate
  (`MCP_SQL["SESSION_MODEL"]`, see next item) additionally caps token
  usefulness at its own `SESSION_COOKIE_AGE`. Revisit if abuse patterns
  appear.
- **Why does MCP stop working when my web session ends?** Only if you
  **opted in** to the runtime session-existence gate by setting
  `MCP_SQL["SESSION_MODEL"]` to a session-with-user model. When it's set,
  every MCP request re-checks that the user holds at least one live session
  (`MCPOAuth2Authentication.authenticate`) — the *runtime* half of the
  design's "Option D session-trust" model: issuance trusts a fresh login +
  MFA, and runtime trusts that the same operator still has at least one live
  web session somewhere. With the gate on, if the session expires naturally
  (at your `SESSION_COOKIE_AGE`), an admin deletes it, `clearsessions`
  sweeps an expired row, the operator clears their browser cookies, or a
  server restart wipes session state, the token immediately stops being
  honored even though it's not yet at its 6 h hard cap. Recovery: log back
  in at the Django UI; the next MCP call goes through (no re-OAuth needed if
  the AccessToken row is still alive — the gate only checks "does any
  session for this user exist", not "is this token tied to THE session that
  issued it"). **When `SESSION_MODEL` is unset (the default)** — stock
  `django.contrib.sessions.Session` has no `user` FK, so the gate can't run
  — the token lives until its 6 h cap or explicit logout, regardless of web
  session state.
- **Why "session-trust" and not "fresh 2FA every authorize"?** This rests on
  two consumer-configured pieces. **MFA is opt-in**: `MCP_SQL["MFA_CHECKER"]`
  defaults to `deny_unconfigured_mfa` (fail-closed — denies everyone until a
  consumer wires a real predicate such as `allauth.mfa.utils.is_mfa_enabled`).
  Once wired, and if the consumer's login flow performs MFA at session
  establishment, the consumer's `SESSION_COOKIE_AGE` already requires
  login + MFA at the boundary — so an active session is itself proof of
  recent-enough MFA, and a separate fresh-TOTP challenge at every issuance
  would be redundant. If your MFA is *not* tied to session establishment,
  promote the gate to a `session["mfa_authenticated_at"]` freshness check
  (see "Error-message verbosity" / threat-model notes).
  Promote the gate to require a `session["mfa_authenticated_at"]`
  freshness check if the threat model ever expands (e.g. whitelist
  grows to include PII tables, the user base grows beyond the
  internal team).

## Error-message verbosity

`MCPOAuth2Authentication.authenticate` raises distinct
`AuthenticationFailed` messages (a 401 carrying the `WWW-Authenticate`
challenge) for each gate it fails:

- `"Token was not issued by an mcp-sql Application."`
- `"Token does not carry the mcp:sql scope."`
- `"User account is inactive."`
- `"User does not have a verified TOTP device."`
- `"User holds no MCP profile permission."` (resolves to no profile)
- `"User is assigned to more than one MCP profile; access is denied …"`
  (ambiguous — resolves to >1 profile)
- `"No active web session — re-login at the Django UI to re-issue MCP
  access."` (only when the opt-in `SESSION_MODEL` gate is enabled)
- `"Token is not bound to a user."` (a token with no user, refused before
  the gates; logged at WARNING, no audit row)

and one that is not a 401: when a gate raises instead of deciding (the
`MFA_CHECKER` failing, a DB blip, a bad `SESSION_MODEL`), the response is a
**503** with `"MCP access could not be verified; try again later."`,
`Retry-After: 30` and no `WWW-Authenticate` challenge (`auth.GateUnavailable`, audited as
`gate_error`), so clients retry instead of starting an OAuth
re-authorization that would fail the same way.

The 401 messages reach the MCP client (typically Claude Code) as the body of
the response, and from there the user sees them. The verbosity is **deliberate**:
the consumers are internal users onboarding to the surface, and
"your MFA device was removed, re-set it up" is faster to act on than a
generic "Token is no longer valid." If the threat model ever changes —
the surface gets opened to external partners, or token-holders need to be
treated as potential attackers — collapse the 401 branches into a single
generic message and rely on server logs (and `MCPAuthRejectionLog`) for the
granular reason.

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

The following sequence verifies the full OAuth + MCP transport path against
a running local deployment (substitute your own start command and hostname):

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
values (`mcp-sql`, public, PKCE, `skip_authorization=False` — like every
other client, see "Every client requires consent" above), loopback redirect
URIs:

```sql
SELECT name, client_id, client_type, authorization_grant_type,
       skip_authorization, redirect_uris
FROM oauth2_provider_application
WHERE name LIKE 'mcp-sql%';
```

Expected: exactly one row with `name='mcp-sql'`, plus zero or more
`name='mcp-sql-<token>'` rows (one per `claude mcp add` invocation across
all developers) and one `mcp-sql-{cloud,local}.<slug>` row per declared
client, every one with `skip_authorization=false`.

If the curated row is missing, the `0005_create_mcp_sql_application`
migration did not run — re-apply with `python manage.py migrate mcp_sql`. If
it still has `skip_authorization=true`, migration
`0016_curated_application_requires_consent` has not run. If a DCR-minted row
has `skip_authorization=true`, it predates the security fix; delete it and
have the developer re-register via `claude mcp add`.

## Post-incident notes

- Token-table cleanup is **not** automatic beyond expiry. Operators may
  prune expired tokens periodically; the DB load is negligible until the
  cohort grows substantially. A scheduled prune task is a possible future
  addition (see [Roadmap / known gaps](#roadmap--known-gaps)).
- If a profile's group (the `default` profile's is `mcp_sql_users`) is
  deleted, every user in that tier loses MCP access. The `post_migrate`
  receiver in `mcp_sql.signals` re-provisions every profile's group +
  permission on the next `migrate`; to recreate the `default` profile's
  group by hand:

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

## Roadmap / known gaps

These are deliberately unimplemented today; each is bounded by an existing
control so none is a live exposure:

- **Periodic cleanup of stale DCR-minted Applications.** Every
  `claude mcp add` mints one `mcp-sql-<token>` Application row, and nothing
  prunes them. Bounded by: loopback-only redirect URIs + the issuance gate +
  the silent per-IP registration block, so an accumulated row is inert
  without a live MFA'd cohort user. A scheduled prune could be added if row
  growth becomes operationally noticeable.
- **Expired-token / audit-table retention.** Token rows past their 6 h
  expiry and old `MCPQueryLog` / `MCPAuthRejectionLog` rows are not
  auto-pruned. Negligible DB load until the cohort grows substantially.
- **"Application bound to creating user" (full anti-phishing defense).** The
  consent screen (see [Every client requires
  consent](#every-client-requires-consent)) converts the silent-GET
  phishing attack into one needing the victim's active click; binding each
  DCR client to its creator would close the gap fully, at the cost of a
  schema change on `oauth2_provider_application`.
- **Client ID Metadata Documents (CIMD) for cloud clients.** The IETF-draft
  direction both vendors are moving toward: the `client_id` is an HTTPS URL to
  a metadata document the AS fetches, so no per-client row or operator paste is
  needed. Deferred deliberately — its payoff is directory-scale onboarding we
  do not have, and it adds an SSRF-guarded outbound fetch on the auth path while
  still needing a row for DOT's non-null `Grant.application` FK. Today's
  settings-declared [clients](#clients)
  cover the same clients with a curated allowlist and no new network egress; if
  CIMD lands natively in django-oauth-toolkit it becomes an additive
  recognition branch, not a rewrite.
- **Out of scope by design:** per-token / per-minute / concurrent rate
  limits. The DB role + per-statement GUCs + the per-user volume tripwires
  are the enforcement/alerting layers.
