# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.2.0b1

The multi-client release: declared clients ship ON, Cursor is supported, every
`MCP_SQL` key has a default, and every audit row now names the client that
made the request.

### Breaking

All but the last three fail loudly at startup, and none require any client to
reconnect (client_ids are unchanged, provisioning never deletes rows, and
tokens are 6-hour anyway). The default-ON flip, the dropped `is_staff`
requirement and the curated client's new consent page are called out
separately below precisely because they do **not** announce themselves.

- **`MCP_SQL["CLOUD_CLIENTS"]` → `MCP_SQL["CLIENTS"]`**, reshaped from a list
  of entries carrying `NAME` to a **dict keyed by slug**, and from the singular
  `REDIRECT_MATCH` / `REDIRECT_URI` pair to a **`REDIRECTS` list** of
  `{"MATCH": "exact"|"prefix", "URI": ...}` rules (so one provider is one
  client_id even when it calls back from several shapes). Optional `LABEL` sets
  the consent-screen display name. Declaring the old key raises
  `ImproperlyConfigured` naming the replacement — it is not silently ignored,
  because ignoring it would empty `CLIENTS`, de-recognise the consumer's
  declared clients, and start rejecting their live tokens.

  ```python
  # before                                     # after
  "CLOUD_CLIENTS": [                           "CLIENTS": {
      {"NAME": "claude",                           "claude": {
       "REDIRECT_MATCH": "exact",                      "LABEL": "Claude.ai",
       "REDIRECT_URI": "https://…/cb"},                "REDIRECTS": [
  ]                                                        {"MATCH": "exact", "URI": "https://…/cb"}],
                                                   },
                                               }
  ```

- **Unknown `MCP_SQL` keys are now rejected** (`extra="forbid"`, at every
  nesting level). A typo'd key used to be ignored, leaving the default in place
  with nothing in the logs to explain why the setting had no effect.
- **`"https"` in `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]` is now
  required by default**, because the shipped clients use https callbacks. DOT's
  own default includes it; this only affects a consumer who narrowed the list
  (e.g. to `["http"]`). Add `"https"`, or set `"CLIENTS": {}`.

- **`"http"` in `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]` is now
  required unconditionally**, not just when a `local` client is declared.
  `/o/register` is mounted unconditionally and only ever mints `http` loopback
  callbacks, and DOT enforces the scheme list at the authorization redirect
  rather than at boot — so narrowing the list to `["https"]` used to boot clean
  and then break every self-registering client (Claude Code, Cursor
  desktop/CLI) opaquely at `/o/authorize/`. It is now a boot error. A consumer
  running `["https"]` today will not start until they add `"http"`; DOT's own
  default has both, so most consumers never declared the key at all.

  **Known conflict with DOT ≥ 3.4's opt-in RFC 9700 gate.** DOT 3.4 added
  `OAUTH2_PROVIDER["COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME"]`. It changes no
  runtime behaviour — it only sets the severity of the `manage.py check
  --deploy` finding for `"http"` in `ALLOWED_REDIRECT_URI_SCHEMES`: warning
  `oauth2_provider.W008` while the gate is `False` (DOT's default, so on DOT
  ≥ 3.4 every deployment of this package sees that warning under
  `--deploy`), error
  `oauth2_provider.E003` once it is `True`. Since this package will not boot
  without `"http"`, no configuration satisfies both with the gate on:
  `check --deploy` fails on E003. The `http` entry is what RFC 8252 loopback
  callbacks need, and DOT's own hint for E003 says to keep it if you support
  them. Either leave the gate off, or turn it on and add
  `"oauth2_provider.E003"` to `SILENCED_SYSTEM_CHECKS` (Django silences errors
  as well as warnings; checked against DOT 3.4.1). DOT says the gate defaults
  flip to `True` in its 4.0; this package caps DOT at `<4`.

- **Declared clients now ship ON.** `CLOUD_CLIENTS` defaulted to `[]`; `CLIENTS`
  defaults to `claude`, `chatgpt` and `cursor`. A consumer who declared the old
  key hits the `ImproperlyConfigured` above and makes a deliberate choice — but
  one who never declared it was running a structurally loopback-only surface on
  the 0.1.0b5 default, and after this upgrade `provision_mcp_clients` creates
  three `Application` rows bound to `claude.ai` / `chatgpt.com` / `cursor.com`
  callbacks at the next `migrate`, with no error and no prompt. The derived
  client_ids are guessable (`mcp-sql-cloud.claude`), so what stands between a
  phished authorization link and a token is now a cohort user (active + MFA +
  profile — the issuance gate limits who can be a victim, not whether the
  link works) declining the consent screen — no longer RFC 8252 loopback
  delivery. Under loopback-only, a phished code still landed on the victim's
  own machine; with a shared provider callback, the victim's browser is sent
  to the provider carrying a `state` the attacker's own connector minted, and
  the consent page looks the same either way (see "Changed" below). Whether
  the provider then completes that callback for the attacker's connector is
  provider behaviour this server does not control and that was not tested. An operator who
  deliberately chose loopback-only should know the posture moved.
  Set `"CLIENTS": {}` to keep the old behaviour, or name just the clients you
  want. Provisioning logs each client at INFO on every `migrate`.

- **`is_staff` is no longer required for MCP access.** Both the issuance gate
  at `/o/authorize/` and the per-request gate now check only `is_active`,
  `MFA_CHECKER`, and exactly one MCP profile: the explicit profile assignment
  (the profile's permission, via its group or granted directly) is the access
  grant, and a staff flag only duplicated it. At upgrade, any **active
  non-staff** user who already holds an MCP profile permission — for example
  through a group that also has non-staff members — gains access, with no
  error. Check who holds the profile permissions before upgrading. New
  auth-rejection rows use reason `inactive` ("User account is inactive"); rows
  written by 0.1.x keep `inactive_or_non_staff`, which stays a valid choice
  (migration `0015` adds the new one). Custom user models without an
  `is_staff` field now pass the gates, and `mcp_sql_smoke`'s attribution
  fallback no longer assumes the field.

- **The curated `mcp-sql` client now shows the consent page.** Migration
  `0016` sets `skip_authorization=False` on the existing row (its reverse
  restores `True`), and `0005` creates it that way on fresh installs. Every
  client kind now requires consent. The curated row used to skip it on the
  reasoning that its redirect is fixed, so no attacker can mint a rogue copy;
  but its registered redirect is `http://127.0.0.1`, and DOT accepts any port
  on a loopback IP, so a phished `/o/authorize/?client_id=mcp-sql&
  redirect_uri=http://127.0.0.1:<port>` link opened by a logged-in cohort
  user sent a code silently to any local port, where any listening process
  holding the PKCE verifier it chose could exchange it. Users of the fixed
  `mcp-sql` client_id (an MCP client configured with it explicitly) now click
  Authorize once per token, every 6 hours with the recommended token
  lifetime. Claude Code's `claude mcp add` registers its own client through
  `/o/register` and already saw the consent page, so it is unaffected. Also
  affects 0.1.0b5.

### Added

- **Every `MCP_SQL` key now has an in-package default** — declare only what you
  change, or omit `MCP_SQL` entirely. One merge rule, applied identically by
  the settings accessor and by `conf.merged_config()`: a declared key replaces
  its default **wholesale**, never member-by-member. In practice a real
  deployment sets two things: each profile's `ALLOWED_MODELS` (default: empty,
  so nothing is readable) and `MFA_CHECKER` (default: denies everyone). Both
  defaults are useless-but-safe on purpose.
- **Declared clients ship ON**: `claude`, `chatgpt`, and `cursor` (its hosted
  web / Cursor Agents surface). They are inert until an operator pastes a
  client_id into the provider's connector AND a user passes the login, MFA,
  profile, and consent gates. `"CLIENTS": {}` runs loopback-only.
- **Cursor support.** The hosted surface rides the shipped `cursor` entry; the
  desktop app and CLI need no configuration, because Cursor performs RFC 7591
  dynamic registration automatically and `/o/register` now accepts their
  request (see below). They therefore get their own `mcp-sql-<token>` identity,
  distinct in the audit trail from the hosted agents. The legacy
  `cursor://` deeplink is deliberately unsupported — admitting a custom scheme
  means widening `ALLOWED_REDIRECT_URI_SCHEMES`, which is install-global.
- **A `local` client kind** for a client that pins a fixed loopback port and
  cannot use DCR (Cursor's static `mcp.json` path). Held to narrower rules than
  an https entry: `localhost` only (never `127.0.0.1` / `::1`, which DOT
  port-wildcards), explicit port, non-root path, `MATCH: "exact"`. While one is
  declared, boot also refuses DOT ≥ 3.4's
  `OAUTH2_PROVIDER["ALLOW_LOCALHOST_LOOPBACK"] = True`, which would
  port-wildcard `localhost` too and silently turn the exact rule into "any port
  on the user's machine". Documented, not shipped — see `docs/oauth.md` →
  "Clients".
- **Client attribution on every audit row.** `MCPQueryLog` gains
  `application_name` and `client_kind`; `MCPAuthRejectionLog` gains
  `client_kind` (migration `0014`). `client_kind` is one of `curated` / `dcr` /
  `cloud` / `local` and is **derived, never declared** — for a declared client
  it comes from its redirect scheme, so it cannot drift from what the client
  is. The query-volume tripwire names the client too — the one whose query
  crossed the threshold; counting stays per user across clients, so a burst
  spread over several clients still alerts.
- **`manage.py mcp_sql_clients`** prints each declared client's client_id and
  callbacks — the values to paste into a provider connector, without scrolling
  through `migrate` output.

### Changed

- **A declared client's client_id namespace is derived from its redirect
  scheme**: all-https → `mcp-sql-cloud.<slug>` (unchanged from 0.1.0b5),
  all-loopback → `mcp-sql-local.<slug>`, and an entry mixing the two refuses to
  boot. One client_id must never span a provider-hosted and a machine-local
  surface, or `client_kind` on an audit row would be a guess.
- **`/o/register` registers the loopback SUBSET** of a request's
  `redirect_uris` and echoes back what it registered (RFC 7591 §3.2.1), instead
  of refusing any request containing a non-loopback URI. This is what lets
  Cursor register at all — it may present a hosted https callback and the
  `cursor://` deeplink alongside its loopback one. Nothing non-loopback is ever
  stored, an empty subset is still a refusal, duplicates collapse, and the list
  is capped at 10. The declared (unverified) `client_name` is now logged at INFO
  beside the minted client_id; it is still never persisted.
- **The consent screen now says who is asking and where the code will go.** It
  showed "Authorize MCP SQL?" for every client — naming the resource, never the
  requester or the destination — which left nothing to check on the screen that
  exists to break phished authorization links. It now shows the declared
  client's operator-authored `LABEL` and, for every client, the destination
  (`scheme://host[:port]`, rebuilt from the validated `redirect_uri`'s parsed
  parts so a userinfo component cannot render). A self-registered client gets
  no label: its `client_name` is attacker-chosen free text. The destination
  names the provider or machine, not whose account there — a shared callback
  (Claude.ai's, every ChatGPT connector's) renders identically for an
  attacker's own connector — so the screen's real check is its "Only continue
  if you started this from there" line.
- The `"prefix"` redirect matcher also refuses a backslash anywhere in the
  (percent-decoded) path, since a browser reads `\` as `/` in an https URL and
  `..\` is traversal by another spelling. Hardening rather than a reachable
  fix: oauthlib's absolute-URI check already rejects such a `redirect_uri`, and
  Django's `iri_to_uri` would encode it to `%5C` in the `Location` anyway — it
  is refused so the path anchor depends on neither.
- Provisioning now names orphaned declared-client `Application` rows in a
  WARNING. It still never deletes them — that would cascade live tokens in the
  middle of a `migrate`.

### Fixed

- **The RFC 9728 discovery document advertised a resource identifier that did
  not match the path it was served at, making the surface unreachable from
  clients that validate it.** `resource` was built straight off
  `reverse("mcp_sql_endpoint")` — `https://<host>/mcp/sql/`, with the trailing
  slash — while the document itself was served only at
  `/.well-known/oauth-protected-resource/mcp/sql`. RFC 9728 §3.3 requires the
  returned `resource` to be *identical* to the identifier the client inserted
  the well-known suffix into, and says the document MUST NOT be used
  otherwise. Cursor Desktop enforces this and aborted the flow after the
  consent screen but before the token exchange; Claude Code and Cursor CLI
  ignored the mismatch. Compounding it, the metadata path implied by the
  advertised identifier (`…/oauth-protected-resource/mcp/sql/`) returned 404,
  so no client could retrieve the document the spec-correct way.

  The document is now served under **both** spellings of the resource path and
  `resource` echoes the one requested, and the 401 challenge's
  `resource_metadata` pointer follows the spelling of the request that drew it
  (`/mcp/sql/` → `…/oauth-protected-resource/mcp/sql/`, `/mcp/sql` →
  `…/oauth-protected-resource/mcp/sql`). That covers both clauses of §3.3: a
  client that builds the metadata URL from its own identifier gets that
  identifier back, and one that follows the 401 pointer gets back the URL it
  sent the request to. What it cannot cover is a client that requests one
  spelling and then compares against the other — no single document satisfies
  that (the MCP Python SDK's `check_resource_allowed` normalises the slash, so
  it is lenient here either way). Both spellings already routed to the
  transport, so the derived audience reaches the same endpoint either way.
  The pointer's path changes only for requests to `/mcp/sql/`; a client whose
  request URL is slash-less — which is what the original Cursor Desktop failure
  implies — is pointed exactly where it was (its scheme is covered by the next
  entry). The pointer change was not re-tested against a live client. No live
  token is affected: a token bound to either spelling passes at either
  transport path (see the RFC 8707 entry below for what the server now does
  with `resource`).
- **Both discovery documents now agree on one origin.** The scheme is the
  other half of the same identifier: `resource` and the four AS endpoint URLs
  were composed with `request.build_absolute_uri`, which trusts
  `request.scheme`, while `issuer` deliberately forced `https` off `DEBUG`.
  Behind a TLS terminator that does not forward `X-Forwarded-Proto` (or with
  `SECURE_PROXY_SSL_HEADER` unwired) one document therefore advertised
  `"resource": "http://host/mcp/sql"` beside
  `"authorization_servers": ["https://host/o"]` — the same §3.3 mismatch, and
  AS endpoints on a different origin than the issuer naming them. Every
  absolute URL in both documents — and the `resource_metadata` URL in the 401
  challenge, which is where clients actually start, and the
  `registration_client_uri` in `/o/register`'s 201 — now goes through one
  hardened helper (`consts.absolute_url`). Note the widened effect: with
  `DEBUG` off, the AS endpoint URLs, the 401 pointer and
  `registration_client_uri` are now forced to https as well, where previously
  only `issuer` was. A `DEBUG=False` plain-http deployment was
  already out of spec for RFC 8414 §2, but it will now advertise an https
  surface it does not serve.
- **An RFC 8707 `resource` other than this server's MCP endpoint minted a
  token `/mcp/sql/` could never accept.** From DOT 3.4 (3.4.1 is the floor
  since 0.1.0b6) a `resource` sent to `/o/authorize/` or `/o/token/` is stored on the grant and
  access token, and DOT audience-checks every bearer carrying one against the
  request URL. Any `resource` was accepted, so another URL — or the endpoint
  with another scheme, host or path — got a 200 token and then a bare 401 on
  every MCP call: indistinguishable from a bad token, no audit row, and each
  call counted toward the bad-token IP throttle until a shared egress IP was
  silently blocked. The advertised value itself failed the same way behind a
  TLS-terminating proxy without `SECURE_PROXY_SSL_HEADER`: discovery says
  `https` (`DEBUG` off), DOT built the request URL as `http`. Now:
  - `/o/authorize/` and `/o/token/` accept a `resource` only if it names the
    discovery document's `resource` on the host of the request: scheme and
    host in any case, the scheme's default port spelled out or omitted, the
    path exactly the endpoint's, with or without the trailing slash. Anything
    else (including an empty value, the bare origin `https://<host>`, another
    path, port, host or scheme, a port the package does not take — two
    ports or above 65535, which URL parsers refuse too, or more than five
    digits, the package's own cap — a query, a fragment, userinfo) is
    **`invalid_target`** — a redirect to the client's validated
    `redirect_uri` with its `state` and no grant at the authorization
    endpoint (GET, and the consent POST's form field and query string), a
    400 at the token endpoint (`MCPTokenView`, now mounted at `/o/token/`;
    the code is not consumed). The package's `invalid_target` names the
    accepted value, never the client's (DOT's own errors, such as the
    token-step one below, may name it). A NUL (any control character) in
    `resource` — at the authorization GET, in the consent POST's form field
    or query string, or at the token endpoint — is refused by the OAuth
    views' control-character screen (0.1.0b6) with `invalid_request` (the
    error page at `/o/authorize/`, a 400 at `/o/token/`) instead of a 500.
  - Equivalent spellings are equivalent at each step, not across steps:
    when the grant carries a `resource`, `/o/token/` also
    requires each `resource` sent there to be one of the grant's, compared
    as strings. Exchange the code with the same `resource` string the
    authorization request carried, or with none (the token then carries the
    grant's); another spelling gets DOT's own `invalid_target`, which names
    the value sent, and the code is not consumed. When the grant carries
    none, DOT stores the token request's value (already limited to the
    advertised identifier by the package) on the token as sent. The MCP
    SDKs send the same value at both steps.
  - Discovery, and every other absolute URL the package builds, spells the
    host canonically: lowercased, without the scheme's default port. A proxy
    forwarding `Host: <name>:443` (nginx `proxy_set_header Host
    $host:$server_port`, or an `X-Forwarded-Host` carrying the port under
    `USE_X_FORWARDED_HOST`) made discovery advertise
    `https://<name>:443/mcp/sql/`, which clients that parse the URL (the MCP
    TypeScript and Python SDKs) send back as `https://<name>/mcp/sql/`.
  - `/mcp/sql/` hands DOT's audience check the request URL built the same way
    discovery builds `resource`, so a token bound to the advertised value
    always passes, with or without `SECURE_PROXY_SSL_HEADER`, whatever the
    spelling of the forwarded host. The check is not disabled: a token bound
    to a URL that is not a prefix of the endpoint's still gets a 401 (tokens
    issued before upgrading expire within their 6 h). DOT's default
    validator is a URL-prefix match, so one bound to a prefix — the origin,
    `https://<host>/mcp` — passes; the package no longer issues those.
  - On the consent POST the form's `resource` and a
    `resource` in the URL's query string must agree; a blank form field
    beside a query `resource` reached the grant as a plain string and 500'd.

  **Behaviour change**: a client sending a `resource` that is not the
  advertised one is now refused with `invalid_target` naming the expected
  value. The bearer is verified through `audience.CanonicalUriOAuthLibCore`
  on the package's `MCPServer` (0.1.0b6) and the configured
  `OAUTH2_VALIDATOR_CLASS`; a custom `OAUTH2_BACKEND_CLASS` does not apply to
  `/mcp/sql/` or `/o/token/`, which pin DOT's form-body `OAuthLibCore` (with DOT's `JSONOAuthLibCore` configured, a JSON token
  request's `resource` was never seen by the check and reached the token; a
  JSON body is now not read, as RFC 6749 §4.1.3 has it, and is refused).
  Discovery's URLs change spelling only where the forwarded host was not
  canonical. `docs/oauth.md` → "The `resource` parameter (RFC 8707)". Also
  affects 0.1.0b5 on DOT 3.4.
- **A declared https callback on a loopback host was classified and audited
  as `cloud`.** Kind derives from the scheme, so an https callback whose host
  was really the user's own machine (`https://localhost:8443/cb`) took the
  `mcp-sql-cloud.*` namespace, skipped the loopback hardening, and wrote
  `client_kind="cloud"` on every audit row while the browser following the
  redirect delivered the code to the end user's machine. An https declared
  callback's host must now be a **fully-qualified ASCII DNS name** (letters,
  digits, hyphens and dots; an internationalised domain in its punycode
  `xn--` form), is never an **IP literal** of any kind — loopback or not, IPv6
  or IPv4, including the resolver's shorthand forms (`127.1`, `0x7f.1`, `0`) —
  is never **single-label** (`localhost4`, `ip6-localhost`, a machine's own
  hostname: such names resolve only through `/etc/hosts` or a search domain),
  and never sits under a special-use suffix that only resolves locally
  (`.localhost`, mDNS `.local` — which includes the machine's own
  `<hostname>.local` — `.home.arpa`, `.internal`, and the `localdomain*`
  pseudo-TLDs of `localhost.localdomain` / `localhost4.localdomain4`). It is
  an allow-shape rather than a loopback detector because the detector kept
  missing spellings: percent-encoded and fullwidth hosts, `0.0.0.0`,
  `*.localhost`, and — on Python 3.12.3, whose `ipaddress` does not call them
  loopback — IPv4-mapped IPv6 addresses; a list of distro loopback aliases
  missed Fedora's `localhost4` the same way, hence the single-label rule. All
  of these now fail at boot; an https callback declared on an IP literal, a
  single-label or a non-ASCII host must be re-declared as a fully-qualified
  DNS name. Not
  covered: a public DNS name that resolves to loopback, which no syntactic
  check can see. A NUL or lone surrogate in a declared host now fails boot
  with `ImproperlyConfigured` naming the URI instead of escaping as a bare
  `ValueError` / `UnicodeEncodeError`.
- **`approval_prompt=auto` could skip the consent page.** DOT's
  `AuthorizationView.get()` reads `approval_prompt` from the query string
  (falling back to `REQUEST_APPROVAL_PROMPT`), and on `auto` it issues a code
  on a plain GET — no page, no POST — whenever the user already holds an
  unexpired token for the same Application. `skip_authorization=False` did not
  prevent it. A declared client is one Application shared by every account at
  its provider, so a staff user who had connected Claude.ai had their browser
  sent straight to the shared callback with a code bound to the attacker's
  PKCE challenge and carrying the attacker's `state`, just by opening a
  crafted link. Reproduced against DOT 3.4.1 (302
  to the callback with the code). `MCPAuthorizationView` now pins
  `approval_prompt` to `force` for every request, so consent is an explicit
  POST every time. The pin covers every Application the package creates,
  the curated `mcp-sql` row included (it requires consent since migration
  `0016`, see Breaking). **This predates the multi-client work** — DCR clients (and
  0.1.0b5's opt-in cloud clients) had the same skip — but declared clients
  shipping ON makes it reachable by default. Whether a given provider then
  completes a callback it receives in another user's browser is outside this
  server and was not tested.
- **Logout now also revokes pending authorization codes.** The `user_logged_out`
  receiver deleted the user's MCP access tokens but not their DOT `Grant`
  rows, so a code issued just before logout — a consent approved a moment
  ago, or a phished approval the user logs out to undo — could still be
  exchanged at `/o/token/` afterwards for a fresh token nothing had deleted
  (reproduced end to end: consent, logout, exchange → 200 with a new access
  token). Logout now deletes the user's pending MCP codes and their MCP
  access tokens (with 0.1.0b6's revocation, their refresh tokens too, in one
  transaction), through one shared Application predicate so the deletes can
  never disagree (the existing name test: exactly `APPLICATION_NAME`, or
  starting with `APPLICATION_NAME_PREFIX`); rows of other Applications are
  untouched, and the logout audit row counts both. Not reached: a code or
  refresh exchange already in progress at that instant. Predates the
  multi-client work.
- **A declared redirect URI with an empty userinfo passed boot validation.**
  The check refused a non-empty user or password, but `https://@claude.ai/cb`
  (or `http://@localhost:8787/cb`) parses with username `""` and slipped
  through. Any `@` in the authority of a declared redirect URI — cloud and
  local alike — is now a boot error; an `@` in the path or query is
  unaffected.
- **The consent screen corrupted IPv6 destinations.** `urlparse().hostname`
  strips the brackets, so `http://[::1]:8787/cb` rendered as
  `http://::1:8787` — and `::1` is an accepted DCR loopback host. An explicit
  `:0` was also dropped by a falsy-port test. Both fixed; this is the one line
  on that page the user is asked to verify.
- **A registered redirect URI could smuggle a second, off-machine one.**
  `Application.redirect_uris` stores the list as `" ".join(...)` and DOT
  matches with `redirect_uris.split()`, so a single submitted string carrying
  whitespace became **two** registered URIs. `urlparse` reports the loopback
  hostname for `"http://127.0.0.1:8765/cb http://evil.example/steal"`, so the
  loopback check passed, the string was stored verbatim, and DOT then
  exact-matched `http://evil.example/steal` as a valid redirect for that
  client — delivering the authorization code off the victim's machine, which
  is the one thing loopback-only registration exists to prevent. PKCE offers
  no protection: the attacker registered the client and holds the verifier.
  The remaining barrier was the consent screen, which this release happens to
  have taught to name the destination. Both the anonymous DCR path and
  operator-declared redirects now refuse embedded whitespace, using the same
  `.split()` operation DOT performs so the two cannot drift; at `/o/register`
  such a URI refuses the whole registration, even beside a clean one.
  **This predates the multi-client work** — the predicate and the join are
  identical on 0.1.0b5 — and is fixed here because this release restates the
  guarantee it broke.
- **`/o/register` capped the redirect_uri count but not each URI's length.**
  `Application.redirect_uris` is an unbounded `TextField`, so ten 6 KB URIs
  still persisted ~60 KB from one anonymous request inside the 64 KiB body
  cap — the thing the count cap's own comment claimed to prevent. Each stored
  URI is now bounded at 1024 characters, applied *inside* the loopback filter
  so an over-long callback the server discards anyway cannot fail the whole
  registration (Cursor presents a hosted callback beside its loopback one, and
  that URL can carry a long `state`).
- **`validate_redirect_uri` rejected the exact callbacks of any client that
  also had a prefix rule.** It returned the prefix verdict instead of falling
  through to DOT's stock exact matching. Unreachable in 0.1.0b5 (one rule per
  entry); reachable the moment a client carries both.
- **Over-long `redirect_uris` silently discarded audit rows.** Both writers
  passed the Application's registered list straight into a 1024-char column; an
  overflow raised `DataError`, which the best-effort audit wrappers swallow —
  losing the row entirely. It is now truncated at the single point where the
  client identity is built.
- `MCPQueryLog.client_redirect` was documented as the redirect the token "was
  issued against … the auth url cannot lie". It is the Application's
  **registered** `redirect_uris` — DOT does not persist which redirect a given
  authorization used. Read it as "one of these". The docstring now says so.
- **A GET to `/mcp/sql/` could pin a worker thread forever.** The view
  accepted GET and DELETE and forwarded them into the FastMCP bridge. With a
  valid token and `Accept: application/json, text/event-stream`, the SDK
  answered a GET with an SSE stream that never ends (with `Last-Event-ID`, with
  no response at all), and the bridge waited for it: a sync worker until
  gunicorn's timeout, a gthread or ASGI thread for good, with a default-DB
  connection held throughout (idle in transaction under
  `ATOMIC_REQUESTS=True`), surviving token revocation. `/mcp/sql/` now answers
  every method but POST with `405` and `Allow: POST`, before authentication.
  No client loses anything: the transport is stateless, the Python MCP SDK
  only opens a GET stream or sends DELETE once the server issued an
  `Mcp-Session-Id` (a stateless server never does), and the TypeScript SDK's
  post-initialize GET, previously answered `406`, now gets the `405` it treats
  as "no stream offered". Also affects 0.1.0b5. As a backstop the bridge
  now cancels an exchange after 30 seconds and completes any response the app
  leaves unfinished (`504` if the deadline cut it off before it started, `500`
  if the app ended without one), so no future path that leaves a response
  unfinished can pin a thread either. An exception the app raises itself,
  including its own `TimeoutError`, stays an ordinary `500`.
- **Under `ATOMIC_REQUESTS=True` no auth rejection was ever recorded.** DRF
  rolls back the request transaction on every `APIException`, including the
  `AuthenticationFailed` each per-request gate raises right after writing its
  `MCPAuthRejectionLog` row, so with the documented default-alias setting the
  table stayed empty (the 401 was still sent). `/mcp/sql/` now opts out of
  `ATOMIC_REQUESTS` on every database alias (not just `default`, so audit
  tables routed to another alias are covered too): the rows commit as
  written, and the view no longer holds a transaction open for the whole
  exchange. Also affects 0.1.0b5.
- **A non-IP `REMOTE_ADDR` broke every audit write.** `client_ip` went
  straight into a `GenericIPAddressField`. Behind a front end that copies an
  unvalidated `X-Forwarded-For` entry into `REMOTE_ADDR` (uvicorn with
  `--forwarded-allow-ips='*'`, for one), a client sending `X-Forwarded-For:
  not-an-ip` made psycopg 3 raise `ValueError` at the insert: queries still
  ran but left no `MCPQueryLog` row (nor a tripwire count), and gate denials
  became 500s with no rejection row. On psycopg2 the rows were dropped
  silently. Every audit writer now stores a normalised address, or `NULL`
  when the value is not one. Also affects 0.1.0b5.
- **A per-request gate that raised was an unaudited 500.** An exception from
  the consumer's `MFA_CHECKER`, from profile resolution (a DB blip) or from
  the `SESSION_MODEL` lookup escaped the auth class: fail-closed, but with no
  `MCPAuthRejectionLog` row. It is now a denial with the new reason
  `gate_error` (a choice folded into the unreleased migration `0015`; no new
  migration), answered `503` with `Retry-After: 30` and no `WWW-Authenticate`
  challenge, with the traceback logged. Deliberately not a 401: MCP clients
  answer a 401 with a full OAuth re-authorization, which during an
  MFA-backend or session-store outage fails the same way and can leave a
  hosted connector needing a manual reconnect. Likewise a cache fault in the once-per-hour "ambiguous profile"
  WARNING dedup no longer turns that denial into a 500; the WARNING is
  emitted instead. Also affects 0.1.0b5.
- **Tokens with no user or no Application reached gates that assumed them.**
  DOT allows both to be `NULL` (a `client_credentials` token from another
  OAuth use case on the same install, a shell-minted row). A userless token on
  an MCP Application was an unaudited 500; on any other Application a 401
  whose audit insert failed on the non-null `user` column. A userless token is
  now refused with a 401 and a WARNING naming the token and its client (the
  rejection table is keyed to a user); a token with no Application is an
  audited `bad_application` denial. Also affects 0.1.0b5.
- **Documented: a logout from an expired session revokes nothing.** Django
  sends `user_logged_out` with `user=None` when the web session has already
  ended (and django-allauth sends nothing), so the user's MCP tokens and
  pending codes survive and no audit row is written. `docs/oauth.md` →
  "What logout cannot revoke" says so and gives the remedy (log in, then log
  out). Unchanged behaviour; also affects 0.1.0b5.
- **A consent POST's error redirect trusted the form's hidden `redirect_uri`.**
  DOT raises Cancel's `access_denied` and an invalid `resource`'s
  `invalid_target` before oauthlib validates that field, then
  redirected the user's browser, `state` included, to whatever it held.
  Exploiting it takes a tampered, CSRF-bearing consent POST (script on the
  same origin). The view now
  re-validates the target against the client before every error redirect and
  shows the error page when it does not belong to the client. A consent POST
  naming a `client_id` that does not exist was a 500; it shows the same error
  page, also when the client is deleted while the POST is in flight (on
  every path, Authorize or Cancel, with or without a `resource`). A
  `client_id` containing a NUL byte (on the GET, DOT handed it to Postgres,
  which raised `DataError`, a 500) is refused before any lookup by 0.1.0b6's
  control-character screen, which shows an error page too. All inherited
  from DOT; also affects 0.1.0b5.
- **`/o/register` could answer an anonymous 500.** Each of these escaped the
  view as a 500 on every retry, before the per-IP `register` counter:
  - a NUL in a loopback redirect URI (`http://127.0.0.1:8761/cb\u0000`): the
    loopback filter refused whitespace but not NUL, and Postgres rejected the
    INSERT (`DataError` under psycopg 3);
  - a lone surrogate there (`\ud800`, a legal JSON escape): the driver
    cannot encode it as UTF-8 (`UnicodeEncodeError`);
  - a redirect URI with a malformed bracketed host (`http://[::1`,
    `http://[127.0.0.1]/cb`) or a host invalid under NFKC normalisation (a
    fullwidth solidus): `ValueError` inside the loopback filter, even when a
    clean URI rode alongside;
  - a body that is not UTF-8, JSON nested past the recursion limit, or an
    integer longer than Python's digit limit;
  - a `grant_types` or `response_types` that is not a list (`null`, a
    number); a string there also turned the "must include
    `authorization_code`" check into a substring test.

  None of these is a 500 any more. A URI that does not parse is now never
  registered: like any other URI that is not a valid loopback callback, it
  drops out of the registered subset (a 400 if nothing else is left). That
  also covers a loopback URI with a port that is not a number in range
  (`http://127.0.0.1:99999/cb`): the filter never read the port, so such a URI
  used to be registered verbatim (a 201), unusable. The rest are RFC 7591
  400s for the whole request, even beside a clean URI: the body and type
  cases above, a `redirect_uris` member that is not a string (it used to be
  dropped silently), a `client_name` that is not a string (absent, `null` or
  empty still gets the default name; a falsy non-string such as `0` or `[]`
  used to get it silently), and the characters below.
  The character rule (documented once, at the top of the character section
  of `views/registration.py`): a requested `redirect_uris` entry
  (`invalid_redirect_uri`) must be printable and visible: no control, format,
  surrogate, private-use, unassigned or noncharacter, separator,
  default-ignorable (invisible) or blank character (e.g. U+2800), and no
  conjoining Hangul jamo. A `client_name` (`invalid_client_metadata`) must be
  assigned, visible text: no control, surrogate, private-use, unassigned or
  noncharacter, line / paragraph separator or blank character, no Hangul
  vowel or final that does not continue a syllable, and no format or
  default-ignorable (invisible) character except inside a well-formed
  sequence: a zero-width non-joiner or joiner between two visible non-ASCII
  characters (Persian and Indic spelling, emoji ZWJ sequences); VS15 / VS16
  after a base Unicode's emoji-variation-sequences.txt lists (so `↔️`, `‼️`,
  `ℹ️` and keycaps work, `★` plus VS16 does not); a Mongolian free variation
  selector after a Mongolian letter; the combining grapheme joiner before a
  combining mark; a subdivision flag (U+1F3F4, a lowercase two-letter region
  and a one-to-four letter / digit subdivision in tags, U+E007F). Visible
  format marks such as the Arabic number sign are ordinary text. Ideographic
  variation selectors and the deprecated Khmer inherent vowels are refused,
  as is the soft hyphen (invisible except at a line break). "Assigned"
  follows the running Python's Unicode version (Python 3.11 ships Unicode
  14.0). Nothing refused is stored, echoed or logged: a callback is copied
  into every audit row's `client_redirect`, and an invisible or reordering
  character there would let a registrant make it read as something else.
  Ordinary non-ASCII text is still accepted in a `client_name`; a redirect
  URI must be printable ASCII (0.1.0b6's loopback predicate), so a
  non-ASCII one drops out of the registered subset. A seeded fuzz of the endpoint
  (malformed hosts, ports, encodings, odd characters) pins that it answers
  only 201 or 400. An unparseable body is `invalid_client_metadata`, and
  `grant_types` / `response_types` must be arrays of strings. Also affects
  0.1.0b5.

## 0.1.0b7

### Added

- **Django 6.1 and Python 3.14 support.** The Django cap is widened to
  `<6.2`, and CI gains Django 6.1 × Python 3.12/3.13/3.14 and Django 6.0 ×
  Python 3.14 legs. No package code changed: the suite passes on Django 6.1.1
  (CI and locally), and `makemigrations --check` and mypy (django-stubs 6.1.2)
  are clean on 6.1.1 in local runs — CI's `typecheck` job stays on Django
  5.2. Two constraints come with 6.1, both from upstream rather than this
  package:
  - **PostgreSQL 15+.** Django 6.1 refuses to connect to PostgreSQL 14; the
    floor stays 14 on Django 4.2–6.0.
  - **DRF ≥ 3.18.** DRF ≤ 3.17 fails to import on Django 6.1, and pip will
    not stop that pairing: DRF ≤ 3.17 declares `django>=4.2` uncapped, and a
    Django-dependent DRF floor can't be expressed in this package's metadata
    without dropping Django 4.2. A fresh install resolves DRF 3.18; an app
    with an existing DRF pin must bump it together with Django.

  Not verified: Django 5.2 on Python 3.14, and PostgreSQL 17+ (CI runs 14
  and 15, plus 16 on one Django 6.0 leg). django-oauth-toolkit doesn't
  declare Django 6.1 support yet; the suite passes on 6.1 with DOT 3.4.1 (the
  floor since 0.1.0b6).

### Changed

- README "Compatibility" now gives the PostgreSQL floor per Django line, and
  its DRF ranges include the releases CI resolves today (DRF 3.18 on Django
  5.2+). It also notes that Django 4.2 is end-of-life upstream (last release
  4.2.30 on 2026-04-07; later security fixes ship only for 5.2+): the package
  still supports 4.2, but running it is a risk the consumer carries.

## 0.1.0b6

### Security

- **The SQL Postgres ran could differ from the SQL that was checked
  (critical; affects every release up to and including 0.1.0b5).** The
  executor sends sqlglot's re-serialization of the validated query, not the
  agent's text, and that re-serialization is not faithful for some inputs,
  on every supported sqlglot (30.7 and 30.21 alike). `E'\\'` (one
  backslash) came back as `e'\'`, swallowing its closing quote so that
  later literal text ran as SQL; an alias written as a dollar-quoted string
  (`AS $$x, version() AS v$$`, which Postgres itself refuses) came back
  unquoted as SQL. Either let an agent read the catalogs or any table the
  login role can read, and run further `;`-separated statements —
  including `RESET ROLE` and writes, which committed (see the next entry).
  Escape strings with any backslash also changed value (`E'a\\nb'` ran as
  a newline, matching the wrong rows).
  - The parser refuses source forms sqlglot and Postgres read differently,
    with the new rejection reason `unsafe_literal`, before every other
    check: an `E'…'` escape-string literal containing a backslash, a
    `U&'…'` / `U&"…"` Unicode escape (sqlglot 30.7 read it as `U & '…'`,
    which then ran and could match different rows), any identifier written
    as a string constant (`AS $$…$$`, `AS 'x'`, `AS E'x'`), a
    double-quoted name called as a function that sqlglot would fold onto
    its builtin (`"Count"(x)`, `"Extract"(...)`; every other quoted call,
    such as `"Lower"(x)`, now runs as written, quotes included, and quoted
    aliases and CTEs with a column list stay accepted), adjacent string constants
    (`'a' 'b'`, which sqlglot always read as `CONCAT`) and a dollar-quote
    tag Postgres rejects (`$u&$…$u&$`). `E'…'` without a backslash, standard
    strings with backslashes, `$$…$$` values and `U & 'x'` with spaces stay
    accepted; the hint shows the replacement for each (`chr(10)` for a
    newline, `||` for adjacent strings, ...).
  - The executor validates the SQL it is about to send, not only the
    agent's text: the LIMIT-wrapped query is rendered without comments,
    the rendered text goes through the full validation again (same
    whitelist, every check), and it must re-render (by sqlglot) to the
    identical string. Otherwise nothing runs and the attempt is audited
    with the new reason `roundtrip_mismatch`, naming the rendered SQL and
    the failing check. Comments are never sent (sqlglot rewrote `--`
    comments as `/* */`, and their text is not checked). The rendering must
    still end in exactly the injected LIMIT, and a construct sqlglot knows
    it cannot express in Postgres (`IGNORE NULLS` / `RESPECT NULLS`), which
    it used to drop with a warning, is refused instead.
  - The SQL is rendered as written. sqlglot's postgres dialect rewrote much
    of what it read into its own spelling, and not all of it meant the
    same to Postgres: calls to hundreds of functions (`like(a, b)` → `b
    LIKE a`, arguments swapped; `regexp_like(x, p, 'i')` dropped the flags;
    `date_part` → `EXTRACT` and `log10(x)` → `LOG(10, x)`, numeric instead
    of double precision; `to_char(d, '%Y')` "translated" the format;
    `date_add(t, i, zone)` and, on 30.7, `date_trunc(unit, t, zone)` lost
    the zone; `strpos` → `POSITION`, `now()` → `CURRENT_TIMESTAMP` and
    others gave a different column name), multi-part interval strings
    (`INTERVAL '1 day 02:03:04'` ran as `'1 DAY'`, `'3 days ago'` lost its
    sign), JSON keys (`j -> ''` dropped the key; on 30.7 a quote in a key
    was not escaped), quoted type names (`::"char"` became `CHAR`), `bit
    '011'` / `char 'abc'` (cut to one character), the PG16 numeric
    constants (`0x1F` became a bit string, `1_000` the number 1 with an
    alias), `(1, NULL) IS NOT NULL` on 30.7 (became `NOT … IS NULL`, the
    opposite for a row), and `string_agg(DISTINCT a, ',')` (became a CASE
    tuple). Each now renders as the agent wrote it (`parser.FaithfulPostgres`);
    calls Postgres itself rejects (`nvl`, `iif`, `last_day`, 1-argument
    `to_number`, `initcap(s, '-')`) now fail in Postgres instead of being
    translated into something that runs. A LIMIT that is not a plain
    integer (`LIMIT 3.5`, `LIMIT 2 + 3`, `LIMIT (SELECT …)`, `LIMIT -1`) is
    kept and capped (`LIMIT LEAST(<as written>, n)`) instead of being
    replaced by the cap; a value numeric as written (number literals,
    arithmetic on them, a cast to a numeric type, a scalar subquery
    selecting one: `(SELECT 'NaN'::float8)`) is cast to bigint first,
    which for those is exactly Postgres's LIMIT coercion (`'NaN'::float8`,
    an integer beyond bigint: Postgres's error), while anything else is
    left to Postgres's type resolution (`LIMIT '3'::text` stays an error).
    A value whose type is not evident from how it is written (a column or
    function call, a subquery selecting one) is not cast, so a NaN or
    infinite float there yields the cap where Postgres raises: a known
    residual (the cap still holds).
    `(SELECT … LIMIT 5)` no longer fails with a second LIMIT.
    `QUALIFY` (not Postgres SQL) is a syntax error and `qualify` an ordinary
    name, as in Postgres. Also rendered as written: `x IS NOT NULL IS TRUE`
    (sqlglot 30.13+ dropped the `NOT`), `IS NOT TRUE` / `IS NOT FALSE`
    inside a comparison or an IS chain (`y > 2 IS NOT TRUE` came back `y >
    NOT 2 IS TRUE`; `IS NOT UNKNOWN` there keeps its `NOT`, but renders as
    `IS NOT NULL`, like `IS UNKNOWN` as `IS NULL` — the same for a boolean
    operand; on any other type Postgres raises and the rendering runs, a
    known residual), a negated operator inside one on 30.7
    (`g NOT LIKE 'a%' IS TRUE` came back `NOT g LIKE 'a%' IS TRUE`; any `NOT`
    that is an operand now keeps its parentheses), `a ^ b` (was `POWER(a,
    b)`: another column name and sqlglot's precedence), `~ -1` / `- ~1`
    (rendered `~-1`, which Postgres reads as the operator `~-`) and, on
    30.7, a cast right after the right operand of `->`, `->>`, `#>`, `#>>`,
    `?` (`j #> '{a}'::text[]` cast the whole expression); `2 %-3`, `y=~1`,
    `-~y` (one operator to Postgres, `%-`, `=~`, `-~`), operators sqlglot
    reads but Postgres does not have (`a == b`, `<=>`, `??`, `~~~`, which
    ran as `=`, `IS NOT DISTINCT FROM`, ...) and `json_object(KEY 'a' VALUE
    1)` (no `KEY` in Postgres) are refused; a column named `key` is not that
    keyword (`json_object(key VALUE x)`, `"KEY" VALUE x` run on PG16, where
    sqlglot dropped the column as the keyword). Also as written: `INTERVAL
    '<string>' <field> [TO <field>]` (`INTERVAL '25 hours' DAY` is 0 days
    to Postgres; sqlglot dropped the field or read it as an alias) — only
    an unquoted word is a field, compared as Postgres compares keywords
    (ASCII letters only: `INTERVAL '1' "day"` is one second named `day`,
    and so is `mınute` with a dotless `ı`, which `str.upper` had made
    `MINUTE`), a seconds field keeps its precision (`SECOND(2)`, `DAY TO
    SECOND(3)`), and a field word or `TO` after a complete qualifier
    (`INTERVAL '1' DAY HOUR`, `... DAY TO`) is a parse error, as in
    Postgres (it ran with an alias); any other word after the string is an
    alias, as to Postgres (`INTERVAL '1' WEEK` is 1 second named `week`;
    sqlglot read `WEEK`, `DAYS`, `q`, `MON`, `hr`, ... as units, 7 days),
    and the string keeps its spelling (`'1 week'`, not `'1 WEEK'`) and its
    quotes (`INTERVAL '1 day'', g, ''b'` had run as three projections) —
    and `INTERVAL(3) '1.23456'` (was the sum `INTERVAL '3' + INTERVAL
    '1.23456'`); any other `INTERVAL(…)` (`INTERVAL(3.0) '1.2'`,
    `INTERVAL(-1) '1 day'`, `INTERVAL(1 + 2) '…'`, `INTERVAL(3)` alone) is
    a parse error, as in Postgres (it ran as a sum or with parts dropped).
    The string ends the interval: a `+` after it is the operator, not
    sqlglot's sum of intervals (`INTERVAL '1 day' + 2 * INTERVAL '1 day'`
    ran as `INTERVAL '1 day' + INTERVAL '2'`, dropping the rest). Every
    form of string constant is that string, everywhere a string is: `E'…'`
    without a backslash and `$$…$$` / `$tag$…$tag$` (sqlglot's own nodes
    for them were not: `INTERVAL $$1$$ week` and `INTERVAL E'1' week` ran
    as 7 days, `INTERVAL $$25 hours$$ DAY` as 25 hours, `INTERVAL(2)
    $$1.234$$` and `DATE $$2024-01-01$$` were refused, `LIMIT
    $$5000000000$$` failed as an int4). `INTERVAL` is a typed literal only
    before a string constant or `(`, as in Postgres (a `U&'…'` constant is
    refused as an unsafe literal, here as anywhere); anywhere else it is
    a name, so a column `interval` is read as the column (`interval + 1`
    ran as `INTERVAL '1'`, one second; `interval - y` and `interval[1]`
    lost the operand; `interval * 2` was refused as `SELECT *`,
    `interval / 2` was a parse error; a slice, `interval[:1]`, runs), and
    `INTERVAL 5`, `INTERVAL 5 DAY`, `INTERVAL N'1' week`, `interval day
    '1'` are parse errors, as in Postgres (they ran). Left: a bare field
    word after the column is read as its alias (`SELECT interval day` runs
    as `interval AS day`; Postgres requires `AS` there, as for any
    column). Interval type modifiers in a cast run as written
    (`'12.345'::interval(1)`, `CAST(x AS interval(3))`, `interval
    second(2)`, `interval day to second(3)`, their arrays; refused before
    as `roundtrip_mismatch` / `parse_error`); `interval(1) day` and
    `interval minute(2)` stay parse errors, as in Postgres. A word after an
    interval type in a cast that is not one of Postgres's fields (YEAR,
    MONTH, DAY, HOUR, MINUTE, SECOND) is an alias, as Postgres reads it:
    sqlglot read a unit of its own list there. The one-letter units ran as
    a field, a wrong value: `'90'::interval h` as `INTERVAL HOUR` (3 days
    18 hours, where Postgres returns 90 seconds named `h`), `y` as 90
    years, `m` as 90 minutes, `d` as 90 days (`s`: the value, under another
    column name). Other words were kept and failed in Postgres
    (`'90'::interval days` / `mins` / `mon` / `week` came back as
    `INTERVAL DAYS`, ..., a syntax error), and `'1.5'::interval(1) secs`
    was refused.
    Where Postgres then rejects the text (`CAST(x AS interval h)`, the
    word in a `WHERE`, `interval min to sec`, `interval h[]`) it is now a
    parse error (it ran). The array part of a type name is read as
    Postgres reads it: `ARRAY` after a type was dropped at the end of the
    input (`'{a,b}'::text array` ran as `text`, `'{1}'::interval day array`
    as one day — wrong values), became the alias `array` before a comma and
    was refused before an operator; `ARRAY[n]` was refused, and a bound
    after a type (`'{1,2}'::int[3]`, `int[][1]`) was rendered as a
    subscript of the cast (a Postgres syntax error) — all now run as
    written. `bit varying` ran as `bit(1)` (`'10101'::bit varying` returned
    `1`) and `bit varying(n)` was refused: both are `varbit` now. A word
    after the quoted `"interval"` (a plain type name to Postgres, which
    takes no field) was dropped (`'90'::"interval" days` lost its alias):
    it is the alias. Postgres's syntax errors in the same places, which
    ran, are parse errors: `int[] array`, `int array[]`, a bound that is
    not an unsigned integer constant, an array type in a typed literal
    (`int[] '{1}'`), a bare `array` alias, an interval field word or
    `varying` after a type (`'1'::int day`, `'90'::"interval" day`,
    `'1'::bit(3) varying`). A refused
    escape literal is the audit reason (`unsafe_literal`) also when the
    text fails to parse (`interval day E'a\b'` had become `parse_error`).
    Also as written: a subscripted
    column named
    `array` or `list` (`"array"[1]`, `t.array[1]`, `list[1]` became the
    constructor `ARRAY[1]` / `LIST(1)`),
    `json_object(...)` whenever its arguments parse as plain expressions
    (array slices, `format(...)`, columns named `value` / `key` / `on` had
    turned it into the SQL/JSON constructor), the prefix operators `@ x`
    and `@-@ x` (read as a parameter `$x`; a real parameter `$1` / `$name`
    stays one, an error in Postgres, and is never read as `@`), `a ^@ b`
    (starts with; read as `a ^ (@ b)`, which returned other values or
    errors), `!! q` (tsquery negation, refused before) and `! x` (Postgres's
    error; sqlglot ran it as `NOT x`), `overlaps(a, b, c, d)`, and
    `qualify` as a name everywhere (select alias, `GROUP BY`). `LIMIT
    '<integer>'` (also in parentheses, `LIMIT ('5000000000')`, or `$$…$$` /
    `E'…'`; surrounding ASCII whitespace only, as Postgres's input) is read
    as the bigint it is to Postgres. An array constructor subscripted without
    parentheses (`ARRAY[1, 2][1]`, a syntax error to Postgres, which
    sqlglot parenthesised; `ARRAY(SELECT …)[1]`, which it turned into
    `ARRAY[1]`) and `INTERVAL(p) '<string>' <field>` are `parse_error`.
    `OPERATOR(schema.op)` keeps its name as written: sqlglot rebuilt it
    from the texts of the tokens inside, so a quoted qualifier came back
    unquoted (`OPERATOR("MySchema".=)` ran as `OPERATOR(MySchema.=)`, the
    operator of schema `myschema` — another operator, or none) and tokens
    written apart came back together (`OPERATOR(pg_catalog.< =)`, a
    Postgres syntax error, ran as `<=`); what is not `[schema.]operator`
    there is a parse error, as in Postgres. The prefix form
    `OPERATOR(schema.op) x` (refused) runs; every operator, also one
    sqlglot cannot read bare (`~<~`, `|/`, `*=`, `?-|`, ...), can be
    written `OPERATOR(pg_catalog.op)`; `x operator` keeps its alias on
    sqlglot 30.7 (dropped); `!~ x` is the prefix operator `!~` (it ran as
    `! ~x`). A quoted type name is the name as written: sqlglot read its
    text again as SQL, so `'101'::"bit varying"` ran as `varbit` (Postgres:
    no such type) and `'{1}'::"int array"` came back as `"int
    array"[]`; `nchar varying` / `nchar varying(n)` (refused) is
    `varchar`. The guarantee is about what sqlglot reads in the
    executed text — it passed every check and re-renders to itself — not a
    proof about Postgres's lexer; forms whose reading by Postgres is known
    to differ are refused by the parser (above). A new acceptance test runs
    933 ordinary analytical queries (over data with NULLs and mixed case)
    end to end and checks each returns exactly what Postgres returns for
    the original text, on both sqlglot versions, and another renders a
    call (with plain string arguments) to every `pg_catalog` function the
    parser accepts and requires it unchanged; the functions it refuses must
    be denied ones or forms Postgres rejects too.
  - Denied functions could be reached in ways the deny list did not see
    (review round 5): Postgres's attribute notation calls `f(x)` for
    `x.f` / `(expr).f` (`('server_version'::text).current_setting`,
    `(0.1::float8).pg_sleep`, `t.pg_column_size`), a schema-qualified
    `pg_catalog.generate_series(...)` / `unnest(...)` was not recognised,
    and sqlglot read `copy(x)` inside a subquery as a column with an alias
    list. All are now refused with the deny list's reason
    (`disallowed_function` / `disallowed_construct`); `t.to_jsonb` /
    `t.row_to_json`, `t.concat`, `t.quote_literal`, `t.record_out`, ... (the
    whole row) as `select_star`. Only actual calls: `t.f` (and, with
    `BAN_SELECT_STAR` off, `(t.*).f` — under the default ban any `t.*` is
    refused as `select_star`) where the FROM item `t` has a column `f`
    stays a column, whatever it is named —
    a derived table's or CTE's output column, an alias column list, a
    whitelisted table's column (from its model: the columns of its own
    table — a multi-table-inheritance child's parent fields are not; a
    table's system columns `tableoid`, `ctid`, `xmin`, … always are, so
    `(tableoid).pg_relation_filepath` stays a call), a schema-qualified type
    name (`'0/0'::pg_catalog.pg_lsn`) — as do names of denied functions
    attribute notation cannot call (`t.version`, `t.user`, `t.has_access`).
    So does `(t).f` on the same terms for a derived table, a VALUES list or
    an aliased subquery `t` (a base-table or CTE alias `t` is still refused
    there, as `select_star`, by the older bare-row check), provided no FROM
    item in scope has, or may have, a column named `t` (a column `t` wins
    over the row and `(t).f` is then `f(t)`); a FROM item whose column names are not all
    known — a function, a `SELECT *`, an unaliased expression Postgres
    names after its type (`'x'::text` is the column `text`), a whitelisted
    table without model columns — leaves `(t).f` a call. Output names are
    the ones Postgres derives (a scalar subquery's is its own column's, a
    VALUES list's `column1`, …). Anything not provably a column counts as a
    call, including `t.f` when `t` is also a column name in scope — a
    deliberate over-refusal: Postgres reads the FROM item there. Quoted
    names compare case-sensitively, as Postgres compares them, and a quoted
    column named like a parenthesis-less built-in (`"user"`,
    `"current_user"`) is the column, not the built-in (it was refused as
    `disallowed_function`). Scope of the whole-row ban, unchanged: `t.*`
    and the attribute forms are refused anywhere, a bare row alias (`t`,
    `to_jsonb(t)`, `CAST(t AS text)`) only in a projection list — in
    `WHERE`, `JOIN … ON`, `GROUP BY`, `HAVING`, `ORDER BY` it is accepted
    (never returned; the grants bound what it reads).
  - Table names are matched as Postgres matches them (review round 9): a
    quoted name exactly, an unquoted one folded to lowercase (ASCII `A`–`Z`
    only, as Postgres folds in a UTF-8 database) — against the
    whitelist (each entry is a model's exact `db_table`) and against CTE
    names. A quoted CTE `"Shipments"` no longer stands in for the table
    `shipments` (which let an off-whitelist table through and lent the
    real table the CTE's columns), `"Auth_Permission"` is not the
    whitelisted `auth_permission`, and an unquoted reference to a
    mixed-case `db_table` is refused. A CTE name is in scope only where
    Postgres sees it: a CTE's own body sees just the CTEs before it (`WITH
    t AS (SELECT … FROM t)` reads the table `t`), and a schema-qualified
    `public.t` is the table whatever CTE `t` exists; all three had let a
    table off the profile's whitelist through the parser.
  - Any exception while parsing — the tokenizer's `TokenError` for an
    unterminated literal, the `re.error` sqlglot 30.21 raises for some
    `UESCAPE` clauses, the plain `ValueError` / `TypeError` / `IndexError`
    / `KeyError` / `decimal.InvalidOperation` its function builders raised
    on bad arguments — is now an audited `parse_error`; they escaped
    `run_query` with no `MCPQueryLog` row before. `run_query` also audits
    any unexpected exception from parsing or rendering instead of letting
    it escape.
  - `standard_conforming_strings = on` joins the per-transaction guards
    (and the role defaults in `sql/role_setup.sql`): a database- or
    login-role-level `off` would make Postgres read backslashes in standard
    strings differently from the parser.
  - **Behaviour change:** the forms above are now refused; rewrite them as
    the hint suggests. A query whose rendering no longer validates is
    refused as `roundtrip_mismatch` — in the test corpora only `IGNORE
    NULLS` / `RESPECT NULLS`, which Postgres before 19 does not have; none
    of the ordinary analytical queries. **Action:** re-run
    `sql/role_setup.sql` (or `mcp_sql_role_setup`) to pick up the new role
    default; the per-transaction guard applies without it.
- **The table whitelist ignored the schema (affects every release up to and
  including 0.1.0b5).** A whitelist entry matched a table reference by its
  bare name, so `SELECT secret FROM analytics.<whitelisted name>` read a
  same-named relation in any other schema the profile role could SELECT
  (an accidental `GRANT SELECT ON ALL TABLES IN SCHEMA analytics`, an
  archived copy) — every column of it, past the reviewed whitelist and any
  curated view. The grants drift check listed `public` only, so it never
  reported such a grant. Now:
  - an entry is a relation in a schema: `public`, or the schema a
    `db_table` written `schema"."name` (or `"schema"."name"`) names. A
    reference matches it only there — the schema and the name each
    compared as Postgres compares them (quoted exactly, unquoted folded) —
    so `analytics.t` beside a whitelisted `t` is `disallowed_table`;
    `public.t` and `t` still read it. System schemas are refused as before,
    three-part `db.pg_catalog.x` included;
  - an unqualified name is checked as the relation in `public`, and which
    relation Postgres opens for it depends on the new opt-in
    `MCP_SQL["PIN_SEARCH_PATH"]` (default `False`, see Added) — **set it
    to `True`** unless an extension the agents use lives outside `public`.
    Off, as in 0.1.0b5 and every earlier release, it resolves through the
    database's own `search_path`: a schema named after the profile role
    (`"$user"`), a schema a database-, login-role- or connection-level
    setting puts ahead of `public`, or a temporary relation (table or
    view) on the backend (searched first) shadows a whitelisted table —
    read wherever the profile role may SELECT the shadowing relation, a
    grant to `PUBLIC` included, an error otherwise. An agent's query
    cannot create one (a single SELECT in a read-only transaction), but a
    party with no right on any whitelisted table can: any role with
    `CREATE` on the database (a schema named after the profile role), or
    another session on the same backend, e.g. under transaction-mode
    pooling (a temporary relation `ON COMMIT PRESERVE ROWS`), each
    granting `SELECT` to `PUBLIC`. The agent then reads the planted rows
    under the whitelisted name (result spoofing; the text can carry
    prompt injection, still fenced as untrusted data), and the drift
    check below does not report it (it does not see grants to `PUBLIC`,
    through membership, on materialized views or temporary relations).
    A DBA's `search_path` listing another schema first does the same
    without an attacker. On, the read transaction pins `search_path` to
    `public, pg_temp` (`SET LOCAL`, one of the per-transaction guards),
    so an unqualified name is the relation in `public` whenever one of
    that name exists there (if it is missing, a temporary relation of
    that name on the backend is found instead);
  - `mcp_sql_grants` (and the `post_migrate` drift WARNING) lists the
    profile role's SELECT grants in every schema but the system ones
    (`pg_catalog`, `information_schema`, `pg_*`, temporary schemas
    included): a grant outside the whitelist in another schema is drift,
    and `--apply` revokes it, as it does in `public`. GRANT / REVOKE name
    the relation schema-qualified (`"public"."t"`), not through the app
    role's `search_path`; each name quoted as an identifier (every `"`
    doubled), since the inventory's names are chosen by whoever owns the
    relations. The inventory reads `information_schema.role_table_grants`,
    which does not list materialized views, grants to `PUBLIC`, or grants
    the profile role holds only through membership in another role: those
    stay invisible to the check (ledger F42 / F64). A whitelisted
    `db_table` whose schema or table name is longer than 63 bytes is
    refused (`GrantsReconcileError`, also logged by the `post_migrate`
    check): PostgreSQL truncates such a name, so the catalog never listed
    the declared name and every `--apply` re-granted it and revoked the
    truncated one. Shorten `Meta.db_table`. `--apply` checks every
    profile (and computes its drift) before it changes any grant, and
    runs all profiles' GRANT / REVOKE statements in one transaction: a
    profile refused for an overlong or self-referential entry, view
    drift or a missing role no longer leaves the profiles before it
    applied.
  - **With `PIN_SEARCH_PATH` on**, names in agent queries resolve in
    `pg_catalog` and `public` only. An extension installed in another
    schema (Django's `CreateExtension` installs into the first schema on
    the app's `search_path`, normally `public`) loses its unqualified
    names: call its functions qualified (`extensions.similarity(...)`) and
    its operators with `OPERATOR(schema.op)` (`name
    OPERATOR(extensions.=) 'alice'`, `s OPERATOR(extensions.%) 'cafe'`,
    prefix `OPERATOR(ext.@) x`; a quoted schema stays quoted). Written
    bare, its operators either fail or resolve to a `pg_catalog` one
    through a cast (a `citext` column compared with `=` compares as
    `text`, case-sensitively). The pin is recommended in any case and
    costs nothing when every extension the agents use lives in `public`
    (or `pg_catalog`).
    **Behaviour change (both modes):** a whitelisted table that lives in
    another schema through the login's `search_path` (and not in its
    `db_table`) is not the whitelisted relation: spell the schema in
    `db_table` (with the pin on it is not found at all; off, the parser
    accepts the unqualified name but `mcp_sql_grants` grants and checks
    the relation in `public`). **Action:** run `mcp_sql_grants`: a grant it
    now reports in another schema was readable through the parser. With
    the pin on, the `search_path` role default (`mcp_sql_role_setup
    --emit-sql`, or the commented-out line in `sql/role_setup.sql`) is
    optional: the per-transaction guard applies without it.
- **`mcp_sql_grants --apply` could run SQL named by a relation (affects
  every release up to and including 0.1.0b5).** The drift inventory read
  relation names from the catalog and interpolated them into GRANT /
  REVOKE (and the printed statements) without doubling an embedded `"`.
  Up to 0.1.0b5 any role able to create a table in `public` (every role on
  PostgreSQL 14 and older, by default), and with this release's
  every-schema inventory any role owning a schema, could name a table `x" FROM r; CREATE TABLE …; --`, grant SELECT on it to
  a profile role, and `--apply` ran the rest as the operator's role; a
  name containing `"."` made the statement invalid, rolling back every
  revoke of the run. Relations are now `(schema, name)` pairs end to end,
  and every identifier is quoted (`"` doubled; a name with a non-printing
  character as a `U&"…"` escape, so a printed statement is one line). The
  `mcp_sql_smoke` read / write probes name a schema-qualified `db_table`
  the same way (`"s"."t"` broke them).
- **The read transaction was not read-only (affects every release up to and
  including 0.1.0b5).** `SET LOCAL default_transaction_read_only = on`
  only affects transactions that start later, and the executor's had
  already started, so it stayed read-write: a SECURITY DEFINER function
  owned by a privileged role could write, and the write committed (ledger
  F01). `session.enter_readonly_session` now also sets `SET LOCAL
  transaction_read_only = on` (any write fails with SQLSTATE 25006), the
  executor always rolls its read transaction back instead of committing,
  and `session_drift` (the `mcp_sql_smoke` check) reads the live flag.
- **A password change left MCP tokens working (affects every release up to
  and including 0.1.0b5).** A changed password (the user's own change, an
  admin reset, `set_unusable_password`, including saves through a proxy
  of the user model) now revokes the user's MCP access and refresh tokens
  and pending authorization codes after the change commits, with an
  `MCPAuthRejectionLog` row (new reason `password_change`; migration
  0013) when it deleted any (no row for a user who held none, as for
  logout). Done with model signals, so it needs no session table and holds
  with `SESSION_MODEL=None`. The stored hash is read through the user
  model's base manager on the database being written, so a default manager
  that filters rows (active users only, soft delete) cannot hide the user —
  reactivating a user with a new password is a change too. Django's login-time password-hash upgrade is
  not treated as a change — only the save `check_password` (or
  `acheck_password`) makes while it runs, which the package marks by
  wrapping those two methods of `AbstractBaseUser` in `ready()`, and only
  when the hash it checked is the one stored (a legacy hash for a new
  password, assigned in memory and then checked, is a change); any other
  new hash, even one saved the same way (`set_password(...)`,
  `save(update_fields=["password"])` — SSO / LDAP sync, imports), is a
  change. Bulk `QuerySet.update(password=...)` and
  `QuerySet.bulk_update(users, ["password"])` send no signals and are not
  seen — revoke tokens explicitly there. Logout now
  deletes refresh tokens and pending authorization codes as well as access
  tokens (a code issued just before either event could otherwise still be
  exchanged for a new token). On a multi-database install the revocation
  waits for the database the change was written to (logout: the default
  database) and then commits in a transaction of its own, the audit row
  inside it: a transaction the request has open on the token or audit
  database does not undo it when it rolls back (it runs on a separate
  connection there, waiting at most 5 s for a row lock that transaction
  holds; a failure is logged, not retried, and writes no audit row — the
  access did not end). The audit row is written in a savepoint: a failure
  to write it, of any kind, is logged and does not undo the deletes —
  unless the connection itself fails there, which ends the deletes'
  transaction too: that is logged as a failed revocation (it was logged
  as "Revoked N MCP token(s)" while every token survived). No
  exception the revocation raises leaves it, its setup included (a
  consumer router failing in `db_for_write`); with no transaction open it
  runs inside `logout()` before the session is flushed, or inside the
  user's `save()`. A `post_save` sent without `using` (by hand) counts as
  the default database, as Django's `on_commit` does. The three deletes run on the
  database DOT writes its access tokens to, whatever a router says per
  model. The cohort-grant alert reads the user on the database the
  membership change was written to.
- **A `REMOTE_ADDR` that is not one IP address broke the audit writes
  (affects every release up to and including 0.1.0b5).** On psycopg 3,
  Django adapts the audit tables' `client_ip` (`GenericIPAddressField`)
  with `ipaddress.ip_address`, which raises `ValueError` — not a database
  error, so nothing caught it — for a forwarded list (`10.0.0.1,
  10.0.0.2`, from a real-IP middleware that copies `X-Forwarded-For`
  whole), a hostname or `unknown` (on psycopg2 PostgreSQL refuses the
  value: a `DataError`, caught, and the audit row was lost). A bearer
  token the gate refused after resolving it (inactive user, no MFA, no
  permission, ...: the refusals that write an `MCPAuthRejectionLog` row;
  an unknown token writes none and got its 401) then answered 500
  instead of 401, a tool call failed, and logout raised from inside
  `logout()`, before the session was flushed (the user stayed logged in).
  Every audit row now records such a value as no address (`client_ip`
  NULL; `models.audit_client_ip`), whoever writes it: also a consumer
  calling `executor.run_query` / `executor.audit_tool_call` with
  `REMOTE_ADDR` as is. A scoped IPv6 address (`fe80::1%eth0`, which
  Django stored without its zone) is recorded as NULL too. The per-IP
  throttle still keys on the raw value.
- **The app booted with any DOT validator.** The package's OAuth server is
  built with the install's `OAUTH2_PROVIDER["OAUTH2_VALIDATOR_CLASS"]`, and
  the client pinning, the `mcp:sql`-only scope, mandatory PKCE and the
  redirect rules live in `MCPOAuth2Validator`; with DOT's stock validator
  and `PKCE_REQUIRED=False` a code was issued and exchanged without PKCE.
  `ready()` now raises `ImproperlyConfigured` unless the setting is
  `MCPOAuth2Validator` or a subclass. **Action required** only for an
  install that did not follow the documented settings.
- **`/o/register` could register an off-machine redirect URI (affects
  0.1.0b5 and earlier).** The anonymous dynamic-client-registration endpoint
  validated each submitted redirect URI with `urlparse` (scheme `http`, no
  userinfo, loopback host) but stored the list as one space-joined string,
  which django-oauth-toolkit splits again on any `str.split()` whitespace
  when matching. A single submitted URI with embedded whitespace (space, tab,
  CR/LF, or a less obvious separator such as NBSP or U+2028) therefore passed
  the loopback check yet was stored as two or more redirects, one of which
  could name any host. An attacker could mint such a client without
  credentials; turning it into a stolen token still required a logged-in
  user who passes the issuance gate (staff + MFA + MCP profile) to approve
  the attacker's authorization link on the consent screen, after which the
  code went to the attacker's host and was exchangeable with the attacker's
  own PKCE verifier.
  - Registration now refuses any URI that `str.split()` would break apart
    (deliberately DOT's own operation), any non-printable or non-ASCII
    character, any URI whose authority or port does not parse, and an empty
    userinfo (`@` with nothing before it, which the old non-empty-userinfo
    check let through) — each a normal 400 `invalid_redirect_uri` with no
    `Application` row created.
    Previously a malformed authority (e.g. an unterminated IPv6 literal), a
    NUL or a lone surrogate raised an uncaught 500, and a non-numeric or
    out-of-range port was stored, leaving a client that could never complete
    a flow (and, for some such URIs, an uncaught 500 at `/o/authorize/`).
  - Other malformed registration input that raised an uncaught 500 is now a
    400 `invalid_client_metadata` with no row: `grant_types` /
    `response_types` that are not JSON arrays of strings (null or a number
    raised; a plain string was substring-matched and accepted), and a body
    that is not valid UTF-8 or is pathologically nested. A client asking
    for `["authorization_code", "refresh_token"]` is still registered.
  - Rows already registered by an affected release are not deleted.
    `MCPOAuth2Validator` now re-applies the same loopback check at
    `/o/authorize/` to the requested redirect, and to the stored default
    used when a request omits one, of every client that is not a declared
    cloud client. A smuggled entry is therefore refused after upgrading (the
    row's loopback entries keep working). A stored `localhost` URI with an
    unparseable port no longer makes `/o/authorize/` raise a 500: requests
    against that row are refused. For a stored `127.0.0.1` / `[::1]` URI with
    such a port, DOT never reads the stored port (it port-wildcards loopback
    IPs), so a request for a valid port on the same path is still authorized
    — the destination stays on the loopback. `docs/oauth.md` has a shell
    snippet that lists such rows for review and deletion.
  - Behaviour change for the canonical `mcp-sql` row as well: a
    non-loopback redirect, requested or stored, is now refused for it too,
    even if an operator edited its `redirect_uris` (the documented posture
    was already loopback-only).
- **`/o/token/` and `/o/authorize/` served every grant of DOT's default
  oauthlib server, not just the advertised one (affects every release up to
  and including 0.1.0b5).** The package's OAuth views ran on DOT's
  `OAUTH2_SERVER_CLASS`, by default oauthlib's all-grants `Server`, although
  the discovery document advertises `authorization_code` / `code` only. So,
  anonymously: a `grant_type=password` request answered `unauthorized_client`
  for a correct password and `invalid_grant` for a wrong one (a password
  oracle against any active account of the consumer's user model, whatever
  its MCP access); `grant_type=openid`, a device-code request without
  `device_code`, and a NUL in `code` or `client_id` raised uncaught 500s;
  and the implicit and client-credentials grants ran behind the package's
  URLs, held back only by per-Application checks.
  The package's three OAuth views and `MCPOAuth2Authentication` now run on
  the package's own oauthlib server, `oauth_server.MCPServer`, whatever
  `OAUTH2_SERVER_CLASS` says, and parse requests with DOT's form-body
  `OAuthLibCore`, whatever `OAUTH2_BACKEND_CLASS` says: the `code` response
  type and the `authorization_code` grant only (plus the opt-in refresh
  grant, see "Added"), `S256`-only PKCE and the bearer token from the
  `Authorization` header only.
  - `/o/token/` answers a refresh grant with a constant 400 `invalid_grant`
    (see the next entry) and anything else but exactly one
    `grant_type=authorization_code` (password, client credentials, device
    code, `openid`, unknown, missing or repeated) with 400
    `unsupported_grant_type`, before DOT's own token handling or the server
    runs (DOT routes the device-code grant to its own handler before any
    server); then a control character in any other token-request parameter
    gets 400 `invalid_request`. At `/o/authorize/`, a `response_type`
    without `code` in it is redirected back as `unsupported_response_type`,
    and `none` or a value containing `code` but not exactly `code` (`code
    token`, ...) as `unauthorized_client`.
  - `/o/authorize/` screens its parameters (query string and consent POST)
    before DOT could store them on a `Grant`: a control character anywhere,
    a `code_challenge` outside RFC 7636 §4.2's shape (43-128 characters of
    `[A-Za-z0-9-._~]`) or a `nonce` over 255 characters raised an uncaught
    500 (DataError) for a gate-passing user and now gets the error page (400
    `invalid_request`, no redirect, nothing stored).
  - The consent page no longer 500s when DOT re-renders it for an invalid
    consent POST (the template resolved `application.name`, which that
    render does not supply).
  - A `client_id` carrying a control character is never looked up
    (`MCPOAuth2Validator`): it previously raised a 500 from HTTP Basic
    credentials at `/o/token/` and `/o/revoke_token/`, from the body at
    `/o/revoke_token/`, and at `/o/authorize/` (anonymous `prompt=none`
    included); now `invalid_client` / the error page.
  - `MCPOAuth2Validator` is the install's `OAUTH2_VALIDATOR_CLASS`, so for a
    consumer that also mounts DOT's stock views it keeps install-wide
    backstops there: password grants are refused with `invalid_grant` (the
    password is never checked), with refresh off no refresh token is stored
    or returned and refresh grants are refused with `invalid_grant`, PKCE
    stays required and a non-`S256` code cannot be exchanged. Those stock
    views are not otherwise narrowed.
  - **Behaviour change:** none for a client using the advertised flow. A
    client that relied on any other grant, response type or PKCE method was
    already outside the documented surface and is now refused.
- **Refresh tokens renewed access indefinitely (affects 0.1.0b5 and
  earlier).** The docs said refresh tokens were disabled by
  `REFRESH_TOKEN_EXPIRE_SECONDS=0`, but django-oauth-toolkit reads `0` as
  "no age limit": `/o/token/` issued a `refresh_token` alongside every
  access token and honoured it on `grant_type=refresh_token` (verified on
  DOT 3.2.0 and 3.4.1). A client could therefore keep renewing its access
  token without the user ever re-consenting.
  By default (refresh tokens are now opt-in, see "Added") `MCPServer`'s
  authorization-code grant generates no refresh token and
  `MCPOAuth2Validator.save_bearer_token` drops one a stock DOT token view
  would mint: no `refresh_token` field, no `RefreshToken` row. `/o/token/`
  answers every `grant_type=refresh_token` request with a constant 400
  `invalid_grant` and no token lookup — the error that makes an MCP client
  (the MCP TypeScript SDK among them) drop its refresh token and
  re-authorize — so a refresh token stored by an earlier release is refused
  and its client recovers on its own. Existing `RefreshToken` rows are left
  in place and are inert.
  - **Behaviour change:** a client that relied on refresh now re-authorizes
    every `ACCESS_TOKEN_EXPIRE_SECONDS` (6 h in the documented settings),
    with the consent screen for DCR and cloud clients — the interval the
    docs always described.
- **PKCE was not S256-only, and could be switched off (affects 0.1.0b5 and
  earlier).** The validator's S256-only check
  (`validate_code_challenge_method`) is not a hook oauthlib or DOT ever
  calls, so `/o/authorize/` accepted `code_challenge_method=plain`, and an
  omitted method (which oauthlib treats as `plain`), although the discovery
  document advertises `S256` only. With `plain` the challenge in the
  authorization URL is the verifier itself, so anyone who observes that
  request can redeem an intercepted code. A consumer's
  `PKCE_REQUIRED=False` also turned PKCE off altogether.
  `MCPServer`'s authorization-code grant knows the `S256` method only, and
  `MCPOAuth2Validator.is_pkce_required` now returns `True` regardless of
  `PKCE_REQUIRED`: a missing challenge, `plain` or an omitted method is
  refused with `invalid_request` — redirected, like any non-fatal authorize
  error, to the already-validated redirect URI — on the authorize GET and on
  the consent POST. `MCPOAuth2Validator.get_code_challenge_method` refuses
  to exchange a stored non-S256 grant (`invalid_grant`), on any server. The
  dead override is removed.
  - **Behaviour change:** a client that sends `plain`, or no
    `code_challenge_method`, is now refused at `/o/authorize/`.
- **`/mcp/sql/` accepted a bearer token in the URL query string (affects
  every release up to and including 0.1.0b5).** oauthlib, and so DOT, falls
  back to an `access_token` request parameter when there is no
  `Authorization` header, so `/mcp/sql/?access_token=<token>` authenticated
  like the header (verified on DOT 3.2.0, 3.4.0 and 3.4.1), and a form-body
  token passed authentication too — although the RFC 9728 metadata
  advertised `bearer_methods_supported: ["header"]`. A token in a URL ends up
  in proxy and access logs and in `Referer` headers. RFC 6750 §2.3 and §5.3
  advise against sending bearer tokens in URLs, OAuth 2.1 (the draft the MCP
  specification builds on) drops the query-parameter method entirely, and
  the MCP authorization specification requires clients to use the
  `Authorization` header and says access tokens MUST NOT be included in the
  URI query string.
  `MCPOAuth2Authentication` now verifies tokens on `MCPServer`, whose bearer
  handler reads the `Authorization` header only. An `access_token` query or
  form-body parameter on `/mcp/sql/` (with or without the trailing slash) is
  not a credential: a request carrying its token only there gets the
  ordinary 401 challenge — the same for a valid and a bogus token — and the
  parameter is never looked up; nothing is written to `MCPAuthRejectionLog`
  and the bad-token throttle is not counted. Beside an `Authorization`
  header the parameter is ignored and the header's token decides. (DOT's
  opt-in `COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT=True` makes DOT
  refuse any request with an `access_token` query parameter outright, also
  with 401; see `docs/oauth.md`.)
  - **Behaviour change:** a client sending its token anywhere but the
    `Authorization` header is now unauthenticated.
- **The "prefix" cloud-client redirect matcher accepted near-miss callbacks
  (affects 0.1.0b5, which introduced cloud clients).** `_redirect_under_prefix`
  checked the scheme, host, port and path exactly but ignored query strings,
  fragments and `;params`, and refused only a non-empty userinfo. Past
  oauthlib's own URI check, an extra query string (or a bare `?`), `;params`
  (raw or percent-encoded), or an empty `:@` userinfo on the provider's host
  reached the consent page end to end, so an authorization code could be
  delivered to the provider's callback with attacker-chosen parameters (the
  RFC 9700 §4.1 concern); the host itself was always checked exactly. The
  matcher now refuses any `@` in the authority, any query or fragment (even a
  bare `?` / `#`, tested on the raw string) and any `;params`, raw or
  percent-encoded (it uses `urlsplit`, which keeps them in the path, and
  checks the decoded path) — the same userinfo / query / fragment /
  `;params` refusals DOT 3.4.1 applies to "exact" clients (the port check
  keeps its deliberate `:443` normalisation).
- **Raised the `django-oauth-toolkit` floor to `>=3.4.1` (was `>=3.2`)**,
  for two upstream fixes that sit below any of this package's checks:
  - Releases before 3.4.0 redirect an unauthenticated `prompt=none`
    authorization request to whatever `redirect_uri` it names, with an
    `error=login_required` but never a code, before any validation (DOT
    #1719). Now that request is validated first, like any other: an
    unregistered `redirect_uri` gets an error page instead of a redirect,
    while a registered one (a loopback URI, or a declared cloud client's
    `https` callback) still receives the specified `error=login_required`,
    never a code. A new test pins this for the canonical client.
  - Releases before 3.4.1 match redirect URIs loosely. Against a
    registered `https://claude.ai/api/mcp/auth_callback`, DOT 3.4.0's
    matcher accepts the same host with userinfo, extra query parameters, a
    fragment or `;params` added. oauthlib's own absolute-URI check stops
    fragments and any userinfo longer than one character first (its userinfo
    rule matches a single character), but a one-character userinfo, the
    extra-query and the `;params` forms reached the consent page end to end
    (verified on 3.4.0), so an authorization code could be delivered to the
    registered host with attacker-chosen parameters. 3.4.1 matches exactly,
    per RFC 9700 §2.1. This is the matcher behind declared "exact" cloud
    clients; a new test pins these forms being refused at `/o/authorize/`
    for one.
  - **Action required** for a consumer pinning django-oauth-toolkit below
    3.4.1 (e.g. `==3.2.0`): bump it. 3.4.1 still supports Django 4.2 and
    requires `oauthlib>=3.3.0` (unchanged from 3.2.0). Django 4.2 remains
    supported; CI's minimum-versions job now pins
    `django-oauth-toolkit==3.4.1`.

### Added

- **Opt-in refresh tokens**: `MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]`
  (default `0` = off, today's behaviour). A positive value issues a refresh
  token with every access token, rotates it on every refresh (whatever DOT's
  `ROTATE_REFRESH_TOKEN` says), and refuses the chain once that many seconds
  have passed since the user's consent — measured from the
  authorization-code exchange across every rotation (new
  `MCPRefreshTokenFamily` model, migration 0013, which also revokes
  `mcp_readonly_role`'s SELECT on it like the package's other tables), not
  DOT's sliding `REFRESH_TOKEN_EXPIRE_SECONDS`. The value must be an int
  from 0 to ten years (`ImproperlyConfigured` otherwise). Refresh tokens
  without a recorded consent (from earlier releases) stay refused; family
  rows whose refresh tokens are gone are inert and safe to prune. The discovery document and DCR
  responses list `refresh_token` while it is on. Logout and password change
  revoke refresh tokens. Runbook: `docs/oauth.md` "Refresh tokens
  (opt-in)".
- **Opt-in `search_path` pin**: `MCP_SQL["PIN_SEARCH_PATH"]` (default
  `False`; `True` / `False` only, anything else refuses to boot). On, every
  read transaction sets `SET LOCAL search_path = 'public', 'pg_temp'` and
  `mcp_sql_smoke`'s session check expects it, so an unqualified table name
  is the whitelisted relation in `public`: a `"$user"` schema or a schema
  ahead of `public` on the database's `search_path` can no longer shadow
  it, nor can a temporary relation (table or view) while the whitelisted
  relation exists in `public` (`pg_temp` is listed last, so a missing one
  falls through to a temporary relation of that name). **Turning it on
  is recommended:** off, `search_path` is the database's own, as in
  0.1.0b5, and any role with `CREATE` on the database or another session
  on the same backend (e.g. under transaction-mode pooling) can plant a
  same-named relation, readable through a grant to `PUBLIC`, whose rows
  the agent reads under the whitelisted name — without any right on the
  whitelisted tables, and unseen by `mcp_sql_grants` (Security, above).
  The cost of turning it on: an extension installed outside `public` must be
  qualified (`ext.f(...)`, `OPERATOR(ext.op)`; a bare `=` on its `citext`
  column silently compares as `text`). `mcp_sql_role_setup --emit-sql`
  prints the matching role default only when the pin is on;
  `sql/role_setup.sql` carries it commented out. The schema-scoped
  whitelist and grants inventory (Security, above) apply in both modes.
  Details: `docs/architecture.md` "`search_path` is pinned only on
  request".
- CI runs the whole suite a second time under a minimal security posture
  (allow-all `MFA_CHECKER`, no `SESSION_MODEL`; `MCP_SQL_TEST_POSTURE=minimal`,
  `make test-minimal`), and `docs/oauth.md` has a table of what MFA, the
  session gate and the refresh cap each add and what holds without them.

### Changed

- An unknown `MCP_SQL` key at any level now refuses to boot
  (`ImproperlyConfigured: Invalid MCP_SQL settings`, raised from pydantic's
  `ValidationError` — shown as its cause in the traceback — which names
  the key's path with "Extra inputs are not permitted": `PIN_SEARCHPATH`,
  `LIMITS.EXTRA`, `PROFILES.default.EXTRA`, `CLOUD_CLIENTS.0.EXTRA`)
  instead of being ignored, so a misspelt opt-in
  (`PIN_SEARCHPATH`) cannot leave its feature silently off. Remove or
  correct any stray key, top-level or nested.
- `oauthlib` is now a declared dependency (`>=3.3.0,<5`): the package builds
  its OAuth server from oauthlib's classes and relies on two internals,
  pinned by a test. CI's minimum-versions job pins `oauthlib==3.3.0`.
- `docs/oauth.md`, README and the example settings recommend DOT's
  `COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT = True`: DOT then refuses a
  request carrying an `access_token` query parameter itself and stops
  logging a deprecation warning for each one (the package never accepted
  such a token).
- `docs/architecture.md`: a curated view that filters rows must be created
  `WITH (security_barrier)` — otherwise a cast in the agent's `WHERE` runs
  on the hidden rows first and the error text quotes their values (ledger
  F71). Column-only views are unaffected. Documentation only for now.
- Raised the `mcp` floor to `>=1.28.1` (was `>=1.27`), so the declared range
  no longer admits releases carrying CVE-2026-52869, CVE-2026-52870 (both
  fixed in 1.27.2) or CVE-2026-59950 (fixed in 1.28.1). The package was not
  exposed to these: it serves Streamable HTTP with `stateless_http=True`,
  never enables the SDK's experimental tasks, and has no WebSocket
  transport. CI's minimum-versions job now pins `mcp==1.28.1`.

## 0.1.0b5 - 2026-07-01

### Added

- **Opt-in cloud MCP clients** (`MCP_SQL["CLOUD_CLIENTS"]`, empty default =
  feature off / loopback-only). Admits operator-blessed cloud-brokered clients
  (Claude.ai web/desktop/mobile/Cowork, ChatGPT/Codex-cloud) that authenticate
  against a provider-hosted HTTPS callback and vault the token in the provider's
  cloud — **without** relaxing the loopback-only `/o/register` (DCR) endpoint.
  - Each entry yields a derived, stable `client_id` (`mcp-sql-cloud.<name>`,
    logged at `migrate`) to paste into the provider's connector, secret left
    blank. Recognition is settings-gated and fail-closed: removing an entry
    denies its outstanding tokens at the next `/o/authorize/` and `/mcp/sql/`
    request.
  - Provisioning is a `post_migrate` receiver (`provision_mcp_cloud_clients`,
    mirroring `provision_mcp_profiles`): one curated `Application` per entry
    (public/PKCE, no secret, `skip_authorization=False`), create/update only,
    never deleting.
  - Redirect matching is per-entry `"exact"` (Claude — DOT stock matching) or
    `"prefix"` (ChatGPT's per-instance callback — one hardened override:
    https-only, exact host, port-normalised, no userinfo, no traversal,
    segment-anchored prefix).
  - New `client_redirect` audit column on `MCPQueryLog` /
    `MCPAuthRejectionLog` (migration `0012`) records the **issued** redirect URI
    (ground truth), so cloud-client activity stays attributable in the logs.
  - No refresh tokens: the 6-hour re-consent applies to cloud clients too.
  - Operator runbook: `docs/oauth.md` "Cloud clients".

### Changed

- A non-empty `MCP_SQL["CLOUD_CLIENTS"]` now requires `"https"` in
  `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]`; the app raises
  `ImproperlyConfigured` at startup otherwise (cloud callbacks are https). DOT's
  default already allows https, so this only affects a consumer who narrowed the
  list (e.g. to `["http"]` for loopback DCR). Empty `CLOUD_CLIENTS` (the
  default) is unaffected.
- The MCP transport endpoint is now routed at **both** `/mcp/sql/` (canonical —
  what `reverse()` and the RFC 9728 `resource` advertise) and a slash-less
  `/mcp/sql` alias, so a cloud connector that normalises the trailing slash off
  and POSTs to `/mcp/sql` is served rather than triggering an `APPEND_SLASH`
  500.

## 0.1.0b4 - 2026-06-15

Documentation-only release (no code changes).

### Fixed

- README "Installation" `MCP_SQL` block used the pre-`PROFILES` flat
  `ALLOWED_MODELS` shape, which fails startup validation
  (`ImproperlyConfigured`). It now uses the required `PROFILES` shape. A new
  test (`tests/test_docs_config.py`) runs every paste-ready `MCP_SQL` block in
  the docs through `validate_mcp_sql_settings`, so the install snippet can't
  drift from the validator again.
- The OAuth and role-setup runbooks described the pre-`PROFILES`
  authorization model (`has_perm("mcp_sql.use_mcp_session")`, flat
  `ALLOWED_MODELS`); they now match the code's `resolve_profile` /
  per-profile-whitelist behaviour, with corrected auth-error strings and
  logout token-scope. MFA (`MFA_CHECKER`) and the runtime session-existence
  gate (`SESSION_MODEL`) are now documented as opt-in rather than default.

### Added

- README "How it compares" section positioning the package against hosted
  natural-language→SQL services and reference/platform MCP servers, plus a
  one-line summary callout near the top.

### Changed

- Removed internal build-phase ("Phase N") references from the shipped docs;
  added a "Roadmap / known gaps" section instead. Reorganized the
  architecture doc (curated-view pattern ahead of the OAuth surface; the
  "Watch out" invariants grouped under per-layer subheadings with a mini-TOC).

## 0.1.0b3 - 2026-06-12

### Added

- `Documentation` entry in `[project.urls]` (pointing at the repo's `docs/`
  tree). Django Packages reads a package's documentation link from PyPI
  `project_urls` (keys `Documentation`/`Docs`/`docs`/`documentation`); without
  this key the grid listing showed no documentation despite the docs shipping
  in the wheel.

## 0.1.0b2 - unreleased

### Added

- The MCP tools now advertise output schemas: `run_query` and
  `describe_table` declare `TypedDict` return types (`FencedQueryResult`,
  `TableDescription | ToolError`), which the MCP SDK turns into each tool's
  output schema — so a connecting client sees the result shape, including
  that `run_query`'s `rows` is a fenced JSON string rather than a row matrix.
- A stricter type-check gate: the high-signal subset of mypy strict
  (`warn_unused_ignores`, `warn_redundant_casts`, `warn_return_any`,
  `disallow_any_generics`, `disallow_incomplete_defs`) is now enabled, with
  the package annotated to satisfy it (full `disallow_untyped_defs` stays
  off). A consumer's type checker now reads more precise inline types — e.g.
  `QueryResult.rows` is `list[list[Cell]]`, the cursor surface is a
  `SQLCursor` protocol, and audit kwargs are a `TypedDict` — instead of
  `object`/`Any`.

### Changed

- New runtime dependency `typing-extensions>=4.12` (already present
  transitively via pydantic): the MCP tool-output `TypedDict`s must be the
  `typing_extensions` variant for pydantic to build their schemas on
  Python < 3.12.

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
