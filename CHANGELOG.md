# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

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
    (sqlglot 30.13+ dropped the `NOT`), `IS NOT TRUE` / `IS NOT FALSE` /
    `IS NOT UNKNOWN` inside a comparison or an IS chain (`y > 2 IS NOT TRUE`
    came back `y > NOT 2 IS TRUE`), a negated operator inside one on 30.7
    (`g NOT LIKE 'a%' IS TRUE` came back `NOT g LIKE 'a%' IS TRUE`; any `NOT`
    that is an operand now keeps its parentheses), `a ^ b` (was `POWER(a,
    b)`: another column name and sqlglot's precedence), `~ -1` / `- ~1`
    (rendered `~-1`, which Postgres reads as the operator `~-`) and, on
    30.7, a cast right after the right operand of `->`, `->>`, `#>`, `#>>`,
    `?` (`j #> '{a}'::text[]` cast the whole expression); `2 %-3`, `y=~1`,
    `-~y` (one operator to Postgres, `%-`, `=~`, `-~`), operators sqlglot
    reads but Postgres does not have (`a == b`, `<=>`, `??`, `~~~`, which
    ran as `=`, `IS NOT DISTINCT FROM`, ...) and `json_object(KEY 'a' VALUE
    1)` (no `KEY` in Postgres) are refused. Also as written: `INTERVAL
    '<string>' <field> [TO <field>]` (`INTERVAL '25 hours' DAY` is 0 days
    to Postgres; sqlglot dropped the field or read it as an alias) — only
    an unquoted word is a field (`INTERVAL '25 hours' "DAY"` is 25 hours
    and `INTERVAL '1' "day"` one second, each with an alias), and a seconds field keeps its precision (`SECOND(2)`,
    `DAY TO SECOND(3)`) — and `INTERVAL(3) '1.23456'` (was the sum
    `INTERVAL '3' + INTERVAL '1.23456'`); a subscripted column named
    `array` or `list` (`"array"[1]`, `t.array[1]`, `list[1]` became the
    constructor `ARRAY[1]` / `LIST(1)`),
    `json_object(...)` whenever its arguments parse as plain expressions
    (array slices, `format(...)`, columns named `value` / `key` / `on` had
    turned it into the SQL/JSON constructor), the prefix operators `@ x`
    and `@-@ x` (read as a parameter `$x`; a real parameter `$1` / `$name`
    stays one, an error in Postgres, and is never read as `@`), `overlaps(a, b, c, d)`, and
    `qualify` as a name everywhere (select alias, `GROUP BY`). `LIMIT
    '<integer>'` (also in parentheses, `LIMIT ('5000000000')`) is read as
    the bigint it is to Postgres. An array constructor subscripted without
    parentheses (`ARRAY[1, 2][1]`, a syntax error to Postgres, which
    sqlglot parenthesised; `ARRAY(SELECT …)[1]`, which it turned into
    `ARRAY[1]`) and `INTERVAL(p) '<string>' <field>` are `parse_error`. The guarantee is about what sqlglot reads in the
    executed text — it passed every check and re-renders to itself — not a
    proof about Postgres's lexer; forms whose reading by Postgres is known
    to differ are refused by the parser (above). A new acceptance test runs
    873 ordinary analytical queries (over data with NULLs and mixed case)
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
    whole row) as `select_star`. Only actual calls: `t.f` / `(t.*).f` where
    the FROM item `t` has a column `f` stays a column, whatever it is
    named —
    a derived table's or CTE's output column, an alias column list, a
    whitelisted table's column (from its model), a schema-qualified type
    name (`'0/0'::pg_catalog.pg_lsn`) — as do names of denied functions
    attribute notation cannot call (`t.version`, `t.user`, `t.has_access`).
    So does `(t).f` on the same terms, provided no FROM item in scope has,
    or may have, a column named `t` (a column `t` wins over the row and
    `(t).f` is then `f(t)`); a FROM item whose column names are not all
    known — a function, a `SELECT *`, an unaliased expression Postgres
    names after its type (`'x'::text` is the column `text`), a whitelisted
    table without model columns — leaves `(t).f` a call. Output names are
    the ones Postgres derives (a scalar subquery's is its own column's, a
    VALUES list's `column1`, …). Anything not provably a column counts as a
    call, including `t.f` when `t` is also a column name in scope — a
    deliberate over-refusal: Postgres reads the FROM item there. Quoted
    names compare case-sensitively, as Postgres compares them.
  - Table names are matched as Postgres matches them (review round 9): a
    quoted name exactly, an unquoted one folded to lowercase — against the
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
  0013). Done with model signals, so it needs no session table and holds
  with `SESSION_MODEL=None`. Django's login-time password-hash upgrade is
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
  exchanged for a new token).
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
- CI runs the whole suite a second time under a minimal security posture
  (allow-all `MFA_CHECKER`, no `SESSION_MODEL`; `MCP_SQL_TEST_POSTURE=minimal`,
  `make test-minimal`), and `docs/oauth.md` has a table of what MFA, the
  session gate and the refresh cap each add and what holds without them.

### Changed

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
