"""Custom DOT validator pinned to mcp-sql Applications + the single
`mcp:sql` scope, plus install-wide backstops for the narrow OAuth surface
`oauth_server.MCPServer` enforces on the package's own endpoints (PKCE,
refresh and password grants). See `docs/architecture.md` "OAuth surface" for
the full picture (consent-screen asymmetry, audience-binding policy, prefix
semantics)."""

import hashlib
import re
from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import unquote
from urllib.parse import urlsplit

from django.db import router
from django.db import transaction
from django.utils import timezone
from mcp_sql.clients import ClientKind
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.conf import refresh_tokens_enabled
from mcp_sql.consts import is_mcp_application
from mcp_sql.models import MCPRefreshTokenFamily
from mcp_sql.views.registration import _is_loopback_redirect
from oauth2_provider.models import Application
from oauth2_provider.models import RefreshToken
from oauth2_provider.models import redirect_to_uri_allowed
from oauth2_provider.oauth2_validators import OAuth2Validator

if TYPE_CHECKING:
    from django.http import QueryDict
    from mcp_sql.clients import DeclaredClient

# C0 controls, DEL and C1 controls. No identifier or parameter of this OAuth
# surface carries one, and a NUL reaching a Postgres text lookup or insert
# raises an uncaught 500 (DataError).
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _record_refresh_family(raw_refresh_token: str) -> None:
    """Record the consent time of the chain `raw_refresh_token` starts, and
    prune family records past the cap (their tokens are refused anyway)."""
    checksum = hashlib.sha256(raw_refresh_token.encode("utf-8")).hexdigest()
    family = (
        RefreshToken.objects.filter(token_checksum=checksum)
        .values_list("token_family", flat=True)
        .first()
    )
    if family is None:
        return  # nothing stored (DOT's grace-period reuse path): nothing new
    now = timezone.now()
    MCPRefreshTokenFamily.objects.get_or_create(
        token_family=family, defaults={"consented_at": now}
    )
    MCPRefreshTokenFamily.objects.filter(
        consented_at__lte=now
        - timedelta(seconds=mcp_sql_settings.REFRESH_TOKEN_MAX_AGE_SECONDS)
    ).delete()


def has_control_character(*params: "QueryDict") -> bool:
    """True if any key or value of the given query dicts carries a control
    character (`_CONTROL_CHARS`). The OAuth views run it over the query
    string and the form body before DOT or the server sees them."""
    return any(
        _CONTROL_CHARS.search(text)
        for qd in params
        for key, values in qd.lists()
        for text in (key, *values)
    )


def _redirect_under_prefix(redirect_uri: str, prefix: str) -> bool:
    """True iff `redirect_uri` is a safe https URL sitting under `prefix`.

    Used only for `MATCH: "prefix"` rules (ChatGPT / Codex-cloud), whose
    callback is per-instance — `https://chatgpt.com/connector/oauth/{id}` —
    and so cannot be pre-registered as an exact URI. The match is deliberately
    strict, hardened against the classic redirect-allowlist bypasses so the
    relaxation stays bounded to the provider's own origin:

    - scheme MUST be https (no downgrade),
    - no `@` anywhere in the authority — no userinfo component at all, not even
      an empty one (`https://chatgpt.com@evil.com/...`, `https://@chatgpt.com/`),
    - no query, fragment or `;params` — not even a bare trailing `?` / `#`, which
      parse to an empty `.query` / `.fragment`, so the raw string is tested.
      The callback is a plain path, and DOT 3.4.1+ matches an exact URI the same
      way (RFC 9700 §2.1). `urlsplit` (not `urlparse`) keeps `;params` in the
      path, where they are refused — also percent-encoded (`%3b`), since the
      check runs on the decoded path,
    - host must EXACTLY equal the prefix host (not `endswith`, so
      `chatgpt.com.evil.com` is rejected), and port must match with only a
      MISSING port normalised to the https default (an explicit `:443` equals
      an implicit one; an explicit `:0` stays distinct),
    - no `..` path segment — literal or single/multi-level percent-encoded
      (`%2e%2e`, `%252e%252e`, ...) — above the prefix path,
    - path must start with the prefix path, anchored at a `/` segment boundary
      so a sibling like `.../oauthEVIL` cannot slip past a bare prefix (also
      enforced at config time by `validation._validate_redirect_uri`).

    Mirrors the care in `views/registration.py::_is_loopback_redirect`.
    """
    try:
        got = urlsplit(redirect_uri)
        want = urlsplit(prefix)
        got_port, want_port = got.port, want.port
    except ValueError:
        # Malformed authority (e.g. a non-numeric port) — reject, fail-closed.
        return False
    # Anchor the prefix to a segment boundary. Validation already requires a
    # trailing slash on a "prefix" REDIRECT_URI; this keeps the predicate
    # correct on its own even if handed a bare prefix.
    want_path = want.path if want.path.endswith("/") else want.path + "/"
    # Fully percent-decode the path (bounded) before the traversal check, so a
    # single- OR multi-encoded `..` (`%2e%2e`, `%252e%252e`, ...) can't slip
    # past. `unquote` is idempotent-converging; 5 layers is far more than any
    # real callback needs. Only the traversal check sees the decoded form —
    # `startswith` stays on the raw path, matched against the raw prefix.
    decoded_path = got.path
    for _ in range(5):
        step = unquote(decoded_path)
        if step == decoded_path:
            break
        decoded_path = step
    # Normalise only a MISSING port to the https default — an explicit `:0` is
    # falsy but not None, so keep it distinct rather than aliasing the default.
    got_port = 443 if got_port is None else got_port
    want_port = 443 if want_port is None else want_port
    return (
        got.scheme == "https"  # no downgrade
        and "@" not in got.netloc  # no userinfo, not even an empty one
        and "?" not in redirect_uri  # no query, not even a bare `?` ...
        and "#" not in redirect_uri  # ... nor a fragment / bare `#`
        and ";" not in decoded_path  # no `;params`, raw or percent-encoded
        and bool(got.hostname)
        and got.hostname == want.hostname  # exact host, never `endswith`
        and got_port == want_port  # exact port (:443 == implicit https)
        and ".." not in decoded_path.split("/")  # no traversal (literal/encoded)
        # ...and no backslash, which a browser's WHATWG parser treats as `/`
        # in an https URL, so `..\` would be traversal by another spelling.
        # oauthlib's absolute-URI check and Django's `iri_to_uri` (`\` ->
        # `%5C`) each already stop it upstream; refused here as well so the
        # path anchor does not depend on either.
        and "\\" not in decoded_path
        and got.path.startswith(want_path)  # under the allowlisted path
    )


def _is_declared_cloud(declared: "DeclaredClient | None") -> bool:
    """True for a settings-declared client of kind `cloud` — the only clients
    whose callbacks may leave the machine."""
    return declared is not None and declared.kind is ClientKind.CLOUD


def _declared_redirect_allowed(declared: "DeclaredClient", redirect_uri: str) -> bool:
    """A declared client's redirect, decided from SETTINGS alone.

    Prefix rules through `_redirect_under_prefix`; exact rules through DOT's
    own matcher (`redirect_to_uri_allowed`, the function behind
    `Application.redirect_uri_allowed`) run on the declared exact URIs, so an
    exact rule means exactly what DOT's matching of a stored `redirect_uris`
    means on the installed DOT version — only the list comes from
    `MCP_SQL["CLIENTS"]` instead of the provisioned row. That row is
    refreshed only by `post_migrate` (`signals.provision_mcp_clients`), so
    reading it let a callback changed or removed in settings keep working,
    and refused the new one, until the next `migrate`.

    A `ValueError` from DOT's parsing (a request port no parser takes, e.g.
    `:99999`, on a declared host) is a refusal, not a 500.
    """
    if any(_redirect_under_prefix(redirect_uri, p) for p in declared.prefixes):
        return True
    try:
        return bool(redirect_to_uri_allowed(redirect_uri, list(declared.exact_uris)))
    except ValueError:
        return False


class MCPOAuth2Validator(OAuth2Validator):
    """Validator pinned to the mcp-sql Application surface + the single scope."""

    def _load_application(self, client_id, request):
        """No client lookup for a `client_id` carrying a control character.

        DOT resolves every client through this (private) method: the
        `client_id` of `/o/authorize/` (`validate_client_id`), of a public
        client at `/o/token/` and `/o/revoke_token/`
        (`authenticate_client_id`), and the one decoded from HTTP Basic
        credentials there. A NUL in it reached the Postgres lookup and
        raised an uncaught 500 — from anonymous requests, and from a header
        the token view's parameter check cannot see. Pinned end to end by
        `test_oauth_server.py::TestControlCharacters`.
        """
        if client_id and _CONTROL_CHARS.search(client_id):
            return None
        return super()._load_application(client_id, request)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Accept the request only if `client_id` resolves to an mcp-sql Application.

        DOT's default looks up by `client_id` and binds the Application onto
        `request.client`. We let it do that, then verify the resulting
        Application is a recognised mcp-sql client via `is_mcp_application`:
        the curated `mcp-sql` row, a dynamically-registered `mcp-sql-<token>`
        row, OR a settings-declared `mcp-sql-{cloud,local}.<slug>` client,
        each only while its `client_id` equals its `name`. An Application that
        matches none of these (e.g. some unrelated OAuth client added later,
        or a row named like an MCP client under another client_id) is
        rejected here.
        """
        if not super().validate_client_id(client_id, request, *args, **kwargs):
            return False
        app = (
            getattr(request, "client", None)
            or Application.objects.filter(client_id=client_id).first()
        )
        return is_mcp_application(app)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """A declared client's redirect is decided by settings; every other
        client's by DOT against its row; and every client that is not a
        declared cloud client is held to a loopback redirect.

        For a settings-declared client (`mcp_sql_settings.clients()`), only
        `_declared_redirect_allowed` decides: its prefix rules
        (`_redirect_under_prefix`, for ChatGPT / Codex-cloud's per-instance
        callbacks) and its exact rules (DOT's matcher on the declared exact
        URIs). There is no fall-through to `super()`: the provisioned row's
        `redirect_uris` is a copy refreshed only on `migrate`, and recognition
        is already settings-gated per request — so are redirects. A callback
        changed in settings takes effect at the next request (old refused, new
        accepted), and a removed rule stops being admissible at once. The
        canonical `mcp-sql` row and every DCR client get DOT's stock matching
        against their own rows.

        EVERY client that is not a declared cloud client — the canonical
        `mcp-sql` row, every DCR client, every declared local client — must
        ALSO pass `_is_loopback_redirect` (the `/o/register` predicate) on the
        requested URI first. Only declared cloud clients may redirect
        off-machine; DOT's matching alone trusts whatever the row stores, and
        a DCR row minted by <= 0.1.0b5 can store an off-machine redirect
        smuggled through whitespace (see `_is_loopback_redirect`). This
        re-check refuses such an entry here without needing the operator to
        find and delete the row first (its loopback entries keep working, like
        any DCR client's). A declared local client's callbacks are
        `http://localhost` ones by derivation (`clients.derive_kind`), and
        prefix rules are https-only, so the check costs it nothing.

        A ValueError from DOT's matching is a refusal, not a 500: such a row
        can also store an unparseable port (`http://localhost:99999/cb`), and
        DOT parses a stored `localhost` candidate's port while matching a
        request for a different, valid one. (It port-wildcards loopback IPs,
        so it never reads the port of a stored `127.0.0.1` / `[::1]`
        candidate: a valid request on the same path matches, staying
        loopback.) The same holds for the settings path
        (`_declared_redirect_allowed`).

        The default used when a request omits `redirect_uri` never reaches
        this method — `get_default_redirect_uri` below holds it to the same
        rules.

        Why declared clients need this + the exact-vs-prefix rationale:
        `docs/oauth.md` → "Clients".
        """
        declared = mcp_sql_settings.clients().get(client_id)
        if not _is_declared_cloud(declared) and not _is_loopback_redirect(redirect_uri):
            return False
        if declared is not None:
            return _declared_redirect_allowed(declared, redirect_uri)
        try:
            return super().validate_redirect_uri(
                client_id, redirect_uri, request, *args, **kwargs
            )
        except ValueError:
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """The default redirect: from settings for a declared client, and held
        to loopback for every client that is not a declared cloud client.

        When a request omits `redirect_uri`, oauthlib resolves the default
        WITHOUT calling `validate_redirect_uri`, and a later non-fatal error
        (missing `response_type`, a bad scope, ...) is then 302'd to it.

        A declared client's default comes from settings, not the provisioned
        row (which would bring back a callback since changed or removed in
        settings): its callback only when it declares exactly one rule and
        that rule is exact — as DOT gives one only for a single stored URI; a
        prefix is not a callback. Every other client gets DOT's default from
        its row.

        A default that fails the loopback predicate for a client that is not
        a declared cloud client (e.g. a canonical row hand-edited to an
        off-machine URI) is dropped too. A dropped default makes oauthlib
        raise its fatal `MissingRedirectURIError` instead — error page, no
        redirect.
        """
        declared = mcp_sql_settings.clients().get(client_id)
        if declared is None:
            uri = super().get_default_redirect_uri(client_id, request, *args, **kwargs)
        elif len(declared.redirects) == 1 and declared.exact_uris:
            uri = declared.exact_uris[0]
        else:
            uri = None
        if uri and not _is_declared_cloud(declared) and not _is_loopback_redirect(uri):
            return None
        return uri

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Reject any token request that asks for scopes other than `mcp:sql`."""
        if not scopes:
            return False
        # Reject anything with extra or different scopes. `scopes` is a list of strings.
        if set(scopes) != {mcp_sql_settings.SCOPE}:
            return False
        return super().validate_scopes(
            client_id, scopes, client, request, *args, **kwargs
        )

    # Install-wide backstops. The package's own endpoints run on
    # `oauth_server.MCPServer`, which has no password or other extra grant
    # (and a refresh grant only when `REFRESH_TOKEN_MAX_AGE_SECONDS` enables
    # it) and accepts only S256 PKCE. This class is the install's
    # `OAUTH2_VALIDATOR_CLASS`, so the hooks below also hold the line for a
    # consumer who mounts DOT's stock views on DOT's stock server.

    def is_pkce_required(self, client_id, request):
        """PKCE on every authorization, whatever `PKCE_REQUIRED` says.

        Every MCP client is public, so PKCE is the only thing binding a code
        to the client that asked for it. oauthlib compares the result with
        `is True`, so it must be the literal.
        """
        return True

    def get_code_challenge_method(self, code, request):
        """Only an `S256` grant can be exchanged.

        `None` for any other stored method — `plain`, explicit or defaulted
        from an omitted method, as every release up to and including 0.1.0b5
        stored on request — makes oauthlib refuse the exchange with
        `invalid_grant` ("Challenge method not found"), on any server.
        """
        method = super().get_code_challenge_method(code, request)
        return method if method == "S256" else None

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Store a refresh token only when refresh is enabled, and record
        when its chain was consented to.

        Refresh off (the default): drop `refresh_token` before DOT stores the
        token. `MCPServer`'s grant does not generate one then, but DOT's
        stock server does, and oauthlib serialises this same dict as the
        `/o/token/` body after `save_token` (which calls this method) — so
        the field is gone from a stock token view's response too, and DOT
        creates no `RefreshToken` row.

        Refresh on: a refresh token minted by the authorization-code exchange
        starts a new chain (DOT gives it a fresh `token_family`); its consent
        time is recorded in `MCPRefreshTokenFamily`, in the same transaction,
        for `validate_refresh_token`'s hard cap. Rotations inherit the family
        and record nothing. Expired family rows are pruned here too.
        """
        if not refresh_tokens_enabled():
            token.pop("refresh_token", None)
            return super().save_bearer_token(token, request, *args, **kwargs)
        with transaction.atomic(using=router.db_for_write(RefreshToken)):
            result = super().save_bearer_token(token, request, *args, **kwargs)
            raw = token.get("refresh_token")
            if raw and request.grant_type == "authorization_code":
                _record_refresh_family(raw)
        return result

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Refresh only when enabled, and only within the chain's hard cap.

        Refresh off: refuse every refresh grant (`invalid_grant`), including
        refresh tokens minted by releases up to and including 0.1.0b5 (DOT
        reads the documented `REFRESH_TOKEN_EXPIRE_SECONDS=0` as "no age
        limit").

        Refresh on: DOT's own checks (token known, not revoked, issued to
        this client) and then the package's cap: the token's family must
        have a consent record (`MCPRefreshTokenFamily`) younger than
        `REFRESH_TOKEN_MAX_AGE_SECONDS`. Measured from the consent, across
        rotations — unlike DOT's `REFRESH_TOKEN_EXPIRE_SECONDS`, a window
        that slides with each new access token. A family with no record (a
        token from 0.1.0b5 or earlier, or any written outside
        `save_bearer_token`) is refused.
        """
        if not refresh_tokens_enabled():
            return False
        if not super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        ):
            return False
        family = getattr(request.refresh_token_instance, "token_family", None)
        cutoff = timezone.now() - timedelta(
            seconds=mcp_sql_settings.REFRESH_TOKEN_MAX_AGE_SECONDS
        )
        return (
            family is not None
            and MCPRefreshTokenFamily.objects.filter(
                token_family=family, consented_at__gt=cutoff
            ).exists()
        )

    def rotate_refresh_token(self, request):
        """Always rotate: each refresh revokes the presented refresh token
        and issues a new one (in the same family), whatever DOT's
        `ROTATE_REFRESH_TOKEN` says."""
        return True

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Refuse every password grant (`invalid_grant`) without calling
        `authenticate()`, so a correct and a wrong password get the same
        answer — no password oracle, even on DOT's stock token view."""
        return False
