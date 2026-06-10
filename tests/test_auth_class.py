"""Tests for `MCPOAuth2Authentication`.

The centerpiece is `TestOAuthTokenIsolationFromGlobalDRF`, which pins the
design's central acceptance criterion: a token issued for `/mcp/sql/` must
not authenticate against any other DRF endpoint. The structural reason is
that `MCPOAuth2Authentication` is mounted on the MCP view only — never in
`REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`. The default global
classes (`SessionAuthentication`, `TokenAuthentication`) ignore the
`Bearer` prefix.
"""

from datetime import timedelta
from http import HTTPStatus

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from mcp_sql.auth import MCP_REQUEST_BODY_MAX_BYTES
from mcp_sql.auth import MCPOAuth2Authentication
from mcp_sql.auth import PayloadTooLarge
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP


def _bearer_request(token: str):
    """Build a DRF request carrying `Authorization: Bearer <token>`."""
    return APIRequestFactory().post("/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {token}")


@pytest.mark.django_db
class TestMCPOAuth2AuthenticationHappy:
    def test_valid_token_returns_user_and_token(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        request = _bearer_request(mcp_access_token.token)
        user, token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk
        assert token.pk == mcp_access_token.pk

    def test_success_binds_resolved_profile_on_request(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """The view's tool closures read `request.mcp_profile`; the auth
        class is the only writer. Pins that the success path actually sets
        it — the view's guarded read raises if it ever goes missing."""
        request = _bearer_request(mcp_access_token.token)
        MCPOAuth2Authentication().authenticate(request)
        assert request.mcp_profile.name == "default"
        assert request.mcp_profile.role == "mcp_readonly_role"


@pytest.mark.django_db
class TestMCPOAuth2AuthenticationRejections:
    """Each defense-in-depth gate raises `AuthenticationFailed`."""

    def test_no_authorization_header_returns_none(self, mcp_mfa_on):
        request = APIRequestFactory().post("/mcp/sql/")
        assert MCPOAuth2Authentication().authenticate(request) is None

    def test_expired_token_rejected(self, mcp_access_token, mcp_mfa_on):
        # DOT's parent `OAuth2Authentication.authenticate` returns `None` for
        # invalid/expired tokens (no `AuthenticationFailed` raised). Our
        # subclass forwards that `None`, and DRF then treats the request as
        # anonymous — which the project's default `IsAuthenticated`
        # permission class rejects downstream with 401/403.
        mcp_access_token.expires = timezone.now() - timedelta(hours=1)
        mcp_access_token.save()
        request = _bearer_request(mcp_access_token.token)
        assert MCPOAuth2Authentication().authenticate(request) is None

    def test_wrong_scope_rejected(self, mcp_access_token, mcp_mfa_on):
        mcp_access_token.scope = "read"
        mcp_access_token.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="mcp:sql scope"):
            MCPOAuth2Authentication().authenticate(request)

    def test_empty_scope_rejected(self, mcp_access_token, mcp_mfa_on):
        mcp_access_token.scope = ""
        mcp_access_token.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="mcp:sql scope"):
            MCPOAuth2Authentication().authenticate(request)

    def test_inactive_user_rejected(self, mcp_user, mcp_access_token, mcp_mfa_on):
        mcp_user.is_active = False
        mcp_user.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="active staff"):
            MCPOAuth2Authentication().authenticate(request)

    def test_non_staff_user_rejected(self, mcp_user, mcp_access_token, mcp_mfa_on):
        mcp_user.is_staff = False
        mcp_user.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="active staff"):
            MCPOAuth2Authentication().authenticate(request)

    def test_no_mfa_rejected(self, mcp_access_token, mcp_mfa_off):
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="verified TOTP"):
            MCPOAuth2Authentication().authenticate(request)

    def test_perm_revoked_after_issuance_rejected(
        self, mcp_user, use_mcp_perm, mcp_access_token, mcp_mfa_on
    ):
        mcp_user.user_permissions.remove(use_mcp_perm)
        # No profile assignment remains → resolve_profile returns NO_PERM.
        mcp_access_token.refresh_from_db()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="no MCP profile permission"):
            MCPOAuth2Authentication().authenticate(request)

    def test_ambiguous_profile_rejected(
        self, two_profiles, mcp_user, mcp_access_token, mcp_mfa_on
    ):
        """A user assigned to >1 MCP profile is denied AMBIGUOUS_PROFILE and an
        audit row is written (TIC-585 fail-closed: never guess a tier)."""
        from django.contrib.auth.models import Group

        from mcp_sql.models import MCPAuthRejectionLog

        # mcp_user already holds `use_mcp_session` (the default tier) directly;
        # add the second-profile group → two distinct profile codenames.
        mcp_user.groups.add(Group.objects.get(name=SECOND_PROFILE_GROUP))
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="more than one MCP profile"):
            MCPOAuth2Authentication().authenticate(request)
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.AMBIGUOUS_PROFILE

    def test_no_active_session_rejected(self, mcp_user, mcp_access_token, mcp_mfa_on):
        """A token with all issuance-time properties intact but no live
        Django session for the user must still be rejected. This pins the
        runtime half of the design's "Option D session-trust" gate: the
        16h `SESSION_COOKIE_AGE` is the implicit upper bound on token
        usefulness, replacing what would otherwise be a parallel TTL."""
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="active web session"):
            MCPOAuth2Authentication().authenticate(request)

    def test_session_gate_opt_out_authenticates_without_session_row(
        self, mcp_user, mcp_access_token, mcp_mfa_on, settings
    ):
        """When `MCP_SQL["SESSION_MODEL"]` is unset, the session-existence
        gate is skipped entirely. The token + perm + MFA gates still fire,
        but a user without a live session row authenticates successfully.

        Pins the in-package default contract: stock-Django consumers (no
        `user` FK on `sessions.Session`) can use the package without
        crashing on `FieldError`, accepting the slightly weaker security
        posture (token outlives logout up to its 6h TTL).
        """
        settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}
        request = _bearer_request(mcp_access_token.token)
        user, token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk
        assert token.pk == mcp_access_token.pk

    def test_expired_session_rejected(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """A session row that exists but is past its `expire_date` must
        not satisfy the gate. Matches the `clearsessions` cron semantics
        — the row sticks around briefly after expiry until the sweep
        deletes it, but we must already treat it as gone."""
        mcp_active_session.expire_date = timezone.now() - timedelta(seconds=1)
        mcp_active_session.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed, match="active web session"):
            MCPOAuth2Authentication().authenticate(request)

    def test_token_from_different_application_rejected(self, mcp_user, mcp_mfa_on):
        """A `mcp:sql`-scoped token under any non-`mcp-sql` Application must
        be rejected. The validator pins issuance to `mcp-sql`, but the
        auth class re-verifies on every request because the validator does
        not run on `AccessToken.objects.create()` calls (admin / shell)."""
        import secrets
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        rogue_app = Application.objects.create(
            name="rogue",
            client_id="rogue",
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1",
        )
        rogue_token = AccessToken.objects.create(
            user=mcp_user,
            token="rogue_" + secrets.token_urlsafe(16),
            application=rogue_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )
        request = _bearer_request(rogue_token.token)
        with pytest.raises(AuthenticationFailed, match="mcp-sql Application"):
            MCPOAuth2Authentication().authenticate(request)


@pytest.mark.django_db
class TestAuthRejectionAuditLog:
    """Every `MCPOAuth2Authentication` rejection writes one MCPAuthRejectionLog
    row with the right reason / user / token / application_name / error
    / client_ip. Separate audit table from MCPQueryLog (which captures
    query attempts) so Phase 4 alerts can detect revoked-credential
    probing distinct from query-volume."""

    def test_bad_scope_writes_audit_row(
        self, mcp_user, mcp_access_token, mcp_app, mcp_mfa_on
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        mcp_access_token.scope = "read"
        mcp_access_token.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.BAD_SCOPE
        assert log.user_id == mcp_user.pk
        assert log.token_pk == str(mcp_access_token.pk)
        assert log.application_name == mcp_app.name
        assert "mcp:sql scope" in log.error

    def test_inactive_user_writes_audit_row(
        self, mcp_user, mcp_access_token, mcp_mfa_on
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        mcp_user.is_active = False
        mcp_user.save()
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.INACTIVE_OR_NON_STAFF
        assert log.user_id == mcp_user.pk

    def test_no_mfa_writes_audit_row(self, mcp_user, mcp_access_token, mcp_mfa_off):
        from mcp_sql.models import MCPAuthRejectionLog

        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.NO_MFA
        assert log.user_id == mcp_user.pk

    def test_perm_revoked_writes_audit_row(
        self, mcp_user, use_mcp_perm, mcp_access_token, mcp_mfa_on
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        mcp_user.user_permissions.remove(use_mcp_perm)
        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.NO_PERM
        assert log.user_id == mcp_user.pk

    def test_no_session_writes_audit_row(self, mcp_user, mcp_access_token, mcp_mfa_on):
        from mcp_sql.models import MCPAuthRejectionLog

        request = _bearer_request(mcp_access_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.NO_SESSION
        assert log.user_id == mcp_user.pk

    def test_bad_application_writes_audit_row_with_application_name(
        self, mcp_user, mcp_mfa_on
    ):
        import secrets
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        from mcp_sql.models import MCPAuthRejectionLog

        rogue_app = Application.objects.create(
            name="rogue",
            client_id="rogue",
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1",
        )
        rogue_token = AccessToken.objects.create(
            user=mcp_user,
            token="rogue_" + secrets.token_urlsafe(16),
            application=rogue_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )
        request = _bearer_request(rogue_token.token)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.BAD_APPLICATION
        assert log.user_id == mcp_user.pk
        assert log.application_name == "rogue"
        assert log.token_pk == str(rogue_token.pk)

    @pytest.mark.usefixtures("_isolated_mcp_cache")
    def test_bad_token_writes_no_audit_row(self, mcp_mfa_on):
        """A bearer header that fails DOT validation (random / revoked /
        expired-and-deleted token) does NOT write to MCPAuthRejectionLog.

        Anonymous probing is a high-volume noise floor (the
        `/mcp/sql/` URL is guessable); auditing every probe to the
        default DB would write-amplify and bloat the audit table. The
        signal lives in Redis counters (`throttle.record_attempt`)
        instead. This table is reserved for **resolved-user** denials.
        See `TestAnonymousProbeCounter` and `TestBadTokenIpBlock` for
        the Redis-side coverage.
        """
        import secrets

        from mcp_sql.models import MCPAuthRejectionLog

        request = _bearer_request("nonexistent_" + secrets.token_urlsafe(16))
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert MCPAuthRejectionLog.objects.count() == 0

    def test_audit_write_failure_does_not_mask_auth_failure(
        self, mcp_user, mcp_access_token, mcp_mfa_on, monkeypatch, caplog
    ):
        """If the audit-write itself errors with a `DatabaseError` (DB
        unreachable, schema not yet applied on a fresh deploy), the
        AuthenticationFailed still raises with the original error message
        and the failure is logged at ERROR (Sentry-visible). Non-DB
        exceptions (a future field-rename bug, etc.) are deliberately NOT
        caught — they would surface as 500s rather than being swallowed.
        """
        import logging

        from django.db import OperationalError

        from mcp_sql.models import MCPAuthRejectionLog

        def boom(*args, **kwargs):
            msg = "simulated default-DB outage"
            raise OperationalError(msg)

        monkeypatch.setattr("mcp_sql.models.MCPAuthRejectionLog.objects.create", boom)
        # Trigger a known rejection (no active session).
        request = _bearer_request(mcp_access_token.token)
        with (
            caplog.at_level(logging.ERROR, logger="mcp_sql.auth"),
            pytest.raises(AuthenticationFailed, match="active web session"),
        ):
            MCPOAuth2Authentication().authenticate(request)

        # Audit-table absence is part of the contract: failed write means
        # zero rows, not a partially-formed one (the monkeypatch raises
        # before create() commits).
        assert MCPAuthRejectionLog.objects.count() == 0
        # The failure logs at ERROR so Sentry's `event_level=ERROR`
        # integration captures it. `feedback_aggregate_alert_logs` does
        # not apply here — this is a per-occurrence operational signal
        # (DB outage), not the aggregate "rejection volume" Phase 4 will
        # add. Sentry's auto-fingerprinting collapses these into one Issue.
        assert any(
            "Failed to write MCPAuthRejectionLog" in record.message
            for record in caplog.records
            if record.levelname == "ERROR"
        )

    def test_no_authorization_header_writes_no_audit_row(self, mcp_mfa_on):
        """Anonymous traffic (no Authorization header at all) must NOT
        pollute the audit log — only actual rejection attempts should
        leave a trace."""
        from mcp_sql.models import MCPAuthRejectionLog

        request = APIRequestFactory().post("/mcp/sql/")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert MCPAuthRejectionLog.objects.count() == 0


def _bearer_request_from_ip(token: str, ip: str):
    """Build a DRF request carrying `Authorization: Bearer <token>` + REMOTE_ADDR.

    The auth class's silent-block path reads `request.META["REMOTE_ADDR"]`
    to scope per-IP counters; tests must supply this explicitly because
    `APIRequestFactory` defaults to `127.0.0.1` for every request and would
    otherwise share state across "different IP" assertions.
    """
    return APIRequestFactory().post(
        "/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {token}", REMOTE_ADDR=ip
    )


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestAnonymousProbeCounter:
    """A bearer-bearing request that fails DOT validation increments a
    single Redis counter: the per-IP fixed-window counter that drives the
    silent block. No global cross-IP counter is kept (the botnet-probe
    alert it would have fed was dropped as low-value), and no
    `MCPAuthRejectionLog` row is written on this path — the table is
    reserved for resolved-user denials.
    """

    def test_bad_token_increments_per_ip_counter(self, mcp_mfa_on):
        from django.core.cache import cache

        request = _bearer_request_from_ip("nonexistent_token_aaa", "203.0.113.7")
        assert MCPOAuth2Authentication().authenticate(request) is None

        assert cache.get("mcp_sql:bad_token:ip:203.0.113.7") == 1

    def test_no_authorization_header_does_not_increment_counter(self, mcp_mfa_on):
        """Anonymous traffic (no `Authorization` header at all) reflects
        background hum — health checks, discovery crawlers, idle pollers
        — not probe intent. The counter tracks probe intent only."""
        from django.core.cache import cache

        request = APIRequestFactory().post("/mcp/sql/", REMOTE_ADDR="203.0.113.7")
        assert MCPOAuth2Authentication().authenticate(request) is None

        assert cache.get("mcp_sql:bad_token:ip:203.0.113.7") is None

    def test_separate_ips_have_independent_counters(self, mcp_mfa_on):
        from django.core.cache import cache

        for _ in range(5):
            MCPOAuth2Authentication().authenticate(
                _bearer_request_from_ip("nonexistent_token_ccc", "203.0.113.7")
            )
        MCPOAuth2Authentication().authenticate(
            _bearer_request_from_ip("nonexistent_token_ddd", "198.51.100.9")
        )

        assert cache.get("mcp_sql:bad_token:ip:203.0.113.7") == 5
        assert cache.get("mcp_sql:bad_token:ip:198.51.100.9") == 1

    def test_counter_failure_does_not_break_auth_flow(
        self, mcp_mfa_on, monkeypatch, caplog
    ):
        """If Redis is down, `throttle.record_attempt` swallows the error
        at WARNING (sub-Sentry) and the request still returns None — no
        500, no cascading failure into the auth path."""
        import logging

        from django.core.cache import cache

        def boom(*args, **kwargs):
            msg = "redis unreachable"
            raise ConnectionError(msg)

        monkeypatch.setattr(cache, "add", boom)

        request = _bearer_request_from_ip("nonexistent_token_eee", "203.0.113.7")
        with caplog.at_level(logging.WARNING, logger="mcp_sql.throttle"):
            assert MCPOAuth2Authentication().authenticate(request) is None

        assert any(
            "MCP bad_token counter increment failed" in record.message
            for record in caplog.records
            if record.levelname == "WARNING"
        )


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestBadTokenIpBlock:
    """After `BAD_TOKEN_IP_THRESHOLD` probes from one IP within the window,
    subsequent bearer-bearing requests from that IP short-circuit before
    DOT's DB SELECT. The wire response stays a generic 401 (return None
    → DRF renders 401 via `authenticate_header`) — identical to
    "bad token" or "no auth header" so a probing attacker cannot
    fingerprint the block.
    """

    def test_below_threshold_does_not_block(self, mcp_mfa_on, settings):
        """First N probes (N < threshold) all reach DOT and get
        rejected normally — counter rises but no silent-block kicks in."""
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 3}

        for i in range(2):  # 2 probes, threshold 3 — not blocked yet
            request = _bearer_request_from_ip(f"nonexistent_{i}", "203.0.113.42")
            assert MCPOAuth2Authentication().authenticate(request) is None

        assert cache.get("mcp_sql:bad_token:ip:203.0.113.42") == 2

    def test_threshold_crossing_silently_blocks_subsequent_probes(
        self, mcp_mfa_on, settings
    ):
        """Once the counter reaches the threshold, every subsequent
        bearer-bearing request returns None without further incrementing
        the counter and without invoking DOT."""
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 3}

        # Three probes — counter at threshold after the third.
        for i in range(3):
            request = _bearer_request_from_ip(f"nonexistent_{i}", "203.0.113.42")
            assert MCPOAuth2Authentication().authenticate(request) is None

        assert cache.get("mcp_sql:bad_token:ip:203.0.113.42") == 3

        # Fourth probe — silently blocked; counter does NOT advance.
        request = _bearer_request_from_ip("nonexistent_fourth", "203.0.113.42")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert cache.get("mcp_sql:bad_token:ip:203.0.113.42") == 3

    def test_blocked_ip_short_circuits_before_dot(
        self, mcp_mfa_on, settings, monkeypatch
    ):
        """When the IP is blocked the auth class returns None BEFORE
        calling super().authenticate() — saves the DB SELECT under
        sustained probing."""
        from django.core.cache import cache
        from oauth2_provider.contrib.rest_framework import OAuth2Authentication

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 1}

        # Seed the per-IP counter at the threshold directly (no need to
        # probe first; we're isolating the block behavior).
        cache.set("mcp_sql:bad_token:ip:203.0.113.99", 1, timeout=3600)

        # Spy on DOT's authenticate to confirm it's never invoked.
        calls = []
        original = OAuth2Authentication.authenticate

        def spy(self, request):
            calls.append(request)
            return original(self, request)

        monkeypatch.setattr(OAuth2Authentication, "authenticate", spy)

        request = _bearer_request_from_ip("anything", "203.0.113.99")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert calls == [], "DOT's authenticate must NOT be called on blocked IP"

    def test_block_does_not_apply_to_different_ip(self, mcp_mfa_on, settings):
        """One IP at threshold does not leak the block to a different IP."""
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 1}
        cache.set("mcp_sql:bad_token:ip:203.0.113.99", 5, timeout=3600)

        # Fresh IP — should NOT be blocked.
        request = _bearer_request_from_ip("nonexistent_xyz", "198.51.100.77")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert cache.get("mcp_sql:bad_token:ip:198.51.100.77") == 1

    def test_blocked_ip_does_not_increment_counter(self, mcp_mfa_on, settings):
        """Block short-circuits before `throttle.record_attempt`, so the
        per-IP counter stays frozen on subsequent spam."""
        from django.core.cache import cache

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 1}
        cache.set("mcp_sql:bad_token:ip:203.0.113.99", 10, timeout=3600)

        for _ in range(5):
            request = _bearer_request_from_ip("anything", "203.0.113.99")
            assert MCPOAuth2Authentication().authenticate(request) is None

        # Counter frozen — the per-IP key does not advance.
        assert cache.get("mcp_sql:bad_token:ip:203.0.113.99") == 10

    def test_block_check_failure_fails_open(self, mcp_mfa_on, monkeypatch):
        """If Redis is down during the block lookup, the check returns
        False (fail-open) — a Redis blip cannot accidentally lock
        everyone out. The downstream DOT validation still runs."""
        from django.core.cache import cache

        def boom(*args, **kwargs):
            msg = "redis unreachable"
            raise ConnectionError(msg)

        monkeypatch.setattr(cache, "get", boom)

        request = _bearer_request_from_ip("anything", "203.0.113.99")
        # No exception, just the normal `None` for a bad token via DOT
        # — same as the unguarded path would yield.
        assert MCPOAuth2Authentication().authenticate(request) is None


@pytest.mark.django_db
class TestOAuthTokenIsolationFromGlobalDRF:
    """A valid `mcp:sql` token must NOT unlock any other DRF API endpoint.

    Structural reason: `MCPOAuth2Authentication` is mounted on `/mcp/sql/`
    only. The global `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]` is
    `SessionAuthentication + TokenAuthentication`. `TokenAuthentication`
    reads `Authorization: Token <key>`, not `Bearer <key>`;
    `SessionAuthentication` ignores the header entirely. The OAuth bearer
    therefore yields anonymous on every default-auth endpoint.

    These tests pin the contract. If a future change adds OAuth to the
    global default classes, these tests fail loudly.
    """

    def test_oauth_token_does_not_unlock_user_list_api(
        self, client, mcp_access_token, mcp_mfa_on
    ):
        url = reverse("api:user-list")
        response = client.get(
            url, HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}"
        )
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
        assert not response.wsgi_request.user.is_authenticated

    def test_oauth_token_does_not_unlock_global_search_api(
        self, client, mcp_access_token, mcp_mfa_on
    ):
        url = reverse("global_search")
        response = client.get(
            url,
            {"term": "anything"},
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
        )
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
        assert not response.wsgi_request.user.is_authenticated

    def test_same_token_authenticates_against_mcp_endpoint_auth_class(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """Positive control: the same token that fails on `/api/...` works
        for the MCP auth class. The dichotomy makes isolation unambiguous.
        Needs `mcp_active_session` so the runtime session-trust gate in
        `MCPOAuth2Authentication.authenticate` is satisfied."""
        request = _bearer_request(mcp_access_token.token)
        user, token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk
        assert token.pk == mcp_access_token.pk


@pytest.mark.django_db
class TestAuthorizationHeaderRequired:
    """`bearer_methods_supported: ["header"]` in the RFC 9728 discovery
    document declares that the protected resource accepts bearer tokens
    only via the `Authorization` header (RFC 6750 §2.1).

    Pinning RFC 6750 §2.2 (form-body) and §2.3 (query) rejection at the
    *behavior* layer would require monkeypatching DOT to look for the
    token in body/query — DOT 3.2.0 simply doesn't have those code paths,
    so a black-box test sending the token in body/query is indistinguishable
    from sending no token at all, and provides no signal. We rely on DOT's
    documented behavior here (`oauth2_provider.contrib.rest_framework.
    OAuth2Authentication.authenticate` reads from the Authorization header
    only); these tests pin the *presence* requirement, which is what we
    actually own.
    """

    def test_missing_authorization_header_returns_401(self, client):
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"",
            content_type="application/json",
        )
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

    def test_non_bearer_authorization_scheme_returns_401(
        self, client, mcp_access_token
    ):
        # `Basic` (or `Token`, or `Digest`) → DOT's auth class doesn't
        # match → returns None → DRF's IsAuthenticated rejects with 401/403.
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Basic {mcp_access_token.token}",
        )
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

    def test_malformed_bearer_authorization_returns_401(self, client):
        # `Bearer ` with no token → DOT can't parse → None → 401/403.
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"",
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer ",
        )
        assert response.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}


@pytest.mark.django_db
class TestWWWAuthenticateAdvertisesDiscovery:
    """The 401 from `/mcp/sql/` must carry `resource_metadata` so MCP
    clients can discover the OAuth flow. Without it the handshake cannot
    start — verified manually against Claude Code (`claude mcp list`
    reports `Failed to connect` against a bare `Bearer realm="api"`).

    `authenticate_header` is the unit under test; the discovery view
    itself is tested in `test_discovery.py`. This pair pins the contract
    that the challenge content matches the registered RFC 9728 view's URL.
    """

    def test_unauthenticated_challenge_includes_resource_metadata(self, client):
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"",
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith('Bearer realm="api"')
        # The resource_metadata value must be the absolute URL of the
        # RFC 9728 view; a client should be able to fetch the metadata
        # without any other knowledge. Reverse-and-substring is brittle
        # against substring collisions but cheap; if a path collision
        # ever appears, switch to full-URL equality.
        expected_path = reverse("mcp_sql_protected_resource_metadata")
        assert 'resource_metadata="' in challenge
        assert expected_path in challenge


class TestBodySizeCap:
    """`PayloadTooLarge` (HTTP 413) fires BEFORE the body force-cache so an
    oversize POST cannot OOM a worker on the auth-class body precache. The
    cap is set to 1 MiB — generous for the SQL the `/mcp/sql/` body carries
    (even a large literal `IN (...)` list), refusing only abuse-shape bodies.
    The anonymous OAuth endpoints get a tighter 64 KiB cap via
    `decorators.cap_request_body` (see `tests/test_decorators.py`).
    """

    def test_oversize_content_length_raises_413(self):
        factory = APIRequestFactory()
        # Carry a bearer token so the body-precache path is the one that
        # would have fired. The auth-class never reaches token validation
        # — the size check sits before super().authenticate.
        request = factory.post(
            "/mcp/sql/",
            data="x" * 10,  # actual body small; what matters is the header
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer test",
        )
        # Spoof CONTENT_LENGTH to the cap + 1.
        request.META["CONTENT_LENGTH"] = str(MCP_REQUEST_BODY_MAX_BYTES + 1)
        with pytest.raises(PayloadTooLarge) as exc:
            MCPOAuth2Authentication().authenticate(request)
        assert exc.value.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    def test_content_length_at_cap_passes_size_gate(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """Boundary: exactly MCP_REQUEST_BODY_MAX_BYTES is permitted (the
        cap is exclusive on the upper end). Confirms the size gate doesn't
        false-positive on borderline-sized bodies; full auth proceeds."""
        request = _bearer_request(mcp_access_token.token)
        request.META["CONTENT_LENGTH"] = str(MCP_REQUEST_BODY_MAX_BYTES)
        user, _token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk

    def test_missing_content_length_does_not_block(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """No `CONTENT_LENGTH` header → treated as zero → size gate passes.
        GETs (when added later) and TestClient-style requests without an
        explicit length header must not be falsely refused."""
        request = _bearer_request(mcp_access_token.token)
        # APIRequestFactory may set CONTENT_LENGTH to a small int; remove it.
        request.META.pop("CONTENT_LENGTH", None)
        user, _token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk

    def test_garbage_content_length_does_not_block(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        """A non-integer `CONTENT_LENGTH` falls through to zero rather than
        raising — defensive parse around an attacker-controlled header."""
        request = _bearer_request(mcp_access_token.token)
        request.META["CONTENT_LENGTH"] = "not-a-number"
        user, _token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk
