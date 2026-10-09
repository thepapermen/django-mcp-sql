"""Tests for `MCPOAuth2Authentication`.

The centerpiece is `TestOAuthTokenIsolationFromGlobalDRF`, which pins the
design's central acceptance criterion: a token issued for `/mcp/sql/` must
not authenticate against any other DRF endpoint. The structural reason is
that `MCPOAuth2Authentication` is mounted on the MCP view only — never in
`REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`. The default global
classes (`SessionAuthentication`, `TokenAuthentication`) ignore the
`Bearer` prefix.
"""

import json
from datetime import timedelta
from http import HTTPStatus

import pytest
from django.core.cache import cache
from django.test.client import BOUNDARY
from django.test.client import MULTIPART_CONTENT
from django.test.client import encode_multipart
from django.urls import reverse
from django.utils import timezone
from mcp_sql.auth import MCP_REQUEST_BODY_MAX_BYTES
from mcp_sql.auth import GateUnavailable
from mcp_sql.auth import MCPOAuth2Authentication
from mcp_sql.auth import PayloadTooLarge
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP
from oauth2_provider.oauth2_validators import OAuth2Validator
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory


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
        # `_verify_bearer` (DOT's own authenticate logic) returns `None` for
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
        with pytest.raises(AuthenticationFailed, match="inactive"):
            MCPOAuth2Authentication().authenticate(request)

    def test_non_staff_user_is_accepted(
        self, mcp_user, mcp_access_token, mcp_mfa_on, mcp_active_session
    ):
        # No staff requirement: the explicit profile assignment is the gate.
        mcp_user.is_staff = False
        mcp_user.save()
        request = _bearer_request(mcp_access_token.token)
        user, _token = MCPOAuth2Authentication().authenticate(request)
        assert user.pk == mcp_user.pk

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

    @pytest.mark.usefixtures("session_gate_on")
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

    @pytest.mark.usefixtures("session_gate_on")
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

    @pytest.mark.parametrize(
        ("remote_addr", "stored"),
        [("not-an-ip", None), ("a:b:zz", None), ("fe80::1%eth0", None)],
    )
    def test_non_ip_remote_addr_still_writes_the_row(
        self, mcp_user, mcp_access_token, gate_posture, remote_addr, stored
    ):
        """A front end that puts non-IP text into `REMOTE_ADDR` (uvicorn
        `--forwarded-allow-ips='*'` copying a client's `X-Forwarded-For`)
        used to turn the denial into a 500 (psycopg 3 `ValueError` at the
        insert) or silently drop the row (psycopg2 `DataError`)."""
        from mcp_sql.models import MCPAuthRejectionLog

        mcp_user.is_active = False
        mcp_user.save(update_fields=["is_active"])
        request = APIRequestFactory().post(
            "/mcp/sql/",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
            REMOTE_ADDR=remote_addr,
        )
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)

        log = MCPAuthRejectionLog.objects.get()
        assert log.reason == AuthRejectionReason.INACTIVE
        assert log.client_ip == stored

    def test_legacy_inactive_or_non_staff_reason_stays_valid(self):
        # Rows written by 0.1.x carry `inactive_or_non_staff`; the choice must
        # survive so those rows still validate and display (migration 0015).
        from mcp_sql.models import MCPAuthRejectionLog

        choices = dict(MCPAuthRejectionLog._meta.get_field("reason").choices)
        assert AuthRejectionReason.INACTIVE_OR_NON_STAFF in choices
        assert AuthRejectionReason.INACTIVE in choices

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
        assert log.reason == AuthRejectionReason.INACTIVE
        assert log.user_id == mcp_user.pk

    # The throttle keys its cache on the raw `REMOTE_ADDR` (a space in it
    # warns: memcached would refuse such a key).
    @pytest.mark.filterwarnings("ignore::django.core.cache.CacheKeyWarning")
    @pytest.mark.usefixtures("_isolated_mcp_cache")
    @pytest.mark.parametrize(
        ("remote_addr", "recorded"),
        [("198.51.100.4", "198.51.100.4"), ("10.0.0.1, 10.0.0.2", None)],
    )
    def test_audit_row_client_ip_is_one_address_or_none(
        self, mcp_user, mcp_access_token, mcp_mfa_on, remote_addr, recorded
    ):
        """Review round 18: a `REMOTE_ADDR` that is not one IP address made
        the audit insert raise `ValueError` (psycopg 3 adapts `inet` with
        `ipaddress.ip_address`), which escaped as a 500 instead of the 401."""
        from mcp_sql.models import MCPAuthRejectionLog

        mcp_user.is_active = False
        mcp_user.save()
        request = _bearer_request_from_ip(mcp_access_token.token, remote_addr)
        with pytest.raises(AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(request)
        assert MCPAuthRejectionLog.objects.get().client_ip == recorded

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

    @pytest.mark.usefixtures("session_gate_on")
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
        from mcp_sql.models import MCPAuthRejectionLog
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

    @pytest.mark.usefixtures("session_gate_on")
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


@pytest.mark.django_db
class TestGateFailuresAreAuditedDenials:
    """A gate that raises is a denial: 503 plus a `gate_error` row, never a
    500 with no trace. Fails closed either way, but the unaudited 500 left
    no record of who was refused. 503 rather than 401 so clients do not
    start an OAuth re-authorization that would fail the same way."""

    def _assert_gate_error(self, token, user):
        from mcp_sql.models import MCPAuthRejectionLog

        with pytest.raises(GateUnavailable, match="could not be verified"):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.GATE_ERROR
        assert row.user_id == user.pk

    def test_endpoint_answers_503_without_a_challenge(  # noqa: PLR0913 — fixtures
        self, client, mcp_user, mcp_access_token, gate_posture, settings, monkeypatch
    ):
        """Owner decision: a raising gate is a 503, not a 401. A 401 carries
        `WWW-Authenticate`, which sends MCP clients into a full OAuth
        re-authorization that would fail the same way during an MFA-backend
        or session-store outage. Still a denial, still audited."""
        from mcp_sql.models import MCPAuthRejectionLog

        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "MFA_CHECKER": "mcp_sql.tests.conftest._mfa_checker_raises",
        }
        reached = []
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint._invoke_wsgi_app",
            lambda *args, **kwargs: reached.append(1),
        )
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"{}",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
        )
        assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        assert "WWW-Authenticate" not in response
        assert response["Retry-After"] == "30"
        assert reached == []
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.GATE_ERROR

    def test_raising_mfa_checker(
        self, mcp_user, mcp_access_token, gate_posture, settings, caplog
    ):
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "MFA_CHECKER": "mcp_sql.tests.conftest._mfa_checker_raises",
        }
        self._assert_gate_error(mcp_access_token, mcp_user)
        assert "simulated MFA backend outage" in caplog.text

    def test_raising_profile_resolution(
        self, mcp_user, mcp_access_token, gate_posture, monkeypatch
    ):
        from django.db import OperationalError

        def boom(user):
            msg = "simulated default-DB outage"
            raise OperationalError(msg)

        monkeypatch.setattr("mcp_sql.auth.mcp_sql_settings.resolve_profile", boom)
        self._assert_gate_error(mcp_access_token, mcp_user)

    def test_raising_session_lookup(
        self, mcp_user, mcp_access_token, mcp_mfa_on, monkeypatch, settings
    ):
        # The session gate on explicitly: the minimal test posture
        # (`MCP_SQL_TEST_POSTURE=minimal`) runs with `SESSION_MODEL=None`.
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "SESSION_MODEL": "mcp_sql_testapp.TestSession",
        }

        def boom(name):
            msg = f"No installed app with label {name!r}."
            raise LookupError(msg)

        monkeypatch.setattr("mcp_sql.auth.apps.get_model", boom)
        self._assert_gate_error(mcp_access_token, mcp_user)

    def test_ambiguous_warning_dedup_cache_fault_still_denies(  # noqa: PLR0913 — fixtures
        self,
        two_profiles,
        mcp_user,
        mcp_access_token,
        gate_posture,
        monkeypatch,
        caplog,
    ):
        """The once-per-hour WARNING dedup is a cache call; a cache fault
        there must not turn the AMBIGUOUS_PROFILE denial into a 500."""
        import logging

        from django.contrib.auth.models import Group
        from mcp_sql.models import MCPAuthRejectionLog

        def boom(*args, **kwargs):
            msg = "simulated cache timeout"
            raise TimeoutError(msg)

        monkeypatch.setattr("mcp_sql.auth.cache.add", boom)
        mcp_user.groups.add(Group.objects.get(name=SECOND_PROFILE_GROUP))
        with (
            caplog.at_level(logging.WARNING, logger="mcp_sql.auth"),
            pytest.raises(AuthenticationFailed, match="more than one MCP profile"),
        ):
            MCPOAuth2Authentication().authenticate(
                _bearer_request(mcp_access_token.token)
            )
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.AMBIGUOUS_PROFILE
        # Without the dedup the warning is still emitted (signal over silence).
        assert "MCP profile resolution ambiguous" in caplog.text


@pytest.mark.django_db
class TestTokensMissingUserOrApplication:
    """DOT allows `AccessToken.user` and `.application` to be NULL (e.g. a
    `client_credentials` token from a second OAuth use case on the same
    install, or a shell-minted row). Neither may reach a gate that assumes
    them: a userless token on an MCP app was an unaudited 500
    (`None.is_active`), and on another app a 401 whose audit insert failed on
    the non-null `user` FK."""

    def _token(self, *, user, application):
        import secrets

        from oauth2_provider.models import AccessToken

        return AccessToken.objects.create(
            user=user,
            token="t_" + secrets.token_urlsafe(16),
            application=application,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )

    @pytest.mark.parametrize("mcp_named_app", [True, False])
    def test_userless_token_is_a_logged_401(
        self, client, mcp_app, gate_posture, caplog, mcp_named_app
    ):
        import logging

        from mcp_sql.models import MCPAuthRejectionLog
        from oauth2_provider.models import Application

        application = (
            mcp_app
            if mcp_named_app
            else Application.objects.create(
                name="some-other-service",
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            )
        )
        token = self._token(user=None, application=application)
        with caplog.at_level(logging.WARNING, logger="mcp_sql.auth"):
            response = client.post(
                reverse("mcp_sql_endpoint"),
                data=b"{}",
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token.token}",
            )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response["WWW-Authenticate"].startswith('Bearer realm="api"')
        # The rejection table is keyed to a real user, so the record is the
        # WARNING naming the token and its client.
        assert MCPAuthRejectionLog.objects.count() == 0
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any(
            "no user" in r.getMessage() and str(token.pk) in r.getMessage()
            for r in warnings
        )
        assert not any(r.levelno >= logging.ERROR for r in caplog.records)

    def test_applicationless_token_is_an_audited_bad_application(
        self, mcp_user, gate_posture
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        token = self._token(user=mcp_user, application=None)
        with pytest.raises(AuthenticationFailed, match="mcp-sql Application"):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.BAD_APPLICATION
        assert row.user_id == mcp_user.pk
        assert row.application_name == ""


@pytest.mark.django_db(transaction=True)
class TestRejectionAuditSurvivesAtomicRequests:
    """Rejection rows must outlive DRF's rollback under `ATOMIC_REQUESTS`.

    The documented deployment runs the default alias with
    `ATOMIC_REQUESTS=True`, and DRF's exception handler marks every
    `ATOMIC_REQUESTS` transaction for rollback on ANY `APIException`,
    including the `AuthenticationFailed` each gate raises right after writing
    its audit row. Inside the request transaction, every gate denial was
    therefore rolled back while the 401 still went out. `mcp_endpoint` is
    `non_atomic_requests`, so the row is written in autocommit and survives.

    Transactional (`transaction=True`) because a rollback only shows when the
    request's transaction is a real one, not a savepoint in the test's.
    """

    def test_inactive_user_rejection_row_is_committed(
        self, client, mcp_user, mcp_access_token, gate_posture, monkeypatch
    ):
        from django.db import connections
        from mcp_sql.models import MCPAuthRejectionLog

        monkeypatch.setitem(
            connections["default"].settings_dict, "ATOMIC_REQUESTS", value=True
        )
        mcp_user.is_active = False
        mcp_user.save(update_fields=["is_active"])

        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"{}",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response["WWW-Authenticate"].startswith('Bearer realm="api"')
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.INACTIVE
        assert row.user_id == mcp_user.pk

    def test_endpoint_opts_out_of_atomic_requests(self):
        from mcp_sql.views.mcp_endpoint import mcp_endpoint

        assert "default" in mcp_endpoint._non_atomic_requests


class TestEveryAliasIsNonAtomic:
    """The opt-out covers every alias, not only `default`.

    DRF's `set_rollback()` marks every `ATOMIC_REQUESTS` connection, so a
    consumer whose router sends `mcp_sql`'s audit tables to another alias
    with `ATOMIC_REQUESTS=True` lost every rejection row to the 401 while a
    bare `@non_atomic_requests` (which records only `default`) let Django
    wrap the view in that alias's transaction. No DB needed: this asks
    Django's own handler what it would wrap.
    """

    def test_handler_wraps_the_view_in_no_alias_transaction(self, monkeypatch):
        from django.core.handlers.base import BaseHandler
        from django.db import connections
        from mcp_sql.views.mcp_endpoint import mcp_endpoint

        for alias in ("audit", "reporting"):
            monkeypatch.setitem(
                connections.settings,
                alias,
                {**connections.settings["default"], "ATOMIC_REQUESTS": True},
            )
        monkeypatch.setitem(
            connections.settings["default"], "ATOMIC_REQUESTS", value=True
        )
        assert BaseHandler().make_view_atomic(mcp_endpoint) is mcp_endpoint


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
        the token lookup — saves the DB SELECT under sustained probing."""
        from django.core.cache import cache
        from oauth2_provider.oauth2_validators import OAuth2Validator

        settings.MCP_SQL = {**settings.MCP_SQL, "BAD_TOKEN_IP_THRESHOLD": 1}

        # Seed the per-IP counter at the threshold directly (no need to
        # probe first; we're isolating the block behavior).
        cache.set("mcp_sql:bad_token:ip:203.0.113.99", 1, timeout=3600)

        # Spy on DOT's token lookup to confirm it's never invoked (the
        # bearer check no longer goes through DOT's DRF `authenticate`, so a
        # spy there would pass vacuously). Control: the same request from an
        # unblocked IP does reach it.
        calls = []
        original = OAuth2Validator._load_access_token

        def spy(self, token):
            calls.append(token)
            return original(self, token)

        monkeypatch.setattr(OAuth2Validator, "_load_access_token", spy)

        request = _bearer_request_from_ip("anything", "203.0.113.99")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert calls == [], "DOT's token lookup must NOT run on a blocked IP"
        request = _bearer_request_from_ip("anything", "203.0.113.100")
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert calls == ["anything"]

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
    only via the `Authorization` header (RFC 6750 §2.1). These tests pin the
    *presence* requirement; refusing a token sent any other way (RFC 6750
    §2.2 form body, §2.3 query) is `MCPOAuth2Authentication`'s own guard —
    DOT/oauthlib alone would accept both — pinned by
    `TestBearerTokenOnlyInHeader` below.
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


_MCP_URLS = ["/mcp/sql/", "/mcp/sql"]  # canonical route + the slash-less alias
_INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
)
_ACCEPT = {"HTTP_ACCEPT": "application/json, text/event-stream"}


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache", "mcp_mfa_on", "mcp_active_session")
@pytest.mark.parametrize("url", _MCP_URLS)
# DOT's own RFC 9700 nag for a query-string token: expected here, the point is
# that the token is ignored all the same (`test_oauth_server.py` pins DOT's
# opt-in setting that refuses such a request without it).
@pytest.mark.filterwarnings(
    "ignore:Presenting an OAuth 2.0 access token in the URI query string"
    ":DeprecationWarning"
)
class TestBearerTokenOnlyInHeader:
    """A bearer token is accepted from the `Authorization` header only.

    oauthlib's stock `BearerToken` (and so DOT) also takes an `access_token`
    from the query string or a form body when no header is present — every
    release up to and including 0.1.0b5 authenticated
    `/mcp/sql/?access_token=<token>`. On `MCPServer`'s `HeaderOnlyBearer`
    such a parameter is not a credential: a request carrying a token only
    there is unauthenticated (the ordinary 401 challenge, the same for a
    valid and a bogus token), the parameter is never looked up, and beside a
    header it is ignored — the header's token decides.
    """

    @pytest.fixture
    def token_lookups(self, monkeypatch) -> list:
        # Spy on DOT's token lookup: a parameter token must never reach it.
        calls: list = []
        original = OAuth2Validator._load_access_token

        def spy(self, token):
            calls.append(token)
            return original(self, token)

        monkeypatch.setattr(OAuth2Validator, "_load_access_token", spy)
        return calls

    def _assert_unauthenticated(self, response, token_lookups) -> None:
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith('Bearer realm="api"')
        assert "resource_metadata=" in challenge
        assert "error=" not in challenge
        assert token_lookups == []
        # No `Authorization` header: anonymous traffic, not a resolved-user
        # denial (no audit row) and not a bearer probe (no throttle count).
        assert not MCPAuthRejectionLog.objects.exists()
        assert cache.get("mcp_sql:bad_token:ip:127.0.0.1") is None

    def test_header_only_is_served(self, client, url, mcp_access_token, token_lookups):
        response = client.post(
            url,
            data=_INITIALIZE,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
            **_ACCEPT,
        )
        assert response.status_code == HTTPStatus.OK, response.content
        assert token_lookups == [mcp_access_token.token]

    def test_valid_token_in_query_is_not_a_credential(
        self, client, url, mcp_access_token, token_lookups
    ):
        response = client.post(
            f"{url}?access_token={mcp_access_token.token}",
            data=_INITIALIZE,
            content_type="application/json",
            **_ACCEPT,
        )
        self._assert_unauthenticated(response, token_lookups)

    def test_bogus_token_in_query_gets_the_same_401(self, client, url, token_lookups):
        # Same answer as for a valid token: the URL token is never checked.
        response = client.post(
            f"{url}?access_token=not-a-token",
            data=_INITIALIZE,
            content_type="application/json",
            **_ACCEPT,
        )
        self._assert_unauthenticated(response, token_lookups)

    def test_query_token_beside_a_valid_header_is_ignored(
        self, client, url, mcp_access_token, token_lookups
    ):
        response = client.post(
            f"{url}?access_token=not-a-token",
            data=_INITIALIZE,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
            **_ACCEPT,
        )
        assert response.status_code == HTTPStatus.OK, response.content
        assert token_lookups == [mcp_access_token.token]

    def test_query_token_never_rescues_a_bad_header(
        self, client, url, mcp_access_token, token_lookups
    ):
        # The valid parameter token is not a fallback for a failed header.
        response = client.post(
            f"{url}?access_token={mcp_access_token.token}",
            data=_INITIALIZE,
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer not-a-token",
            **_ACCEPT,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        assert token_lookups == ["not-a-token"]

    def test_query_token_on_a_get_is_not_a_credential(
        self, url, mcp_access_token, token_lookups
    ):
        # At the auth-class level: an authenticated GET opens the MCP
        # transport's long-lived stream, so a regression must fail here, not
        # hang the suite.
        request = Request(
            APIRequestFactory().get(f"{url}?access_token={mcp_access_token.token}")
        )
        assert MCPOAuth2Authentication().authenticate(request) is None
        assert token_lookups == []

    def test_valid_token_in_urlencoded_body_is_not_a_credential(
        self, client, url, mcp_access_token, token_lookups
    ):
        response = client.post(
            url,
            data=f"access_token={mcp_access_token.token}",
            content_type="application/x-www-form-urlencoded",
            **_ACCEPT,
        )
        self._assert_unauthenticated(response, token_lookups)

    def test_valid_token_in_multipart_body_is_not_a_credential(
        self, client, url, mcp_access_token, token_lookups
    ):
        # The test client's default content type for a dict is multipart.
        response = client.post(
            url, data={"access_token": mcp_access_token.token}, **_ACCEPT
        )
        self._assert_unauthenticated(response, token_lookups)

    def test_form_body_token_never_rescues_a_bad_header(
        self, client, url, mcp_access_token, token_lookups
    ):
        response = client.post(
            url,
            data=f"access_token={mcp_access_token.token}",
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Bearer not-a-token",
            **_ACCEPT,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        assert token_lookups == ["not-a-token"]

    @pytest.mark.parametrize(
        "case",
        [
            (method, encoding)
            for method in ("GET", "DELETE", "OPTIONS", "PUT")
            for encoding in ("urlencoded", "multipart")
        ],
        ids=lambda case: "-".join(case),
    )
    def test_form_body_token_is_not_a_credential_on_any_method(
        self, client, url, mcp_access_token, token_lookups, case
    ):
        method, encoding = case
        # DOT reads the body through DRF's `Request.POST`, which parses a form
        # body whatever the method (Django's own `request.POST` is POST-only).
        # `Accept: application/json` only: were the token accepted, a GET would
        # get a 406 here instead of opening the MCP stream.
        if encoding == "urlencoded":
            body = f"access_token={mcp_access_token.token}"
            content_type = "application/x-www-form-urlencoded"
        else:
            body = encode_multipart(BOUNDARY, {"access_token": mcp_access_token.token})
            content_type = MULTIPART_CONTENT
        response = client.generic(
            method,
            url,
            data=body,
            content_type=content_type,
            HTTP_ACCEPT="application/json",
        )
        # `/mcp/sql/` is POST-only: every other method is a 405 before DRF and
        # the auth class run, so the body is never read as a credential at
        # all (no lookup, no audit row, no throttle count).
        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED
        assert response["Allow"] == "POST"
        assert token_lookups == []
        assert not MCPAuthRejectionLog.objects.exists()
        assert cache.get("mcp_sql:bad_token:ip:127.0.0.1") is None

    def test_json_body_field_named_access_token_is_not_inspected(
        self, client, url, mcp_access_token, token_lookups
    ):
        # The JSON-RPC body is no token transport and is unaffected.
        body = json.loads(_INITIALIZE)
        body["params"]["access_token"] = "irrelevant"
        response = client.post(
            url,
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {mcp_access_token.token}",
            **_ACCEPT,
        )
        assert response.status_code == HTTPStatus.OK, response.content


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
