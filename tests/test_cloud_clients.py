"""Opt-in cloud-client (Category-B) support.

Covers the settings validation, the derived client_id, settings-gated
recognition, the `post_migrate` provisioning receiver, the prefix
`validate_redirect_uri` override + its hardened helper, logout revocation, and
the `client_redirect` audit attribution.

Deliberately does NOT touch the loopback DCR path: `/o/register` stays
loopback-only and its invariants remain pinned by `test_registration.py`. If a
change here ever required editing those, that is the signal the cornerstone was
weakened — it must not be.
"""

import secrets
from datetime import timedelta

import pytest
from django.apps import apps as django_apps
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from mcp_sql.auth import MCPOAuth2Authentication
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.oauth import _redirect_under_prefix
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.signals import _revoke_and_audit_on_logout
from mcp_sql.signals import provision_mcp_cloud_clients
from mcp_sql.validation import validate_mcp_sql_settings
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

CLAUDE = {
    "NAME": "claude",
    "REDIRECT_MATCH": "exact",
    "REDIRECT_URI": "https://claude.ai/api/mcp/auth_callback",
}
CHATGPT = {
    "NAME": "chatgpt",
    "REDIRECT_MATCH": "prefix",
    "REDIRECT_URI": "https://chatgpt.com/connector/oauth/",
}
CLAUDE_CLIENT_ID = "mcp-sql-cloud.claude"
CHATGPT_CLIENT_ID = "mcp-sql-cloud.chatgpt"


def _cfg(clients):
    """The valid test-settings MCP_SQL dict with CLOUD_CLIENTS spliced in."""
    return {**django_settings.MCP_SQL, "CLOUD_CLIENTS": clients}


def _provision(settings, clients):
    """Set CLOUD_CLIENTS and run the real provisioning receiver (mirrors how the
    `two_profiles` fixture drives `provision_mcp_profiles`)."""
    settings.MCP_SQL = {**settings.MCP_SQL, "CLOUD_CLIENTS": clients}
    provision_mcp_cloud_clients(sender=django_apps.get_app_config("mcp_sql"))


def _bearer_request(token: str):
    return APIRequestFactory().post("/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {token}")


# --------------------------------------------------------------------------- #
# Settings validation                                                         #
# --------------------------------------------------------------------------- #


class TestCloudClientValidation:
    def test_empty_is_valid_feature_off(self):
        validate_mcp_sql_settings(_cfg([]))  # no raise

    def test_seed_pair_is_valid(self):
        validate_mcp_sql_settings(_cfg([CLAUDE, CHATGPT]))  # no raise

    @pytest.mark.parametrize(
        "clients",
        [
            pytest.param([{**CLAUDE, "NAME": "Claude"}], id="uppercase-name"),
            pytest.param([{**CLAUDE, "NAME": "1claude"}], id="name-starts-digit"),
            pytest.param([{**CLAUDE, "NAME": ""}], id="empty-name"),
            pytest.param([CLAUDE, CLAUDE], id="duplicate-name"),
            pytest.param([{**CLAUDE, "REDIRECT_MATCH": "fuzzy"}], id="bad-match"),
            pytest.param(
                [{**CLAUDE, "REDIRECT_URI": "http://claude.ai/cb"}], id="http-scheme"
            ),
            pytest.param(
                [{**CLAUDE, "REDIRECT_URI": "https://u:p@claude.ai/cb"}], id="userinfo"
            ),
            pytest.param(
                [{**CLAUDE, "REDIRECT_URI": "https://claude.ai/*"}], id="wildcard"
            ),
            pytest.param(
                [{**CLAUDE, "REDIRECT_URI": "https://claude.ai/a/../b"}], id="traversal"
            ),
            pytest.param(
                [{**CHATGPT, "REDIRECT_URI": "https://chatgpt.com"}],
                id="prefix-without-path",
            ),
            pytest.param(
                [{**CHATGPT, "REDIRECT_URI": "https://chatgpt.com/connector/oauth"}],
                id="prefix-without-trailing-slash",
            ),
            pytest.param(
                [{**CLAUDE, "REDIRECT_URI": "https://claude.ai/a/%2e%2e/b"}],
                id="encoded-traversal",
            ),
            pytest.param([{"NAME": "x"}], id="missing-keys"),
        ],
    )
    def test_invalid_entries_rejected(self, clients):
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(_cfg(clients))

    def test_exact_client_requires_https_in_scheme_allowlist(self, settings):
        # An "exact" client rides DOT's ALLOWED_REDIRECT_URI_SCHEMES; without
        # https it would fail opaquely at /o/authorize/, so boot loudly instead.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],
        }
        with pytest.raises(ImproperlyConfigured, match="ALLOWED_REDIRECT_URI_SCHEMES"):
            validate_mcp_sql_settings(_cfg([CLAUDE]))

    def test_prefix_only_config_unaffected_by_scheme_allowlist(self, settings):
        # A "prefix" client bypasses DOT's allowlist (it enforces https itself),
        # so an http-only allowlist is valid for a prefix-only config.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],
        }
        validate_mcp_sql_settings(_cfg([CHATGPT]))  # no raise


# --------------------------------------------------------------------------- #
# Derivation + settings-gated recognition                                     #
# --------------------------------------------------------------------------- #


class TestCloudClientDerivation:
    def test_client_id_is_prefixed_with_a_dot_marker(self, settings):
        settings.MCP_SQL = _cfg([CLAUDE, CHATGPT])
        clients = mcp_sql_settings.cloud_clients()
        assert set(clients) == {CLAUDE_CLIENT_ID, CHATGPT_CLIENT_ID}
        assert clients[CLAUDE_CLIENT_ID].redirect_match == "exact"
        assert clients[CHATGPT_CLIENT_ID].redirect_uri == CHATGPT["REDIRECT_URI"]

    def test_empty_default_is_off(self, settings):
        settings.MCP_SQL = _cfg([])
        assert mcp_sql_settings.cloud_clients() == {}


class TestCloudRecognition:
    def test_recognised_only_while_in_settings(self, settings):
        settings.MCP_SQL = _cfg([CLAUDE])
        assert is_mcp_application_name(CLAUDE_CLIENT_ID) is True
        # Fail-closed: removing the entry de-recognises it at the next read.
        settings.MCP_SQL = _cfg([])
        assert is_mcp_application_name(CLAUDE_CLIENT_ID) is False

    def test_canonical_and_dcr_shapes_unaffected(self, settings):
        settings.MCP_SQL = _cfg([CLAUDE])
        assert is_mcp_application_name("mcp-sql") is True
        # A genuine DCR name (prefix + 22 urlsafe chars) still matches.
        assert is_mcp_application_name("mcp-sql-" + "a" * 22) is True

    def test_cloud_id_is_disjoint_from_dcr_shape(self, settings):
        # The '.' after "cloud" means the suffix can never be a 22-char DCR
        # token, so a removed cloud client can't leak back in via the DCR branch.
        settings.MCP_SQL = _cfg([])
        assert is_mcp_application_name(CLAUDE_CLIENT_ID) is False


# --------------------------------------------------------------------------- #
# Prefix redirect matching (security-critical)                                #
# --------------------------------------------------------------------------- #


_PREFIX = "https://chatgpt.com/connector/oauth/"


class TestRedirectUnderPrefix:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://chatgpt.com/connector/oauth/abc123",
            "https://chatgpt.com/connector/oauth/",
            "https://chatgpt.com/connector/oauth/deep/er",
            # Explicit https default port equals the prefix's implicit one.
            "https://chatgpt.com:443/connector/oauth/abc123",
        ],
    )
    def test_accepts_under_prefix(self, uri):
        assert _redirect_under_prefix(uri, _PREFIX) is True

    @pytest.mark.parametrize(
        "uri",
        [
            pytest.param("https://chatgpt.com/other", id="wrong-path"),
            pytest.param("https://chatgpt.com/connector/oauth", id="path-not-under"),
            pytest.param(
                "https://chatgpt.com.evil.com/connector/oauth/x", id="suffix-host"
            ),
            pytest.param("https://evil.com/connector/oauth/x", id="wrong-host"),
            pytest.param("http://chatgpt.com/connector/oauth/x", id="http-downgrade"),
            pytest.param(
                "https://u:p@chatgpt.com/connector/oauth/x", id="userinfo-smuggle"
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/../evil", id="path-traversal"
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/%2e%2e/%2e%2e/admin",
                id="encoded-traversal",
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/%252e%252e/admin",
                id="double-encoded-traversal",
            ),
            pytest.param(
                "https://chatgpt.com:8443/connector/oauth/x", id="port-mismatch"
            ),
            pytest.param(
                # `:0` is falsy but not a missing port — must not alias :443.
                "https://chatgpt.com:0/connector/oauth/x",
                id="explicit-port-zero",
            ),
            pytest.param(
                "https://chatgpt.com:notaport/connector/oauth/x", id="malformed-port"
            ),
        ],
    )
    def test_rejects_bypass_attempts(self, uri):
        assert _redirect_under_prefix(uri, _PREFIX) is False

    def test_bare_prefix_is_still_segment_anchored(self):
        # Even handed a prefix without the trailing slash (which validation
        # forbids), the predicate anchors at a `/` boundary: a sibling whose
        # name merely begins with the last segment is rejected, a true child
        # is accepted.
        bare = "https://chatgpt.com/connector/oauth"
        assert _redirect_under_prefix(f"{bare}EVIL/steal", bare) is False
        assert _redirect_under_prefix(f"{bare}-attacker", bare) is False
        assert _redirect_under_prefix(f"{bare}/inst-42", bare) is True


class TestValidateRedirectUriOverride:
    def test_prefix_client_admits_under_prefix(self, settings):
        settings.MCP_SQL = _cfg([CHATGPT])
        v = MCPOAuth2Validator()
        assert (
            v.validate_redirect_uri(
                CHATGPT_CLIENT_ID,
                "https://chatgpt.com/connector/oauth/inst-42",
                request=None,
            )
            is True
        )

    def test_prefix_client_rejects_off_prefix(self, settings):
        settings.MCP_SQL = _cfg([CHATGPT])
        v = MCPOAuth2Validator()
        assert (
            v.validate_redirect_uri(
                CHATGPT_CLIENT_ID, "https://evil.com/x", request=None
            )
            is False
        )

    def test_exact_client_delegates_to_super_never_prefix_matching(
        self, settings, monkeypatch
    ):
        # Load-bearing scoping: an "exact" cloud client must fall through to
        # DOT's stock (exact) matching, NOT the prefix override. Dropping the
        # `== "prefix"` guard would silently loosen exact clients — this pins it.
        from oauth2_provider.oauth2_validators import OAuth2Validator

        settings.MCP_SQL = _cfg([CLAUDE])  # REDIRECT_MATCH == "exact"
        prefix_calls: list = []
        monkeypatch.setattr(
            "mcp_sql.oauth._redirect_under_prefix",
            lambda *a, **k: prefix_calls.append(a) or True,
        )
        monkeypatch.setattr(
            OAuth2Validator,
            "validate_redirect_uri",
            lambda self, *a, **k: "DELEGATED-TO-SUPER",
        )
        result = MCPOAuth2Validator().validate_redirect_uri(
            CLAUDE_CLIENT_ID, CLAUDE["REDIRECT_URI"], request=None
        )
        assert result == "DELEGATED-TO-SUPER"  # rode DOT stock matching
        assert prefix_calls == []  # the prefix override was never touched


# --------------------------------------------------------------------------- #
# Provisioning                                                                 #
# --------------------------------------------------------------------------- #


class TestCloudProvisioning:
    def test_creates_rows_with_curated_posture(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, [CLAUDE, CHATGPT])
        app = Application.objects.get(client_id=CLAUDE_CLIENT_ID)
        assert app.name == CLAUDE_CLIENT_ID
        # Public + PKCE: no client_secret is used at the token endpoint. (DOT
        # hashes whatever secret string is stored, so asserting the raw column
        # is `""` is meaningless — `client_type` is the load-bearing invariant.)
        assert app.client_type == Application.CLIENT_PUBLIC
        assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
        # Consent is load-bearing for a non-loopback redirect.
        assert app.skip_authorization is False
        assert app.redirect_uris == CLAUDE["REDIRECT_URI"]
        assert Application.objects.filter(client_id=CHATGPT_CLIENT_ID).exists()

    def test_is_idempotent(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, [CLAUDE])
        _provision(settings, [CLAUDE])
        assert Application.objects.filter(client_id=CLAUDE_CLIENT_ID).count() == 1

    def test_provisioning_logs_the_client_id_to_paste(self, db, settings, caplog):
        # Discoverability: `migrate` surfaces the derived client_id operators
        # must paste into the provider connector.
        import logging

        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            _provision(settings, [CLAUDE])
        assert CLAUDE_CLIENT_ID in caplog.text

    def test_redirect_change_syncs_on_reprovision(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, [CLAUDE])
        moved = {**CLAUDE, "REDIRECT_URI": "https://claude.com/api/mcp/auth_callback"}
        _provision(settings, [moved])
        app = Application.objects.get(client_id=CLAUDE_CLIENT_ID)
        assert app.redirect_uris == "https://claude.com/api/mcp/auth_callback"

    def test_removed_entry_leaves_row_but_recognition_denies(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, [CLAUDE])
        settings.MCP_SQL = _cfg([])  # remove; row is deliberately NOT deleted
        assert Application.objects.filter(client_id=CLAUDE_CLIENT_ID).exists()
        assert is_mcp_application_name(CLAUDE_CLIENT_ID) is False


# --------------------------------------------------------------------------- #
# Logout revocation + audit attribution                                       #
# --------------------------------------------------------------------------- #


def _cloud_token(user, client_id):
    from oauth2_provider.models import AccessToken
    from oauth2_provider.models import Application

    app = Application.objects.get(client_id=client_id)
    return AccessToken.objects.create(
        user=user,
        token="test_" + secrets.token_urlsafe(24),
        application=app,
        expires=timezone.now() + timedelta(hours=1),
        scope="mcp:sql",
    )


class TestCloudLogoutRevocation:
    def test_logout_revokes_cloud_tokens_via_prefix(self, db, settings, mcp_user):
        from oauth2_provider.models import AccessToken

        _provision(settings, [CLAUDE])
        token = _cloud_token(mcp_user, CLAUDE_CLIENT_ID)
        _revoke_and_audit_on_logout(
            user=mcp_user, client_ip=None, logged_out_at=timezone.now()
        )
        assert not AccessToken.objects.filter(pk=token.pk).exists()


@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestCloudAuthRecognitionAndAudit:
    def test_removed_cloud_client_denied_and_audited_with_redirect(
        self, db, settings, mcp_user
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        _provision(settings, [CLAUDE])
        token = _cloud_token(mcp_user, CLAUDE_CLIENT_ID)
        # Drop the client from settings; the Application row still exists, so
        # DOT resolves the token, but recognition is now fail-closed.
        settings.MCP_SQL = _cfg([])
        with pytest.raises(exceptions.AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.BAD_APPLICATION
        # The audit records the ground-truth issued redirect, not a label.
        assert row.client_redirect == CLAUDE["REDIRECT_URI"]


class TestQueryAuditCarriesRedirect:
    """`client_redirect` reaches `MCPQueryLog` through the executor threading,
    on both an allowed row and the operator-misconfig row."""

    def test_allowed_row_carries_client_redirect(self, db, monkeypatch, mcp_user):
        from types import SimpleNamespace

        from mcp_sql import executor
        from mcp_sql.models import MCPQueryLog

        # `limit=0` short-circuits before any DB work; it only needs the
        # readonly alias present in `connections.databases`.
        monkeypatch.setattr(
            executor, "connections", SimpleNamespace(databases={"mcp_readonly": {}})
        )
        profile = mcp_sql_settings.profiles()["default"]
        result = executor.run_query(
            user=mcp_user,
            profile=profile,
            raw_sql="SELECT 1",
            limit=0,
            client_redirect=CLAUDE["REDIRECT_URI"],
        )
        assert result.row_count == 0
        row = MCPQueryLog.objects.get()
        assert row.decision == MCPQueryLog.DECISION_ALLOWED
        assert row.client_redirect == CLAUDE["REDIRECT_URI"]

    def test_misconfig_row_carries_client_redirect(self, db, mcp_user):
        from mcp_sql.executor import ExecutorMisconfiguredError
        from mcp_sql.executor import run_query
        from mcp_sql.models import MCPQueryLog

        # The test settings deliberately omit the `mcp_readonly` alias, so
        # run_query takes the misconfig path — which must still carry the field.
        profile = mcp_sql_settings.profiles()["default"]
        with pytest.raises(ExecutorMisconfiguredError):
            run_query(
                user=mcp_user,
                profile=profile,
                raw_sql="SELECT 1",
                client_redirect=CLAUDE["REDIRECT_URI"],
            )
        row = MCPQueryLog.objects.get()
        assert row.client_redirect == CLAUDE["REDIRECT_URI"]
