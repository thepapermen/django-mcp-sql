"""Declared (non-DCR) MCP clients.

Covers the settings validation, the kind/client_id derivation and its
mixed-scheme rejection, settings-gated recognition, the `post_migrate`
provisioning receiver, the prefix `validate_redirect_uri` override + its
hardened helper, logout revocation, and the client attribution written onto
both audit tables.

Deliberately does NOT touch the loopback DCR path: `/o/register` stays
loopback-only and its invariants remain pinned by `test_registration.py`. If a
change here ever required editing those, that is the signal the cornerstone was
weakened — it must not be.
"""

import logging
import secrets
from datetime import timedelta
from io import StringIO

import pytest
from django.apps import apps as django_apps
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.utils import timezone
from mcp_sql.auth import MCPOAuth2Authentication
from mcp_sql.clients import REDIRECT_MAX_LENGTH
from mcp_sql.clients import ClientKind
from mcp_sql.clients import RedirectRule
from mcp_sql.clients import derive_kind
from mcp_sql.clients import redirect_rules
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import classify_application_name
from mcp_sql.consts import identify_application
from mcp_sql.consts import is_mcp_application_name
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.oauth import _redirect_under_prefix
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.signals import _revoke_and_audit_on_logout
from mcp_sql.signals import provision_mcp_clients
from mcp_sql.validation import validate_mcp_sql_settings
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

CLAUDE = {
    "LABEL": "Claude.ai",
    "REDIRECTS": [
        {"MATCH": "exact", "URI": "https://claude.ai/api/mcp/auth_callback"},
    ],
}
CHATGPT = {
    "LABEL": "ChatGPT",
    "REDIRECTS": [
        {"MATCH": "prefix", "URI": "https://chatgpt.com/connector/oauth/"},
    ],
}
# The documented-but-not-shipped stopgap for Cursor's static `mcp.json` path:
# its desktop app and CLI pin a fixed loopback port.
CURSOR_DESKTOP = {
    "LABEL": "Cursor Desktop",
    "REDIRECTS": [{"MATCH": "exact", "URI": "http://localhost:8787/callback"}],
}

CLAUDE_ID = "mcp-sql-cloud.claude"
CHATGPT_ID = "mcp-sql-cloud.chatgpt"
CURSOR_ID = "mcp-sql-cloud.cursor"
CURSOR_DESKTOP_ID = "mcp-sql-local.cursor-desktop"

CLAUDE_URI = CLAUDE["REDIRECTS"][0]["URI"]
CHATGPT_PREFIX = CHATGPT["REDIRECTS"][0]["URI"]


def _cfg(clients):
    """The test-settings MCP_SQL dict with CLIENTS spliced in."""
    return {**django_settings.MCP_SQL, "CLIENTS": clients}


def _provision(settings, clients):
    """Set CLIENTS and run the real provisioning receiver (mirrors how the
    `two_profiles` fixture drives `provision_mcp_profiles`)."""
    settings.MCP_SQL = _cfg(clients)
    provision_mcp_clients(sender=django_apps.get_app_config("mcp_sql"))


def _bearer_request(token: str):
    return APIRequestFactory().post("/mcp/sql/", HTTP_AUTHORIZATION=f"Bearer {token}")


# --------------------------------------------------------------------------- #
# Settings validation                                                         #
# --------------------------------------------------------------------------- #


class TestClientValidation:
    def test_empty_is_valid_feature_off(self):
        validate_mcp_sql_settings(_cfg({}))  # no raise

    def test_shipped_defaults_validate(self):
        # The defaults are merged in and validated on every boot, so a typo in
        # `conf.DEFAULTS["CLIENTS"]` would break every install. Pin it here too,
        # explicitly, rather than relying on it being incidental to other tests.
        validate_mcp_sql_settings({})  # no raise

    def test_no_scheme_declaration_is_needed(self, settings):
        """DOT's own default (`["http", "https"]`) already covers both shapes
        this package admits, so a consumer never has to declare
        ALLOWED_REDIRECT_URI_SCHEMES — including for the shipped clients. The
        guard reads DOT's resolved value, so an undeclared key is the default,
        not an empty list."""
        settings.OAUTH2_PROVIDER = {
            k: v
            for k, v in settings.OAUTH2_PROVIDER.items()
            if k != "ALLOWED_REDIRECT_URI_SCHEMES"
        }
        validate_mcp_sql_settings({})  # no raise
        validate_mcp_sql_settings(_cfg({"cursor-desktop": CURSOR_DESKTOP}))  # no raise

    def test_seed_set_is_valid(self):
        validate_mcp_sql_settings(
            _cfg(
                {"claude": CLAUDE, "chatgpt": CHATGPT, "cursor-desktop": CURSOR_DESKTOP}
            )
        )  # no raise

    @pytest.mark.parametrize(
        "clients",
        [
            pytest.param({"Claude": CLAUDE}, id="uppercase-slug"),
            pytest.param({"1claude": CLAUDE}, id="slug-starts-digit"),
            pytest.param({"": CLAUDE}, id="empty-slug"),
            pytest.param({"claude": {**CLAUDE, "REDIRECTS": []}}, id="no-redirects"),
            pytest.param({"claude": {"LABEL": "x"}}, id="missing-redirects"),
            pytest.param(
                {"claude": {"REDIRECTS": [{"URI": CLAUDE_URI}]}}, id="no-match"
            ),
            pytest.param(
                {"claude": {"REDIRECTS": [{"MATCH": "fuzzy", "URI": CLAUDE_URI}]}},
                id="bad-match",
            ),
            pytest.param(
                {"claude": {"REDIRECTS": [{"MATCH": "exact", "URI": "ftp://x/cb"}]}},
                id="unsupported-scheme",
            ),
            pytest.param(
                {
                    "cursor": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "cursor://anysphere/callback"}
                        ]
                    }
                },
                id="custom-scheme",
            ),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [{"MATCH": "exact", "URI": "http://claude.ai/cb"}]
                    }
                },
                id="http-non-loopback",
            ),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "https://u:p@claude.ai/cb"}
                        ]
                    }
                },
                id="userinfo",
            ),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [{"MATCH": "exact", "URI": "https://claude.ai/*"}]
                    }
                },
                id="wildcard",
            ),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "https://claude.ai/a/../b"}
                        ]
                    }
                },
                id="traversal",
            ),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "https://claude.ai/a/%2e%2e/b"}
                        ]
                    }
                },
                id="encoded-traversal",
            ),
            pytest.param(
                {
                    "chatgpt": {
                        "REDIRECTS": [{"MATCH": "prefix", "URI": "https://chatgpt.com"}]
                    }
                },
                id="prefix-without-path",
            ),
            pytest.param(
                {
                    "chatgpt": {
                        "REDIRECTS": [
                            {
                                "MATCH": "prefix",
                                "URI": "https://chatgpt.com/connector/oauth",
                            }
                        ]
                    }
                },
                id="prefix-without-trailing-slash",
            ),
            pytest.param(
                {
                    "local": {
                        "REDIRECTS": [{"MATCH": "exact", "URI": "http://localhost/cb"}]
                    }
                },
                id="loopback-without-port",
            ),
            pytest.param(
                {
                    "local": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "http://localhost:8787"}
                        ]
                    }
                },
                id="loopback-without-path",
            ),
            pytest.param(
                {
                    "local": {
                        "REDIRECTS": [
                            {"MATCH": "prefix", "URI": "http://localhost:8787/cb/"}
                        ]
                    }
                },
                id="loopback-prefix-matching",
            ),
            pytest.param(
                {
                    "local": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "http://127.0.0.1:8787/cb"}
                        ]
                    }
                },
                id="loopback-ip-literal",
            ),
            pytest.param(
                {"claude": {"REDIRECTS": [{"MATCH": "exact", "URI": "https:///cb"}]}},
                id="hostless-https",
            ),
            pytest.param(
                {
                    "local": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "http://localhost:notaport/cb"}
                        ]
                    }
                },
                id="malformed-port",
            ),
        ],
    )
    def test_invalid_entries_rejected(self, clients):
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(_cfg(clients))

    def test_mixed_scheme_entry_rejected(self):
        # The load-bearing invariant: one client_id must not span a
        # provider-hosted and a machine-local surface, because the audit trail
        # could then not tell the two apart. Declare two entries instead.
        mixed = {
            "cursor": {
                "REDIRECTS": [
                    {
                        "MATCH": "exact",
                        "URI": "https://www.cursor.com/agents/mcp/oauth/callback",
                    },
                    {"MATCH": "exact", "URI": "http://localhost:8787/callback"},
                ]
            }
        }
        with pytest.raises(ImproperlyConfigured, match="mixes https and loopback"):
            validate_mcp_sql_settings(_cfg(mixed))

    def test_removed_cloud_clients_key_is_a_loud_error(self):
        # Silently ignoring the old key would empty CLIENTS, de-recognise the
        # consumer's declared clients, and start rejecting their live tokens at
        # the next request. Fail at boot, naming the rename.
        stale = {**django_settings.MCP_SQL, "CLOUD_CLIENTS": [{"NAME": "claude"}]}
        with pytest.raises(ImproperlyConfigured, match="renamed to CLIENTS"):
            validate_mcp_sql_settings(stale)

    def test_unknown_key_rejected(self):
        with pytest.raises(ImproperlyConfigured, match="Invalid MCP_SQL settings"):
            validate_mcp_sql_settings({"CLEINTS": {}})

    def test_unknown_nested_key_rejected(self):
        with pytest.raises(ImproperlyConfigured, match="Invalid MCP_SQL settings"):
            validate_mcp_sql_settings(
                _cfg({"claude": {**CLAUDE, "REDIRECT_URI": CLAUDE_URI}})
            )

    def test_https_client_requires_https_in_scheme_allowlist(self, settings):
        # DOT enforces this list when it issues the 302, so a mismatch fails
        # opaquely at /o/authorize/ — catch it at boot instead.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],
        }
        with pytest.raises(ImproperlyConfigured, match="ALLOWED_REDIRECT_URI_SCHEMES"):
            validate_mcp_sql_settings(_cfg({"claude": CLAUDE}))

    def test_prefix_only_config_also_requires_https(self, settings):
        # A prefix client's redirect override bypasses DOT's allowlist at
        # request time, but the requirement is applied uniformly so the config
        # can't silently break the day an exact client is added.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],
        }
        with pytest.raises(ImproperlyConfigured, match="ALLOWED_REDIRECT_URI_SCHEMES"):
            validate_mcp_sql_settings(_cfg({"chatgpt": CHATGPT}))

    def test_local_client_requires_http_in_scheme_allowlist(self, settings):
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["https"],
        }
        with pytest.raises(ImproperlyConfigured, match="ALLOWED_REDIRECT_URI_SCHEMES"):
            validate_mcp_sql_settings(_cfg({"cursor-desktop": CURSOR_DESKTOP}))

    def test_clients_boot_when_both_schemes_allowed(self, settings):
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],
        }
        validate_mcp_sql_settings(
            _cfg({"claude": CLAUDE, "cursor-desktop": CURSOR_DESKTOP})
        )  # no raise


class TestBuilderGuardsStandAlone:
    """`clients.build_clients` re-checks what `validation` already rejected.

    In a booted process these branches are unreachable: `_validate_clients`
    runs first and produces the richer operator-facing message. They are the
    backstop for the paths that skip boot validation — `@override_settings` in
    a test, a `settings.MCP_SQL` assignment at runtime — where the accessor
    would otherwise build a nonsense client rather than failing. Exercised
    directly, since by construction nothing else can reach them.
    """

    def test_unsupported_scheme_raises(self):
        rules = (RedirectRule(match="exact", uri="ftp://x/cb"),)
        with pytest.raises(ValueError, match="neither an https callback"):
            derive_kind("x", rules)

    def test_mixed_schemes_raise(self):
        rules = (
            RedirectRule(match="exact", uri="https://x.example/cb"),
            RedirectRule(match="exact", uri="http://localhost:8787/cb"),
        )
        with pytest.raises(ValueError, match="mixes https and loopback"):
            derive_kind("x", rules)

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param({"REDIRECTS": [{"URI": CLAUDE_URI}]}, id="missing-match"),
            pytest.param({"REDIRECTS": ["not-a-mapping"]}, id="rule-not-a-mapping"),
        ],
    )
    def test_malformed_rule_raises(self, entry):
        with pytest.raises(ValueError, match="needs a MATCH and a URI"):
            redirect_rules("x", entry)

    def test_missing_redirects_raises(self):
        with pytest.raises(ValueError, match="non-empty REDIRECTS list"):
            redirect_rules("x", {"LABEL": "no rules"})


# --------------------------------------------------------------------------- #
# Derivation + settings-gated recognition                                     #
# --------------------------------------------------------------------------- #


class TestClientDerivation:
    def test_namespace_and_kind_come_from_the_redirect_scheme(self, settings):
        settings.MCP_SQL = _cfg(
            {"claude": CLAUDE, "chatgpt": CHATGPT, "cursor-desktop": CURSOR_DESKTOP}
        )
        clients = mcp_sql_settings.clients()
        assert set(clients) == {CLAUDE_ID, CHATGPT_ID, CURSOR_DESKTOP_ID}
        assert clients[CLAUDE_ID].kind is ClientKind.CLOUD
        assert clients[CURSOR_DESKTOP_ID].kind is ClientKind.LOCAL
        assert clients[CHATGPT_ID].prefixes == (CHATGPT_PREFIX,)
        # An "exact" rule is never offered to the prefix matcher.
        assert clients[CLAUDE_ID].prefixes == ()

    def test_label_defaults_to_the_slug(self, settings):
        settings.MCP_SQL = _cfg({"claude": {"REDIRECTS": CLAUDE["REDIRECTS"]}})
        assert mcp_sql_settings.clients()[CLAUDE_ID].label == "claude"

    def test_ships_on_by_default(self, settings):
        settings.MCP_SQL = {
            k: v for k, v in django_settings.MCP_SQL.items() if k != "CLIENTS"
        }
        assert set(mcp_sql_settings.clients()) == {CLAUDE_ID, CHATGPT_ID, CURSOR_ID}

    def test_empty_dict_turns_them_all_off(self, settings):
        settings.MCP_SQL = _cfg({})
        assert mcp_sql_settings.clients() == {}


class TestRecognition:
    def test_recognised_only_while_in_settings(self, settings):
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        assert is_mcp_application_name(CLAUDE_ID) is True
        # Fail-closed: removing the entry de-recognises it at the next read.
        settings.MCP_SQL = _cfg({})
        assert is_mcp_application_name(CLAUDE_ID) is False

    def test_classification_covers_every_kind(self, settings):
        settings.MCP_SQL = _cfg({"claude": CLAUDE, "cursor-desktop": CURSOR_DESKTOP})
        assert classify_application_name("mcp-sql") is ClientKind.CURATED
        assert classify_application_name("mcp-sql-" + "a" * 22) is ClientKind.DCR
        assert classify_application_name(CLAUDE_ID) is ClientKind.CLOUD
        assert classify_application_name(CURSOR_DESKTOP_ID) is ClientKind.LOCAL
        assert classify_application_name("some-other-app") is None

    def test_declared_id_is_disjoint_from_dcr_shape(self, settings):
        # The '.' after the kind means the suffix can never be a 22-char DCR
        # token, so a removed client can't leak back in via the DCR branch.
        settings.MCP_SQL = _cfg({})
        assert is_mcp_application_name(CLAUDE_ID) is False
        assert is_mcp_application_name(CURSOR_DESKTOP_ID) is False


# --------------------------------------------------------------------------- #
# Prefix redirect matching (security-critical)                                #
# --------------------------------------------------------------------------- #


_PREFIX = CHATGPT_PREFIX


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
            # A browser treats `\` as `/` in an https URL, so these are
            # traversal by another spelling (raw, then percent-encoded).
            pytest.param(
                "https://chatgpt.com/connector/oauth/..\\..\\evil",
                id="backslash-traversal",
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/..%5c..%5cevil",
                id="encoded-backslash-traversal",
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
        settings.MCP_SQL = _cfg({"chatgpt": CHATGPT})
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CHATGPT_ID,
                "https://chatgpt.com/connector/oauth/inst-42",
                request=None,
            )
            is True
        )

    def test_prefix_client_rejects_off_prefix(self, settings, monkeypatch):
        from oauth2_provider.oauth2_validators import OAuth2Validator

        # Pin super() to False so this asserts the override's own verdict, not
        # DOT's stock lookup of a client_id with no Application row.
        monkeypatch.setattr(
            OAuth2Validator, "validate_redirect_uri", lambda self, *a, **k: False
        )
        settings.MCP_SQL = _cfg({"chatgpt": CHATGPT})
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CHATGPT_ID, "https://evil.com/x", request=None
            )
            is False
        )

    def test_exact_client_delegates_to_super_never_prefix_matching(
        self, settings, monkeypatch
    ):
        # Load-bearing scoping: a client with no prefix rules must fall through
        # to DOT's stock (exact) matching. Widening the override to every
        # declared client would silently loosen exact clients — this pins it.
        from oauth2_provider.oauth2_validators import OAuth2Validator

        settings.MCP_SQL = _cfg({"claude": CLAUDE})
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
            CLAUDE_ID, CLAUDE_URI, request=None
        )
        assert result == "DELEGATED-TO-SUPER"  # rode DOT stock matching
        assert prefix_calls == []  # the prefix override was never touched

    @pytest.mark.parametrize(
        "attacker_uri",
        [
            "https://evil.example/cb",
            "https://claude.ai.evil.example/api/mcp/auth_callback",
            "https://claude.ai@evil.example/api/mcp/auth_callback",
            "http://claude.ai/api/mcp/auth_callback",
        ],
    )
    def test_shipped_client_id_cannot_be_pointed_elsewhere(
        self, db, settings, attacker_uri
    ):
        """The whole safety case for shipping clients ON.

        Their client_ids are derived and therefore public — anyone can guess
        `mcp-sql-cloud.claude`. What stops a phished `/o/authorize/` link from
        delivering a victim's code to the attacker is that the redirect is
        bound to the provisioned callback. No stubbing here: this runs the
        real validator against the real provisioned Application.
        """
        from types import SimpleNamespace

        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        # DOT reads the bound Application off the oauthlib request, which the
        # authorization endpoint has already resolved from the client_id.
        oauthlib_request = SimpleNamespace(
            client=Application.objects.get(client_id=CLAUDE_ID)
        )
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CLAUDE_ID, attacker_uri, request=oauthlib_request
            )
            is False
        )

    def test_shipped_client_id_accepts_its_own_callback(self, db, settings):
        """The other half: the binding must not be so tight it breaks the real
        client."""
        from types import SimpleNamespace

        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        oauthlib_request = SimpleNamespace(
            client=Application.objects.get(client_id=CLAUDE_ID)
        )
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CLAUDE_ID, CLAUDE_URI, request=oauthlib_request
            )
            is True
        )

    def test_mixed_rules_still_accept_the_exact_callback(self, settings, monkeypatch):
        # Regression pin for the `or super()` fallthrough. A client carrying
        # BOTH prefix and exact rules has its exact callbacks matched by DOT,
        # not by the prefix helper — returning the prefix verdict alone would
        # reject them.
        from oauth2_provider.oauth2_validators import OAuth2Validator

        both = {
            "chatgpt": {
                "REDIRECTS": [
                    *CHATGPT["REDIRECTS"],
                    {"MATCH": "exact", "URI": "https://chatgpt.com/aip/connect/oauth"},
                ]
            }
        }
        settings.MCP_SQL = _cfg(both)
        monkeypatch.setattr(
            OAuth2Validator, "validate_redirect_uri", lambda self, *a, **k: True
        )
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CHATGPT_ID, "https://chatgpt.com/aip/connect/oauth", request=None
            )
            is True
        )


# --------------------------------------------------------------------------- #
# Provisioning                                                                 #
# --------------------------------------------------------------------------- #


class TestProvisioning:
    def test_creates_rows_with_curated_posture(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE, "chatgpt": CHATGPT})
        app = Application.objects.get(client_id=CLAUDE_ID)
        assert app.name == CLAUDE_ID
        # Public + PKCE: no client_secret is used at the token endpoint. (DOT
        # hashes whatever secret string is stored, so asserting the raw column
        # is `""` is meaningless — `client_type` is the load-bearing invariant.)
        assert app.client_type == Application.CLIENT_PUBLIC
        assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
        # Consent is load-bearing for a fixed, shared redirect.
        assert app.skip_authorization is False
        assert app.redirect_uris == CLAUDE_URI
        assert Application.objects.filter(client_id=CHATGPT_ID).exists()

    def test_every_rule_is_registered(self, db, settings):
        from oauth2_provider.models import Application

        multi = {
            "chatgpt": {
                "REDIRECTS": [
                    *CHATGPT["REDIRECTS"],
                    {"MATCH": "exact", "URI": "https://chatgpt.com/aip/connect/oauth"},
                ]
            }
        }
        _provision(settings, multi)
        app = Application.objects.get(client_id=CHATGPT_ID)
        # DOT stores the allowed set space-joined; both must survive, or the
        # exact callback is rejected at /o/authorize/.
        assert app.redirect_uris.split() == [
            CHATGPT_PREFIX,
            "https://chatgpt.com/aip/connect/oauth",
        ]

    def test_is_idempotent(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        _provision(settings, {"claude": CLAUDE})
        assert Application.objects.filter(client_id=CLAUDE_ID).count() == 1

    def test_provisioning_logs_the_client_id_to_paste(self, db, settings, caplog):
        # Discoverability: `migrate` surfaces the derived client_id operators
        # must paste into the provider connector.
        with caplog.at_level(logging.INFO, logger="mcp_sql.signals"):
            _provision(settings, {"claude": CLAUDE})
        assert CLAUDE_ID in caplog.text
        assert CLAUDE_URI in caplog.text

    def test_redirect_change_syncs_on_reprovision(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        moved = {
            "claude": {
                "REDIRECTS": [
                    {
                        "MATCH": "exact",
                        "URI": "https://claude.com/api/mcp/auth_callback",
                    }
                ]
            }
        }
        _provision(settings, moved)
        app = Application.objects.get(client_id=CLAUDE_ID)
        assert app.redirect_uris == "https://claude.com/api/mcp/auth_callback"

    def test_removed_entry_leaves_row_but_recognition_denies(self, db, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        settings.MCP_SQL = _cfg({})  # remove; row is deliberately NOT deleted
        assert Application.objects.filter(client_id=CLAUDE_ID).exists()
        assert is_mcp_application_name(CLAUDE_ID) is False

    def test_stale_row_is_named_in_a_warning(self, db, settings, caplog):
        # Deleting would cascade live tokens mid-migrate, so provisioning
        # reports instead of acting.
        _provision(settings, {"claude": CLAUDE})
        with caplog.at_level(logging.WARNING, logger="mcp_sql.signals"):
            _provision(settings, {"chatgpt": CHATGPT})
        assert CLAUDE_ID in caplog.text

    def test_curated_and_dcr_rows_are_never_called_stale(self, db, settings, caplog):
        from oauth2_provider.models import Application

        dcr_name = "mcp-sql-" + "a" * 22
        for name in ("mcp-sql", dcr_name):
            Application.objects.update_or_create(
                client_id=name,
                defaults={
                    "name": name,
                    "client_secret": "",
                    "client_type": Application.CLIENT_PUBLIC,
                    "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
                    "redirect_uris": "http://127.0.0.1:1234/cb",
                    "algorithm": "",
                },
            )
        with caplog.at_level(logging.WARNING, logger="mcp_sql.signals"):
            _provision(settings, {"claude": CLAUDE})
        # The stale scan matches the two declared namespaces only. Quoted, so
        # this does not accidentally match `'mcp-sql-cloud.…'` substrings — a
        # bare `in` check would pass no matter what the scan did.
        assert "'mcp-sql'" not in caplog.text
        assert repr(dcr_name) not in caplog.text


# --------------------------------------------------------------------------- #
# Logout revocation + audit attribution                                       #
# --------------------------------------------------------------------------- #


def _declared_token(user, client_id):
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


class TestLogoutRevocation:
    def test_logout_revokes_declared_tokens_via_prefix(self, db, settings, mcp_user):
        from oauth2_provider.models import AccessToken

        _provision(settings, {"claude": CLAUDE})
        token = _declared_token(mcp_user, CLAUDE_ID)
        _revoke_and_audit_on_logout(
            user=mcp_user, client_ip=None, logged_out_at=timezone.now()
        )
        assert not AccessToken.objects.filter(pk=token.pk).exists()


class TestClientsCommand:
    """`manage.py mcp_sql_clients` — the operator's copy-paste source for a
    provider connector's OAuth Client ID."""

    def _run(self, settings, clients):
        settings.MCP_SQL = _cfg(clients)
        out = StringIO()
        call_command("mcp_sql_clients", stdout=out)
        return out.getvalue()

    def test_prints_every_client_with_its_callbacks(self, settings):
        output = self._run(settings, {"claude": CLAUDE, "chatgpt": CHATGPT})
        # The client_id is the whole point — it is what gets pasted.
        assert CLAUDE_ID in output
        assert CHATGPT_ID in output
        assert CLAUDE_URI in output
        assert f"{CHATGPT_PREFIX} (prefix)" in output
        assert "Claude.ai" in output  # the operator-authored label
        assert "cloud" in output  # the derived kind
        # No secret is ever issued for these; say so rather than leaving the
        # operator to guess what to put in the provider's secret field.
        assert "leave blank" in output

    def test_local_client_reports_its_derived_kind(self, settings):
        output = self._run(settings, {"cursor-desktop": CURSOR_DESKTOP})
        assert CURSOR_DESKTOP_ID in output
        assert "local" in output

    def test_empty_clients_explains_the_surface_is_loopback_only(self, settings):
        output = self._run(settings, {})
        assert "empty" in output
        assert "/o/register" in output
        assert "mcp-sql-cloud" not in output


class TestClientIdentity:
    def test_registered_redirect_is_truncated_to_the_column_width(self, db, settings):
        # An Application with many registered URIs would otherwise overflow the
        # audit column, raise DataError inside the best-effort writers, and
        # lose the row entirely.
        from mcp_sql.models import MCPAuthRejectionLog
        from mcp_sql.models import MCPQueryLog
        from oauth2_provider.models import Application

        for model in (MCPQueryLog, MCPAuthRejectionLog):
            assert (
                model._meta.get_field("client_redirect").max_length
                == REDIRECT_MAX_LENGTH
            )
        # `update_or_create`: the shipped default clients are provisioned into
        # the test database by the real `post_migrate` receiver, so this row
        # already exists.
        app, _ = Application.objects.update_or_create(
            client_id=CLAUDE_ID,
            defaults={
                "name": CLAUDE_ID,
                "client_secret": "",
                "client_type": Application.CLIENT_PUBLIC,
                "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
                "redirect_uris": " ".join(
                    f"https://claude.ai/cb/{i:04d}" for i in range(200)
                ),
                "algorithm": "",
            },
        )
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        identity = identify_application(app)
        assert len(identity.redirect) == REDIRECT_MAX_LENGTH
        assert identity.kind == ClientKind.CLOUD

    def test_no_application_yields_the_blank_identity(self):
        # The "no token in hand" case (e.g. the logout-driven revocation rows),
        # matching the models' blank defaults.
        identity = identify_application(None)
        assert (identity.name, identity.kind, identity.redirect) == ("", "", "")

    def test_unrecognised_application_gets_a_blank_kind(self, settings):
        from types import SimpleNamespace

        settings.MCP_SQL = _cfg({})
        identity = identify_application(
            SimpleNamespace(name="some-other-app", redirect_uris="https://x/cb")
        )
        assert identity.kind == ""
        assert identity.name == "some-other-app"


@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestAuthRejectionAttribution:
    def test_removed_client_denied_and_audited_with_attribution(
        self, db, settings, mcp_user
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        _provision(settings, {"claude": CLAUDE})
        token = _declared_token(mcp_user, CLAUDE_ID)
        # Drop the client from settings; the Application row still exists, so
        # DOT resolves the token, but recognition is now fail-closed.
        settings.MCP_SQL = _cfg({})
        with pytest.raises(exceptions.AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.BAD_APPLICATION
        assert row.application_name == CLAUDE_ID
        assert row.client_redirect == CLAUDE_URI
        # De-recognised, so it classifies as nothing — recorded honestly rather
        # than back-filled with the kind it used to have.
        assert row.client_kind == ""


class TestQueryAuditAttribution:
    """The client identity reaches `MCPQueryLog` through the executor
    threading, on both an allowed row and the operator-misconfig row."""

    def _identity(self, settings):
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        from types import SimpleNamespace

        return identify_application(
            SimpleNamespace(name=CLAUDE_ID, redirect_uris=CLAUDE_URI)
        )

    def test_allowed_row_carries_client_attribution(
        self, db, settings, monkeypatch, mcp_user
    ):
        from types import SimpleNamespace

        from mcp_sql import executor
        from mcp_sql.models import MCPQueryLog

        # `limit=0` short-circuits before any DB work; it only needs the
        # readonly alias present in `connections.databases`.
        monkeypatch.setattr(
            executor, "connections", SimpleNamespace(databases={"mcp_readonly": {}})
        )
        result = executor.run_query(
            user=mcp_user,
            profile=mcp_sql_settings.profiles()["default"],
            raw_sql="SELECT 1",
            limit=0,
            client=self._identity(settings),
        )
        assert result.row_count == 0
        row = MCPQueryLog.objects.get()
        assert row.decision == MCPQueryLog.DECISION_ALLOWED
        assert row.application_name == CLAUDE_ID
        assert row.client_kind == ClientKind.CLOUD
        assert row.client_redirect == CLAUDE_URI

    def test_misconfig_row_carries_client_attribution(self, db, settings, mcp_user):
        from mcp_sql.executor import ExecutorMisconfiguredError
        from mcp_sql.executor import run_query
        from mcp_sql.models import MCPQueryLog

        # The test settings deliberately omit the `mcp_readonly` alias, so
        # run_query takes the misconfig path — which must still carry the
        # attribution.
        with pytest.raises(ExecutorMisconfiguredError):
            run_query(
                user=mcp_user,
                profile=mcp_sql_settings.profiles()["default"],
                raw_sql="SELECT 1",
                client=self._identity(settings),
            )
        row = MCPQueryLog.objects.get()
        assert row.application_name == CLAUDE_ID
        assert row.client_kind == ClientKind.CLOUD


@pytest.mark.django_db
class TestReviewFindings:
    """Regression cover for the findings of the 0.2.0b1 adversarial review.

    Each of these was reachable in the shipped code and silent — none of them
    failed a test before being fixed.
    """

    @staticmethod
    def _https_client(host):
        return {"x": {"REDIRECTS": [{"MATCH": "exact", "URI": f"https://{host}/cb"}]}}

    @pytest.mark.parametrize(
        ("host", "reason"),
        [
            # Special-use suffixes that only ever resolve locally: RFC 6761
            # `localhost` (and its FQDN root form and subdomains), RFC 6762
            # mDNS `.local`, RFC 8375 `.home.arpa`, ICANN's `.internal`, and the
            # `localdomain*` pseudo-TLDs of the stock /etc/hosts aliases.
            ("localhost", "local-scope name"),
            ("localhost.", "local-scope name"),
            ("app.localhost", "local-scope name"),
            ("laptop.local", "local-scope name"),
            ("printer.home.arpa", "local-scope name"),
            ("svc.corp.internal", "local-scope name"),
            ("localhost.localdomain", "local-scope name"),
            ("localhost4.localdomain4", "local-scope name"),
            ("localhost6.localdomain6", "local-scope name"),
            # Every single-label name — it can only resolve through /etc/hosts
            # or a search domain. This is what catches the distro aliases a
            # hand-written list missed (Fedora's `localhost4`, found by the
            # review), plus `ip6-localhost` and the machine's own hostname.
            ("localhost4", "fully-qualified"),
            ("localhost4.", "fully-qualified"),
            ("LOCALHOST4", "fully-qualified"),
            ("localhost6", "fully-qualified"),
            ("ip6-localhost", "fully-qualified"),
            ("ip6-loopback", "fully-qualified"),
            ("myhost", "fully-qualified"),
            # Every IPv4 literal, loopback or not — including the abbreviated,
            # hex and integer forms the resolver (and every browser) accepts
            # but `ipaddress` does not, and the unspecified `0` / `0.0.0.0`.
            ("127.0.0.1", "IP-literal"),
            ("127.0.0.2", "IP-literal"),
            ("127.1", "IP-literal"),
            ("0x7f.1", "IP-literal"),
            ("2130706433", "IP-literal"),
            ("0", "IP-literal"),
            ("0.0.0.0", "IP-literal"),  # noqa: S104 — a host under test, not a bind
            ("127.0.0.1.", "IP-literal"),
            ("8.8.8.8", "IP-literal"),
            # IPv6 literals, refused by shape. The IPv4-mapped forms are the
            # ones `ipaddress` on Python 3.12.3 does not call loopback, which
            # is what failed this test there under the old detector.
            ("[::1]", "ASCII DNS name"),
            ("[::ffff:127.0.0.1]", "ASCII DNS name"),
            ("[::ffff:7f00:1]", "ASCII DNS name"),
            # Spellings that are not a plain DNS name at all: percent-encoded,
            # fullwidth digits / letters, the ideographic full stop, and a
            # non-ASCII IDN (admissible only as its punycode A-label).
            ("%6c%6fcalhost", "ASCII DNS name"),
            ("127.0.0.%31", "ASCII DNS name"),
            ("\uff11\uff12\uff17.0.0.1", "ASCII DNS name"),
            ("127\u30020\u30020\u30021", "ASCII DNS name"),
            (
                "\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54",
                "ASCII DNS name",
            ),
            ("b\u00fccher.example", "punycode"),
            ("under_score.example", "ASCII DNS name"),
        ],
    )
    def test_https_host_must_be_a_plain_dns_name(self, host, reason):
        """`redirect_kind` derives `cloud` from the SCHEME, so an https
        callback whose host is really the user's machine would be namespaced
        and audited as provider-hosted while the browser following the redirect
        delivers the code locally. The derivation is what makes `client_kind`
        trustworthy, so the two must not be able to disagree.

        A loopback *detector* lost to every spelling it did not enumerate
        (percent-encoding, fullwidth forms, `0`, `*.localhost`, and on Python
        3.12.3 IPv4-mapped IPv6), so the rule is an allow-shape: a
        fully-qualified ASCII DNS name, no IP literal of any kind, not under a
        special-use suffix that only resolves locally.
        """
        with pytest.raises(ImproperlyConfigured, match=reason):
            validate_mcp_sql_settings({"CLIENTS": self._https_client(host)})

    @pytest.mark.parametrize(
        "host",
        [
            "a\x00b.example",  # NUL
            "\ud800.example",  # lone surrogate
        ],
    )
    def test_unencodable_host_is_a_config_error_not_a_crash(self, host):
        # These used to escape boot validation as a bare `ValueError` /
        # `UnicodeEncodeError` (raised by `socket.inet_aton`) instead of the
        # focused `ImproperlyConfigured` naming the URI.
        with pytest.raises(ImproperlyConfigured, match="ASCII DNS name"):
            validate_mcp_sql_settings({"CLIENTS": self._https_client(host)})

    @pytest.mark.parametrize(
        "uri",
        [
            # The shipped callbacks, verbatim.
            "https://claude.ai/api/mcp/auth_callback",
            "https://chatgpt.com/connector/oauth/",
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "https://p.example/cb",
            # An IDN in its punycode A-label form, a name that merely STARTS
            # with a loopback label, an all-digit label that is not the last
            # one, an explicit port, the FQDN root form, and an uppercase host
            # (`urlparse` lowercases it).
            "https://xn--bcher-kva.example/cb",
            "https://localhost.evil.example/cb",
            "https://local.example/cb",
            "https://home.arpa.example/cb",
            "https://127.example/cb",
            "https://p.example:8443/cb",
            "https://claude.ai./cb",
            "https://Claude.AI/cb",
        ],
    )
    def test_a_real_provider_callback_still_validates(self, uri):
        # The guard must not catch a genuine provider callback.
        validate_mcp_sql_settings(
            {"CLIENTS": {"provider": {"REDIRECTS": [{"MATCH": "exact", "URI": uri}]}}}
        )

    def test_declared_redirect_may_not_carry_whitespace(self):
        # Declared clients are stored with the same `" ".join(...)` that DOT
        # later splits, so embedded whitespace would register a second,
        # never-validated URI — the operator-side twin of the DCR smuggling
        # hole pinned in `test_registration.TestWhitespaceSmuggling`.
        cfg = {
            "sloppy": {
                "REDIRECTS": [
                    {"MATCH": "exact", "URI": "https://p.example/cb https://evil/x"}
                ]
            }
        }
        with pytest.raises(ImproperlyConfigured, match="whitespace"):
            validate_mcp_sql_settings({"CLIENTS": cfg})

    def test_http_scheme_is_required_even_with_no_local_clients(self, settings):
        # `/o/register` is mounted unconditionally and only ever mints http
        # loopback callbacks, and DOT enforces the scheme list at the
        # authorization redirect rather than at boot. Narrowing the list to
        # https once every declared client is cloud used to boot clean and then
        # break Claude Code / Cursor desktop+CLI opaquely at /o/authorize/.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOWED_REDIRECT_URI_SCHEMES": ["https"],
        }
        with pytest.raises(ImproperlyConfigured, match="/o/register"):
            validate_mcp_sql_settings({"CLIENTS": {}})


def _dot_has_localhost_loopback() -> bool:
    from oauth2_provider.settings import DEFAULTS

    return "ALLOW_LOCALHOST_LOOPBACK" in DEFAULTS


@pytest.mark.django_db
@pytest.mark.skipif(
    not _dot_has_localhost_loopback(),
    reason="OAUTH2_PROVIDER['ALLOW_LOCALHOST_LOOPBACK'] exists from DOT 3.4",
)
class TestLocalhostLoopbackFlag:
    """DOT >= 3.4's `ALLOW_LOCALHOST_LOOPBACK=True` port-wildcards a
    registered `http://localhost` callback — the exact widening a declared
    `local` client's rules exist to forbid (`clients.LOOPBACK_HOST`)."""

    @staticmethod
    def _flag(settings, *, on):
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ALLOW_LOCALHOST_LOOPBACK": on,
        }

    def test_the_flag_really_widens_an_exact_localhost_rule(self, settings):
        # The premise, pinned through DOT's own matcher, so this class goes
        # red (rather than silently guarding nothing) if DOT ever changes what
        # the flag means.
        from oauth2_provider.models import Application

        app = Application(redirect_uris=CURSOR_DESKTOP["REDIRECTS"][0]["URI"])
        self._flag(settings, on=False)
        assert not app.redirect_uri_allowed("http://localhost:9999/callback")
        self._flag(settings, on=True)
        assert app.redirect_uri_allowed("http://localhost:9999/callback")

    def test_refused_when_a_local_client_is_declared(self, settings):
        self._flag(settings, on=True)
        with pytest.raises(ImproperlyConfigured, match="ALLOW_LOCALHOST_LOOPBACK"):
            validate_mcp_sql_settings(_cfg({"cursor-desktop": CURSOR_DESKTOP}))

    @pytest.mark.parametrize(
        "clients",
        [
            pytest.param(None, id="shipped-defaults"),
            pytest.param({}, id="no-clients"),
        ],
    )
    def test_left_alone_without_a_local_client(self, settings, clients):
        # Install-global, and it changes nothing else this package promises:
        # DCR and the curated Application already live with any-port loopback
        # via 127.0.0.1 / ::1. Vetoing it here would only break a consumer's
        # unrelated OAuth config.
        self._flag(settings, on=True)
        validate_mcp_sql_settings({} if clients is None else _cfg(clients))

    def test_off_is_fine_with_a_local_client(self, settings):
        self._flag(settings, on=False)
        validate_mcp_sql_settings(_cfg({"cursor-desktop": CURSOR_DESKTOP}))
