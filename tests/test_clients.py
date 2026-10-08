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
from mcp_sql.consts import classify_application
from mcp_sql.consts import classify_application_name
from mcp_sql.consts import identify_application
from mcp_sql.consts import is_mcp_application
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


def _row(name, client_id=None, redirect_uris=""):
    """An Application stand-in carrying what recognition and attribution
    read; `client_id` defaults to the name, as provisioning writes it."""
    from types import SimpleNamespace

    return SimpleNamespace(
        name=name,
        client_id=name if client_id is None else client_id,
        redirect_uris=redirect_uris,
    )


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

    @staticmethod
    def _max_slug(prefix="mcp-sql-"):
        from oauth2_provider.models import get_application_model

        meta = get_application_model()._meta
        width = min(
            meta.get_field("client_id").max_length, meta.get_field("name").max_length
        )
        return width - len(f"{prefix}cloud.")

    def test_slug_at_the_column_limit_is_accepted(self):
        slug = "a" * self._max_slug()
        validate_mcp_sql_settings(_cfg({slug: CLAUDE}))  # no raise
        validate_mcp_sql_settings(_cfg({slug: CURSOR_DESKTOP}))  # no raise

    @pytest.mark.parametrize("entry", [CLAUDE, CURSOR_DESKTOP], ids=["cloud", "local"])
    def test_slug_overflowing_the_client_id_column_is_refused_at_boot(self, entry):
        """A derived client_id longer than DOT's `Application.client_id`
        (255 on DOT 3.4) or `name` (255) used to pass boot and
        fail `migrate` with a DataError in `provision_mcp_clients`."""
        slug = "a" * (self._max_slug() + 1)
        with pytest.raises(ImproperlyConfigured, match="at most"):
            validate_mcp_sql_settings(_cfg({slug: entry}))

    def test_limit_accounts_for_the_prefix(self):
        prefix = "a-much-longer-application-prefix-"
        slug = "a" * (self._max_slug(prefix) + 1)
        validate_mcp_sql_settings(_cfg({slug: CLAUDE}))  # fits the default prefix
        with pytest.raises(ImproperlyConfigured, match="at most"):
            validate_mcp_sql_settings(
                {**_cfg({slug: CLAUDE}), "APPLICATION_NAME_PREFIX": prefix}
            )

    def test_the_largest_accepted_slug_really_provisions(self, db, settings):
        from oauth2_provider.models import Application

        slug = "a" * self._max_slug()
        validate_mcp_sql_settings(_cfg({slug: CLAUDE}))
        _provision(settings, {slug: CLAUDE})
        app = Application.objects.get(client_id=f"mcp-sql-cloud.{slug}")
        assert app.name == app.client_id

    # The curated and DCR client_ids are bounded the same way: migration 0005
    # writes `APPLICATION_NAME` to both columns, `/o/register` writes
    # `<APPLICATION_NAME_PREFIX><22-char token>`. Each used to pass boot and
    # fail the write with a DataError (`migrate`; a 500 from the anonymous
    # `/o/register`).

    @staticmethod
    def _width():
        from oauth2_provider import __version__ as dot_version
        from oauth2_provider.models import get_application_model

        meta = get_application_model()._meta
        width = min(
            meta.get_field("client_id").max_length, meta.get_field("name").max_length
        )
        # DOT 3.2 / 3.3 store client_id in 100 characters, 3.4 in 255.
        major_minor = tuple(int(p) for p in dot_version.split(".")[:2])
        assert width == (255 if major_minor >= (3, 4) else 100)
        return width

    def test_dcr_token_constants_agree(self):
        from mcp_sql.clients import DCR_SUFFIX_LENGTH
        from mcp_sql.clients import DCR_TOKEN_BYTES

        for _ in range(50):
            assert len(secrets.token_urlsafe(DCR_TOKEN_BYTES)) == DCR_SUFFIX_LENGTH

    def test_application_name_at_the_column_limit_is_accepted_and_writes(self, db):
        from oauth2_provider.models import Application

        name = "a" * self._width()
        validate_mcp_sql_settings({**_cfg({}), "APPLICATION_NAME": name})  # no raise
        Application.objects.create(
            name=name,
            client_id=name,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1",
        )

    def test_application_name_overflowing_the_columns_is_refused_at_boot(self):
        name = "a" * (self._width() + 1)
        with pytest.raises(ImproperlyConfigured, match="APPLICATION_NAME is"):
            validate_mcp_sql_settings({**_cfg({}), "APPLICATION_NAME": name})

    @pytest.mark.usefixtures("_isolated_mcp_cache")
    def test_dcr_prefix_at_the_column_limit_really_registers(
        self, db, client, settings
    ):
        import json

        from django.urls import reverse
        from mcp_sql.clients import DCR_SUFFIX_LENGTH
        from oauth2_provider.models import Application

        prefix = "p" * (self._width() - DCR_SUFFIX_LENGTH - 1) + "-"
        config = {**_cfg({}), "APPLICATION_NAME_PREFIX": prefix}
        validate_mcp_sql_settings(config)  # no raise
        settings.MCP_SQL = config
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data=json.dumps({"redirect_uris": ["http://127.0.0.1:3456/callback"]}),
            content_type="application/json",
        )
        assert response.status_code == 201, response.content
        client_id = response.json()["client_id"]
        assert len(client_id) == self._width()
        app = Application.objects.get(client_id=client_id)
        assert app.name == client_id
        assert classify_application(app) is ClientKind.DCR

    @pytest.mark.parametrize("clients", [{}, {"claude": CLAUDE}], ids=["none", "one"])
    def test_dcr_prefix_overflowing_the_columns_is_refused_at_boot(self, clients):
        from mcp_sql.clients import DCR_SUFFIX_LENGTH

        prefix = "p" * (self._width() - DCR_SUFFIX_LENGTH) + "-"
        with pytest.raises(ImproperlyConfigured, match="APPLICATION_NAME_PREFIX is"):
            validate_mcp_sql_settings(
                {**_cfg(clients), "APPLICATION_NAME_PREFIX": prefix}
            )

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
        assert is_mcp_application(_row(CLAUDE_ID)) is True
        # Fail-closed: removing the entry de-recognises it at the next read.
        settings.MCP_SQL = _cfg({})
        assert is_mcp_application(_row(CLAUDE_ID)) is False

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
        assert is_mcp_application(_row(CLAUDE_ID)) is False
        assert is_mcp_application(_row(CURSOR_DESKTOP_ID)) is False

    @pytest.mark.parametrize(
        ("name", "client_id"),
        [
            pytest.param(CLAUDE_ID, "mcp-sql-cloud.other", id="cloud-other-id"),
            pytest.param(CLAUDE_ID, "random-client-id", id="cloud-random-id"),
            pytest.param(CURSOR_DESKTOP_ID, CLAUDE_ID, id="local-named-cloud-id"),
        ],
    )
    def test_declared_name_with_another_client_id_is_not_recognised(
        self, settings, name, client_id
    ):
        # Recognition keys on the name, provisioning / redirects / the consent
        # label on the client_id: a row whose two disagree is nothing, even
        # when BOTH strings are declared clients.
        settings.MCP_SQL = _cfg({"claude": CLAUDE, "cursor-desktop": CURSOR_DESKTOP})
        assert classify_application(_row(name, client_id=client_id)) is None
        assert is_mcp_application(_row(name, client_id=client_id)) is False


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
            # Strict: no `@` in the authority at all, no query / fragment (not
            # even a bare `?` / `#`), no `;params`.
            pytest.param("https://@chatgpt.com/connector/oauth/x", id="empty-userinfo"),
            pytest.param(
                "https://:@chatgpt.com/connector/oauth/x", id="empty-userinfo-colon"
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/x?next=https://evil.example",
                id="query",
            ),
            pytest.param("https://chatgpt.com/connector/oauth/x?", id="bare-query"),
            pytest.param("https://chatgpt.com/connector/oauth/x#frag", id="fragment"),
            pytest.param("https://chatgpt.com/connector/oauth/x#", id="bare-fragment"),
            pytest.param("https://chatgpt.com/connector/oauth/x;p=1", id="path-params"),
            pytest.param(
                "https://chatgpt.com/connector/oauth/x%3bnext=https://evil.example",
                id="encoded-path-params",
            ),
            pytest.param(
                "https://chatgpt.com/connector/oauth/x%253Bp=1",
                id="double-encoded-path-params",
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


@pytest.mark.django_db
class TestExactCloudClientMatchedExactly:
    """An "exact" cloud client rides DOT's own matching, which is exact only
    from django-oauth-toolkit 3.4.1 (the floor; RFC 9700 §2.1). DOT 3.4.0's
    matcher still accepted the registered host with userinfo, extra query
    parameters, a fragment or `;params` added. oauthlib's absolute-URI check
    stops fragments and any userinfo longer than one character first (its
    userinfo rule matches a single character), but on 3.4.0 a one-character
    userinfo, the extra-query and the `;params` forms reached the consent page
    (and then the code redirect)."""

    @staticmethod
    def _authorize(client, redirect_uri):
        from urllib.parse import urlencode

        from django.urls import reverse

        params = {
            "client_id": CLAUDE_ID,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        return client.get(reverse("authorize") + "?" + urlencode(params))

    @pytest.mark.parametrize(
        "variant",
        [
            "https://attacker@claude.ai/api/mcp/auth_callback",
            "https://a@claude.ai/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback?next=https://evil.example",
            "https://claude.ai/api/mcp/auth_callback#frag",
            "https://claude.ai/api/mcp/auth_callback;p=1",
        ],
        ids=["userinfo", "one-char-userinfo", "extra-query", "fragment", "path-params"],
    )
    def test_near_miss_of_the_registered_callback_is_refused(
        self, client, settings, mcp_user, mcp_mfa_on, variant
    ):
        _provision(settings, {"claude": CLAUDE})
        client.force_login(mcp_user)
        response = self._authorize(client, variant)
        assert response.status_code == 400, response.content
        assert "Location" not in response

    def test_registered_callback_gets_the_consent_page(
        self, client, settings, mcp_user, mcp_mfa_on
    ):
        _provision(settings, {"claude": CLAUDE})
        client.force_login(mcp_user)
        response = self._authorize(client, CLAUDE_URI)
        assert response.status_code == 200, response.content


class TestDeclaredLocalClientLoopbackRecheck:
    """Only a declared CLOUD client is exempt from the loopback re-check in
    `MCPOAuth2Validator.validate_redirect_uri`. A declared `local` client's
    callbacks are loopback by derivation, but its Application row is plain
    data: one hand-edited to carry an off-machine redirect must not get a
    code sent there, even though DOT's own matching of the row would accept
    the stored value. Refused twice over since declared redirects are decided
    from settings (the row is never read) — the loopback re-check stays as
    the second guard."""

    OFF_MACHINE = "https://evil.example/cb"

    @staticmethod
    def _params(redirect_uri):
        return {
            "client_id": CURSOR_DESKTOP_ID,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }

    def _provision_edited(self, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"cursor-desktop": CURSOR_DESKTOP})
        app = Application.objects.get(client_id=CURSOR_DESKTOP_ID)
        app.redirect_uris = f"{app.redirect_uris} {self.OFF_MACHINE}"
        app.save(update_fields=["redirect_uris"])

    @pytest.mark.parametrize("method", ["get", "post"])
    def test_off_machine_redirect_on_a_local_row_is_the_error_page(
        self, client, settings, mcp_user, mcp_mfa_on, method
    ):
        from django.urls import reverse
        from oauth2_provider.models import Grant

        self._provision_edited(settings)
        client.force_login(mcp_user)
        params = self._params(self.OFF_MACHINE)
        if method == "get":
            response = client.get(reverse("authorize"), data=params)
        else:
            response = client.post(
                reverse("authorize"), data={**params, "allow": "Authorize"}
            )
        assert response.status_code == 400, response.content
        assert "Location" not in response
        assert not Grant.objects.exists()

    def test_declared_loopback_callback_still_gets_the_consent_page(
        self, client, settings, mcp_user, mcp_mfa_on
    ):
        from django.urls import reverse

        self._provision_edited(settings)
        client.force_login(mcp_user)
        response = client.get(
            reverse("authorize"),
            data=self._params(CURSOR_DESKTOP["REDIRECTS"][0]["URI"]),
        )
        assert response.status_code == 200, response.content


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

        # Pin super() to True: a declared client's verdict is the settings
        # one, so DOT's row-backed matching must never be consulted.
        monkeypatch.setattr(
            OAuth2Validator, "validate_redirect_uri", lambda self, *a, **k: True
        )
        settings.MCP_SQL = _cfg({"chatgpt": CHATGPT})
        assert (
            MCPOAuth2Validator().validate_redirect_uri(
                CHATGPT_ID, "https://evil.com/x", request=None
            )
            is False
        )

    def test_exact_client_is_decided_by_settings_never_super_nor_prefix(
        self, settings, monkeypatch
    ):
        # A client with only exact rules gets DOT's exact matcher on its
        # declared URIs — never the prefix helper (that would loosen it), and
        # never `super()` (that reads the provisioned row, refreshed only on
        # `migrate`).
        from oauth2_provider.oauth2_validators import OAuth2Validator

        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        prefix_calls: list = []
        monkeypatch.setattr(
            "mcp_sql.oauth._redirect_under_prefix",
            lambda *a, **k: prefix_calls.append(a) or True,
        )

        def _no_super(self, *a, **k):
            pytest.fail("declared client fell through to super()")

        monkeypatch.setattr(OAuth2Validator, "validate_redirect_uri", _no_super)
        validator = MCPOAuth2Validator()
        assert validator.validate_redirect_uri(CLAUDE_ID, CLAUDE_URI, request=None)
        assert not validator.validate_redirect_uri(
            CLAUDE_ID, "https://claude.ai/api/mcp/other", request=None
        )
        assert prefix_calls == []  # the prefix helper was never touched

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

    def test_mixed_rules_accept_both_kinds_from_settings(self, settings, monkeypatch):
        # A client carrying BOTH prefix and exact rules: each rule kind is
        # matched by its own helper, from settings, with no `super()` at all.
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
            OAuth2Validator, "validate_redirect_uri", lambda self, *a, **k: False
        )
        validator = MCPOAuth2Validator()
        for uri in (
            "https://chatgpt.com/aip/connect/oauth",
            "https://chatgpt.com/connector/oauth/inst-42",
        ):
            assert validator.validate_redirect_uri(CHATGPT_ID, uri, request=None)
        assert not validator.validate_redirect_uri(
            CHATGPT_ID, "https://chatgpt.com/aip/connect/oauth/x", request=None
        )

    @pytest.mark.parametrize(
        "uri",
        [
            "https://u@chatgpt.com/connector/oauth/",
            "https://u:p@chatgpt.com/connector/oauth/",
        ],
    )
    def test_userinfo_at_the_prefix_rules_own_path_is_refused(self, settings, uri):
        """A prefix rule is not an exact callback: only `_redirect_under_prefix`
        sees its URI, and it refuses any userinfo. The supported DOT (3.4.1+)
        refuses userinfo in its own matcher too, so here this pins that the
        refusal does not depend on DOT: a matcher that compares only the
        parsed hostname (DOT before 3.4) would admit this URI sitting exactly
        at the prefix's own path if it were ever handed the prefix's URI."""
        settings.MCP_SQL = _cfg({"chatgpt": CHATGPT})
        assert (
            MCPOAuth2Validator().validate_redirect_uri(CHATGPT_ID, uri, request=None)
            is False
        )

    @pytest.mark.parametrize(
        "uri",
        [
            # DOT's matcher parses the request's port only when the host
            # matches; a port no parser takes is a refusal, not a 500.
            "https://claude.ai:99999/api/mcp/auth_callback",
            "https://claude.ai:notaport/api/mcp/auth_callback",
        ],
    )
    def test_unparseable_port_on_a_declared_host_is_refused(self, settings, uri):
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        assert (
            MCPOAuth2Validator().validate_redirect_uri(CLAUDE_ID, uri, request=None)
            is False
        )


# A declared client's callbacks as provisioned, and as later edited in
# settings WITHOUT a `migrate` (so the row still carries the old ones).
OLD_CB = "https://claude.ai/api/mcp/auth_callback"
NEW_CB = "https://claude.com/api/mcp/auth_callback"
EXTRA_CB = "https://claude.ai/api/mcp/second_callback"


def _exact(*uris):
    return {
        "LABEL": "Claude.ai",
        "REDIRECTS": [{"MATCH": "exact", "URI": u} for u in uris],
    }


@pytest.mark.django_db
class TestDeclaredRedirectsFollowSettings:
    """Recognition is settings-gated per request; so are a declared client's
    redirects. The provisioned row is refreshed only by `post_migrate`, so a
    verdict read from it lagged settings until the next `migrate`."""

    def _validator_request(self, client_id):
        """What oauthlib holds when it asks: the row bound by
        `validate_client_id`."""
        from types import SimpleNamespace

        from oauth2_provider.models import Application

        return SimpleNamespace(client=Application.objects.get(client_id=client_id))

    def test_changed_exact_callback_applies_without_migrate(self, settings):
        from oauth2_provider.models import Application

        _provision(settings, {"claude": _exact(OLD_CB)})
        settings.MCP_SQL = _cfg({"claude": _exact(NEW_CB)})  # no re-provision
        assert Application.objects.get(client_id=CLAUDE_ID).redirect_uris == OLD_CB
        request = self._validator_request(CLAUDE_ID)
        validator = MCPOAuth2Validator()
        assert validator.validate_redirect_uri(CLAUDE_ID, NEW_CB, request) is True
        assert validator.validate_redirect_uri(CLAUDE_ID, OLD_CB, request) is False

    def test_removed_exact_rule_is_refused_at_once(self, settings):
        _provision(settings, {"claude": _exact(OLD_CB, EXTRA_CB)})
        settings.MCP_SQL = _cfg({"claude": _exact(OLD_CB)})
        request = self._validator_request(CLAUDE_ID)
        validator = MCPOAuth2Validator()
        assert validator.validate_redirect_uri(CLAUDE_ID, OLD_CB, request) is True
        assert validator.validate_redirect_uri(CLAUDE_ID, EXTRA_CB, request) is False

    def test_removed_prefix_rule_is_refused_at_once(self, settings):
        exact = {"MATCH": "exact", "URI": "https://chatgpt.com/aip/connect/oauth"}
        _provision(settings, {"chatgpt": {"REDIRECTS": [*CHATGPT["REDIRECTS"], exact]}})
        settings.MCP_SQL = _cfg({"chatgpt": {"REDIRECTS": [exact]}})
        request = self._validator_request(CHATGPT_ID)
        validator = MCPOAuth2Validator()
        assert validator.validate_redirect_uri(CHATGPT_ID, exact["URI"], request)
        for uri in (CHATGPT_PREFIX, f"{CHATGPT_PREFIX}inst-42"):
            assert validator.validate_redirect_uri(CHATGPT_ID, uri, request) is False

    def test_unchanged_settings_keep_dots_exact_semantics(self, settings):
        # Same verdicts as DOT's matching of the provisioned row: the exact
        # rule is DOT's own matcher, only fed from settings.
        from oauth2_provider.models import Application

        _provision(settings, {"claude": CLAUDE})
        row = Application.objects.get(client_id=CLAUDE_ID)
        request = self._validator_request(CLAUDE_ID)
        validator = MCPOAuth2Validator()
        for uri in (
            CLAUDE_URI,
            f"{CLAUDE_URI}/",
            f"{CLAUDE_URI}?extra=1",
            "https://CLAUDE.ai/api/mcp/auth_callback",
            "https://claude.ai:443/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/AUTH_CALLBACK",
            "http://claude.ai/api/mcp/auth_callback",
            "https://claude.ai.evil.example/api/mcp/auth_callback",
        ):
            assert validator.validate_redirect_uri(
                CLAUDE_ID, uri, request
            ) is row.redirect_uri_allowed(uri), uri

    def test_default_redirect_comes_from_settings(self, settings):
        _provision(settings, {"claude": _exact(OLD_CB)})
        settings.MCP_SQL = _cfg({"claude": _exact(NEW_CB)})
        request = self._validator_request(CLAUDE_ID)
        assert (
            MCPOAuth2Validator().get_default_redirect_uri(CLAUDE_ID, request) == NEW_CB
        )

    @pytest.mark.parametrize(
        "clients",
        [
            pytest.param({"claude": _exact(OLD_CB, EXTRA_CB)}, id="two-exact"),
            pytest.param(
                {
                    "claude": {
                        "REDIRECTS": [
                            {"MATCH": "prefix", "URI": "https://claude.ai/api/mcp/"}
                        ]
                    }
                },
                id="prefix-only",
            ),
        ],
    )
    def test_no_default_unless_one_exact_rule(self, settings, clients):
        # As DOT gives a default only for a single stored URI; a prefix is
        # not a callback, so it is never one.
        _provision(settings, {"claude": _exact(OLD_CB)})
        settings.MCP_SQL = _cfg(clients)
        request = self._validator_request(CLAUDE_ID)
        assert MCPOAuth2Validator().get_default_redirect_uri(CLAUDE_ID, request) is None

    def test_curated_and_dcr_keep_the_row_backed_answers(self, settings, mcp_app):
        from oauth2_provider.models import Application

        dcr_id = "mcp-sql-" + "b" * 22
        Application.objects.create(
            name=dcr_id,
            client_id=dcr_id,
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1:4567/cb",
        )
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        validator = MCPOAuth2Validator()
        curated = self._validator_request("mcp-sql")
        dcr = self._validator_request(dcr_id)
        # Curated: DOT's any-port loopback match on its stored `http://127.0.0.1`.
        assert validator.validate_redirect_uri(
            "mcp-sql", "http://127.0.0.1:9999", curated
        )
        assert not validator.validate_redirect_uri("mcp-sql", CLAUDE_URI, curated)
        assert (
            validator.get_default_redirect_uri("mcp-sql", curated) == "http://127.0.0.1"
        )
        assert validator.validate_redirect_uri(dcr_id, "http://127.0.0.1:4567/cb", dcr)
        assert not validator.validate_redirect_uri(
            dcr_id, "http://127.0.0.1:4567/x", dcr
        )
        assert (
            validator.get_default_redirect_uri(dcr_id, dcr)
            == "http://127.0.0.1:4567/cb"
        )


@pytest.mark.django_db
class TestDeclaredRedirectsFollowSettingsEndToEnd:
    """The same through `/o/authorize/`: consent page, error page, code."""

    def _query(self, redirect_uri=None):
        query = {
            "client_id": CLAUDE_ID,
            "response_type": "code",
            "scope": "mcp:sql",
            "state": "s",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        if redirect_uri is not None:
            query["redirect_uri"] = redirect_uri
        return query

    def _get(self, client, redirect_uri=None):
        from urllib.parse import urlencode

        from django.urls import reverse

        return client.get(
            reverse("authorize") + "?" + urlencode(self._query(redirect_uri))
        )

    def _changed(self, settings):
        _provision(settings, {"claude": _exact(OLD_CB, EXTRA_CB)})
        settings.MCP_SQL = _cfg({"claude": _exact(NEW_CB)})  # no `migrate`

    def test_new_callback_gets_the_consent_page(
        self, client, settings, mcp_user, gate_posture
    ):
        self._changed(settings)
        client.force_login(mcp_user)
        response = self._get(client, NEW_CB)
        assert response.status_code == 200
        assert b'id="authorizationForm"' in response.content

    @pytest.mark.parametrize("stale", [OLD_CB, EXTRA_CB])
    def test_stale_callback_gets_the_error_page(
        self, client, settings, mcp_user, gate_posture, stale
    ):
        from oauth2_provider.models import Grant

        self._changed(settings)
        client.force_login(mcp_user)
        response = self._get(client, stale)
        # oauthlib's fatal redirect-mismatch: an error page, never a redirect
        # to the URI the request named.
        assert response.status_code == 400
        assert "Location" not in response
        assert b'id="authorizationForm"' not in response.content
        assert not Grant.objects.exists()

    def test_omitted_redirect_uses_the_settings_callback(
        self, client, settings, mcp_user, gate_posture
    ):
        self._changed(settings)
        client.force_login(mcp_user)
        response = self._get(client)
        assert response.status_code == 200
        assert NEW_CB.encode() in response.content
        assert OLD_CB.encode() not in response.content

    def test_consent_post_delivers_the_code_to_the_new_callback(
        self, client, settings, mcp_user, gate_posture
    ):
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        from django.urls import reverse

        self._changed(settings)
        client.force_login(mcp_user)
        response = client.post(
            reverse("authorize"),
            data={**self._query(NEW_CB), "allow": "Authorize"},
        )
        assert response.status_code == 302
        location = urlparse(response["Location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == NEW_CB
        assert "code" in parse_qs(location.query)

    def test_consent_post_to_a_stale_callback_issues_nothing(
        self, client, settings, mcp_user, gate_posture
    ):
        from django.urls import reverse
        from oauth2_provider.models import Grant

        self._changed(settings)
        client.force_login(mcp_user)
        response = client.post(
            reverse("authorize"),
            data={**self._query(OLD_CB), "allow": "Authorize"},
        )
        # oauthlib's fatal redirect-mismatch: the error page, not a 500 and
        # not a redirect anywhere.
        assert response.status_code == 400
        assert "Location" not in response
        assert b'id="authorizationForm"' not in response.content
        assert not Grant.objects.exists()

    @pytest.mark.parametrize(
        "clients",
        [
            pytest.param({"claude": _exact(OLD_CB, NEW_CB)}, id="two-exact"),
            pytest.param({"claude": {**CHATGPT, "LABEL": "Claude.ai"}}, id="prefix"),
        ],
    )
    def test_omitted_redirect_without_a_default_gets_the_error_page(
        self, client, settings, mcp_user, gate_posture, clients
    ):
        """No default (two rules, or a lone prefix rule) → `None` from
        `get_default_redirect_uri` → oauthlib's fatal
        `MissingRedirectURIError`: the error page, never a redirect."""
        from oauth2_provider.models import Grant

        _provision(settings, clients)
        client.force_login(mcp_user)
        response = self._get(client)
        assert response.status_code == 400
        assert "Location" not in response
        assert b'id="authorizationForm"' not in response.content
        assert not Grant.objects.exists()


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
        app = Application.objects.get(client_id=CLAUDE_ID)
        assert is_mcp_application(app) is False

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
    def test_registered_redirect_is_truncated_to_the_column_width(self, settings):
        # An Application with many registered URIs would otherwise overflow the
        # audit column, raise DataError inside the best-effort writers, and
        # lose the row entirely. A DCR row: its stored list is what is recorded.
        from mcp_sql.models import MCPAuthRejectionLog
        from mcp_sql.models import MCPQueryLog

        for model in (MCPQueryLog, MCPAuthRejectionLog):
            assert (
                model._meta.get_field("client_redirect").max_length
                == REDIRECT_MAX_LENGTH
            )
        settings.MCP_SQL = _cfg({})
        identity = identify_application(
            _row(
                "mcp-sql-" + "d" * 22,
                redirect_uris=" ".join(
                    f"http://127.0.0.1:{4000 + i}/callback" for i in range(200)
                ),
            )
        )
        assert len(identity.redirect) == REDIRECT_MAX_LENGTH
        assert identity.kind == ClientKind.DCR

    def test_declared_redirects_are_truncated_to_the_column_width(self, settings):
        # The settings-built set goes through the same truncation.
        many = _exact(*(f"https://claude.ai/cb/{i:04d}" for i in range(200)))
        settings.MCP_SQL = _cfg({"claude": many})
        identity = identify_application(_row(CLAUDE_ID, redirect_uris=CLAUDE_URI))
        assert len(identity.redirect) == REDIRECT_MAX_LENGTH
        assert identity.redirect.startswith("https://claude.ai/cb/0000 ")
        assert identity.kind == ClientKind.CLOUD

    def test_declared_redirect_comes_from_settings_not_the_row(self, settings):
        """The row's `redirect_uris` is refreshed only by `post_migrate`, and
        nothing decides a declared client's redirects from it. The audit
        attribution follows what is enforced: the `CLIENTS` entry, every
        rule's URI in declaration order, space-joined as provisioning joins
        them."""
        both = {
            "REDIRECTS": [
                *CHATGPT["REDIRECTS"],
                {"MATCH": "exact", "URI": "https://chatgpt.com/aip/connect/oauth"},
            ]
        }
        settings.MCP_SQL = _cfg({"claude": _exact(NEW_CB), "chatgpt": both})
        assert identify_application(_row(CLAUDE_ID, redirect_uris=OLD_CB)).redirect == (
            NEW_CB
        )
        assert (
            identify_application(_row(CHATGPT_ID, redirect_uris="stale")).redirect
            == f"{CHATGPT_PREFIX} https://chatgpt.com/aip/connect/oauth"
        )

    @pytest.mark.parametrize(
        ("name", "client_id"),
        [
            pytest.param(CLAUDE_ID, CLAUDE_ID, id="removed-from-settings"),
            pytest.param(CLAUDE_ID, "rogue-client-id", id="client-id-mismatch"),
            pytest.param("mcp-sql", "mcp-sql", id="curated"),
        ],
    )
    def test_any_other_row_records_its_stored_redirects(
        self, settings, name, client_id
    ):
        # Only a RECOGNISED declared client reads settings: a declared name
        # under another client_id is not that client, and a removed entry has
        # nothing left in settings to read.
        clients = {} if client_id == CLAUDE_ID else {"claude": _exact(NEW_CB)}
        settings.MCP_SQL = _cfg(clients)
        identity = identify_application(
            _row(name, client_id=client_id, redirect_uris=OLD_CB)
        )
        assert identity.redirect == OLD_CB

    def test_no_application_yields_the_blank_identity(self):
        # The "no token in hand" case (e.g. the logout-driven revocation rows),
        # matching the models' blank defaults.
        identity = identify_application(None)
        assert (identity.name, identity.kind, identity.redirect) == ("", "", "")

    def test_unrecognised_application_gets_a_blank_kind(self, settings):
        settings.MCP_SQL = _cfg({})
        identity = identify_application(
            _row("some-other-app", redirect_uris="https://x/cb")
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

    def test_changed_callback_is_attributed_without_migrate(
        self, db, settings, mcp_user
    ):
        """A callback changed in settings is enforced at once; the audit row
        names it at once too, not the row's copy left by the last `migrate`."""
        from mcp_sql.models import MCPAuthRejectionLog
        from oauth2_provider.models import Application

        _provision(settings, {"claude": _exact(OLD_CB)})
        token = _declared_token(mcp_user, CLAUDE_ID)
        token.scope = "read"
        token.save(update_fields=["scope"])
        settings.MCP_SQL = _cfg({"claude": _exact(NEW_CB)})  # no re-provision
        assert Application.objects.get(client_id=CLAUDE_ID).redirect_uris == OLD_CB
        with pytest.raises(exceptions.AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.BAD_SCOPE
        assert row.client_kind == ClientKind.CLOUD
        assert row.client_redirect == NEW_CB

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param(CLAUDE_ID, id="declared"),
            pytest.param("mcp-sql", id="curated"),
            pytest.param("mcp-sql-" + "c" * 22, id="dcr"),
        ],
    )
    def test_row_named_like_an_mcp_client_under_another_client_id_is_refused(
        self, db, settings, mcp_user, name
    ):
        """Recognition and the consent label key on the name; provisioning
        and redirects on the client_id. A row carrying a recognised NAME under
        a different client_id is not an MCP client: no authorization, and its
        tokens 401 as `bad_application` with a blank kind."""
        from mcp_sql.models import MCPAuthRejectionLog
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application
        from oauthlib.common import Request as OAuthlibRequest

        _provision(settings, {"claude": CLAUDE})
        rogue = Application.objects.create(
            name=name,
            client_id="rogue-client-id",
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://evil.example/cb",
        )
        assert (
            MCPOAuth2Validator().validate_client_id(
                "rogue-client-id", OAuthlibRequest("")
            )
            is False
        )
        token = AccessToken.objects.create(
            user=mcp_user,
            token="test_" + secrets.token_urlsafe(24),
            application=rogue,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )
        with pytest.raises(exceptions.AuthenticationFailed):
            MCPOAuth2Authentication().authenticate(_bearer_request(token.token))
        row = MCPAuthRejectionLog.objects.get()
        assert row.reason == AuthRejectionReason.BAD_APPLICATION
        assert row.application_name == name
        assert row.client_kind == ""


class TestQueryAuditAttribution:
    """The client identity reaches `MCPQueryLog` through the executor
    threading, on both an allowed row and the operator-misconfig row."""

    def _identity(self, settings):
        settings.MCP_SQL = _cfg({"claude": CLAUDE})
        return identify_application(_row(CLAUDE_ID, redirect_uris=CLAUDE_URI))

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
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestDeclaredClientTokenReachesTheEndpoint:
    """The positive half of recognition at `/mcp/sql/`: a token issued to a
    PROVISIONED declared row (client_id == name, entry in settings) passes
    `MCPOAuth2Authentication` and reaches the tools with its identity —
    elsewhere the positive control is always the curated row."""

    @pytest.mark.usefixtures("mcp_active_session", "gate_posture")
    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(("claude", CLAUDE, CLAUDE_ID, ClientKind.CLOUD), id="cloud"),
            pytest.param(
                (
                    "cursor-desktop",
                    CURSOR_DESKTOP,
                    CURSOR_DESKTOP_ID,
                    ClientKind.LOCAL,
                ),
                id="local",
            ),
        ],
    )
    def test_provisioned_declared_token_is_authenticated(
        self, client, settings, monkeypatch, mcp_user, case
    ):
        from unittest.mock import MagicMock

        from django.http import HttpResponse
        from django.urls import reverse
        from mcp_sql.models import MCPAuthRejectionLog
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        slug, entry, client_id, kind = case
        settings.MCP_SQL = {**settings.MCP_SQL, "CLIENTS": {slug: entry}}
        provision_mcp_clients(sender=django_apps.get_app_config("mcp_sql"))
        app = Application.objects.get(client_id=client_id)
        assert app.name == client_id
        token = AccessToken.objects.create(
            user=mcp_user,
            token="test_" + secrets.token_urlsafe(24),
            application=app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )

        # The direct call: credentials, not a rejection.
        user, auth = MCPOAuth2Authentication().authenticate(
            _bearer_request(token.token)
        )
        assert user == mcp_user
        assert auth == token

        # Through the view: the auth class fronts it, and the tools are built
        # for this client (the bridge itself is stubbed out).
        seen = {}

        def capture(**kwargs):
            seen.update(kwargs)
            return MagicMock()

        monkeypatch.setattr("mcp_sql.views.mcp_endpoint._build_mcp_server", capture)
        monkeypatch.setattr("mcp_sql.views.mcp_endpoint._bridge", lambda server: None)
        monkeypatch.setattr(
            "mcp_sql.views.mcp_endpoint._invoke_wsgi_app",
            lambda app, request: HttpResponse(status=200),
        )
        response = client.post(
            reverse("mcp_sql_endpoint"),
            data=b"{}",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token.token}",
        )
        assert response.status_code == 200
        assert seen["user"] == mcp_user
        assert seen["client"].name == client_id
        assert seen["client"].kind == kind
        assert not MCPAuthRejectionLog.objects.exists()


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

    @pytest.mark.parametrize(
        "uri",
        [
            # Any `@` in the authority, cloud and local alike — including an
            # EMPTY userinfo, which `urlparse` reports as username "" and so
            # slipped past a "non-empty username or password" test.
            pytest.param("https://@claude.ai/cb", id="cloud-empty-userinfo"),
            pytest.param("https://user@claude.ai/cb", id="cloud-user"),
            pytest.param("https://:pw@claude.ai/cb", id="cloud-password-only"),
            pytest.param("https://@chatgpt.com/connector/oauth/", id="cloud-prefix"),
            pytest.param("http://@localhost:8787/cb", id="local-empty-userinfo"),
            pytest.param("http://user@localhost:8787/cb", id="local-user"),
            pytest.param("http://:pw@localhost:8787/cb", id="local-password-only"),
        ],
    )
    def test_declared_redirect_may_not_carry_any_userinfo(self, uri):
        match = "prefix" if uri.endswith("/oauth/") else "exact"
        cfg = {"x": {"REDIRECTS": [{"MATCH": match, "URI": uri}]}}
        with pytest.raises(ImproperlyConfigured, match="userinfo"):
            validate_mcp_sql_settings({"CLIENTS": cfg})

    def test_an_at_sign_outside_the_authority_is_fine(self):
        # Only the authority is userinfo; `@` in a path or query is not.
        validate_mcp_sql_settings(
            {
                "CLIENTS": {
                    "x": {
                        "REDIRECTS": [
                            {"MATCH": "exact", "URI": "https://p.example/cb/@me?a=@"}
                        ]
                    }
                }
            }
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
