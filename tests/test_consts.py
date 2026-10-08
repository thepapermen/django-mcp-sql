"""Tests for `mcp_sql.consts.is_mcp_application` and `normalize_client_ip`.

Pins the recognition invariant: only the canonical Application name and
genuinely DCR-minted names (`<prefix><token_urlsafe(16)>`, 22-char suffix)
are MCP-purpose, and only on a row whose `client_id` equals its `name`.
Hand-created `<prefix><arbitrary>` names are rejected.
"""

import secrets
from types import SimpleNamespace

import pytest
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import classify_application
from mcp_sql.consts import is_mcp_application
from mcp_sql.consts import normalize_client_ip

PREFIX = mcp_sql_settings.APPLICATION_NAME_PREFIX
CANONICAL = mcp_sql_settings.APPLICATION_NAME


def _row(name, client_id=None):
    """An Application stand-in carrying the two fields recognition reads;
    `client_id` defaults to the name, as every row the package writes has."""
    return SimpleNamespace(
        name=name, client_id=name if client_id is None else client_id
    )


class TestIsMcpApplication:
    def test_canonical_name_accepted(self):
        assert is_mcp_application(_row(CANONICAL)) is True

    def test_dcr_shaped_name_accepted(self):
        assert is_mcp_application(_row(f"{PREFIX}{secrets.token_urlsafe(16)}")) is True

    def test_word_suffix_rejected(self):
        assert is_mcp_application(_row(f"{PREFIX}superuser")) is False

    def test_path_traversal_suffix_rejected(self):
        assert is_mcp_application(_row(f"{PREFIX}../../bypass")) is False

    def test_wrong_length_suffix_rejected(self):
        assert is_mcp_application(_row(f"{PREFIX}{'a' * 21}")) is False
        assert is_mcp_application(_row(f"{PREFIX}{'a' * 23}")) is False

    def test_unrelated_name_rejected(self):
        assert is_mcp_application(_row("rogue")) is False

    def test_bare_prefix_rejected(self):
        assert is_mcp_application(_row(PREFIX)) is False

    def test_no_application_rejected(self):
        assert is_mcp_application(None) is False

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param(CANONICAL, id="curated"),
            pytest.param(f"{PREFIX}{secrets.token_urlsafe(16)}", id="dcr"),
        ],
    )
    def test_name_without_matching_client_id_rejected(self, name):
        # Recognition keys on the name; everything else keys on client_id.
        # A row NAMED like an MCP client under another client_id is nothing.
        assert classify_application(_row(name, client_id="some-other-id")) is None
        assert is_mcp_application(_row(name, client_id="some-other-id")) is False
        assert is_mcp_application(_row(name, client_id=name.upper())) is False


class TestNormalizeClientIp:
    """Every audit writer stores `client_ip` through `normalize_client_ip`.

    The column is a `GenericIPAddressField`; a non-IP `REMOTE_ADDR` (e.g.
    uvicorn `--proxy-headers --forwarded-allow-ips='*'` copying a client's
    `X-Forwarded-For: not-an-ip`) made psycopg 3 raise `ValueError` at the
    insert (escaping every audit wrapper) and psycopg2 a swallowed
    `DataError` (the row silently lost).
    """

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("203.0.113.9", "203.0.113.9"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            # A zone index is legal for `ipaddress` but not for Postgres `inet`.
            ("fe80::1%eth0", "fe80::1"),
            ("not-an-ip", None),
            ("not-an-ip, 203.0.113.9", None),
            ("a:b:zz", None),
            ("1.2.3.4\x00", None),
            (" 1.2.3.4", None),
            ("", None),
            (None, None),
            (12345, None),
        ],
    )
    def test_value(self, raw, expected):
        assert normalize_client_ip(raw) == expected
