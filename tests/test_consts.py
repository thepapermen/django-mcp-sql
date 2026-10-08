"""Tests for `mcp_sql.consts.is_mcp_application_name` and `models.audit_client_ip`.

Pins the recognition invariant: only the canonical Application name and
genuinely DCR-minted names (`<prefix><token_urlsafe(16)>`, 22-char suffix)
are MCP-purpose. Hand-created `<prefix><arbitrary>` names are rejected.
"""

import secrets

import pytest
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name
from mcp_sql.models import audit_client_ip

PREFIX = mcp_sql_settings.APPLICATION_NAME_PREFIX
CANONICAL = mcp_sql_settings.APPLICATION_NAME


class TestIsMcpApplicationName:
    def test_canonical_name_accepted(self):
        assert is_mcp_application_name(CANONICAL) is True

    def test_dcr_shaped_name_accepted(self):
        assert is_mcp_application_name(f"{PREFIX}{secrets.token_urlsafe(16)}") is True

    def test_word_suffix_rejected(self):
        assert is_mcp_application_name(f"{PREFIX}superuser") is False

    def test_path_traversal_suffix_rejected(self):
        assert is_mcp_application_name(f"{PREFIX}../../bypass") is False

    def test_wrong_length_suffix_rejected(self):
        assert is_mcp_application_name(f"{PREFIX}{'a' * 21}") is False
        assert is_mcp_application_name(f"{PREFIX}{'a' * 23}") is False

    def test_unrelated_name_rejected(self):
        assert is_mcp_application_name("rogue") is False

    def test_bare_prefix_rejected(self):
        assert is_mcp_application_name(PREFIX) is False


class TestNormalizeClientIp:
    """Every audit writer stores `client_ip` through `audit_client_ip` (one IP
    address, as given, else None).

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
            # As given; Postgres `inet` stores it in canonical form.
            ("2001:DB8:0:0:0:0:0:1", "2001:DB8:0:0:0:0:0:1"),
            # A zone index is legal for `ipaddress` but not for Postgres
            # `inet`; dropping it would record another address, so None.
            ("fe80::1%eth0", None),
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
        assert audit_client_ip(raw) == expected
