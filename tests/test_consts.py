"""Tests for `mcp_sql.consts.is_mcp_application_name`.

Pins the recognition invariant: only the canonical Application name and
genuinely DCR-minted names (`<prefix><token_urlsafe(16)>`, 22-char suffix)
are MCP-purpose. Hand-created `<prefix><arbitrary>` names are rejected.
"""

import secrets

from mcp_sql.conf import mcp_sql_settings
from mcp_sql.consts import is_mcp_application_name

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
