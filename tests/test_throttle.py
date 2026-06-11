"""Unit tests for the shared per-IP throttle (`mcp_sql.throttle`).

The `"bad_token"` scope is also exercised end-to-end through the auth class
in `test_auth_class.py`; these tests pin the reusable primitive directly
and the scope-isolation contract the `/o/register` block relies on.
"""

import logging

import pytest
from django.core.cache import cache
from mcp_sql import throttle


@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestIsIpBlocked:
    def test_absent_key_is_not_blocked(self):
        assert throttle.is_ip_blocked("1.2.3.4", scope="register", threshold=5) is False

    def test_at_threshold_is_blocked(self):
        cache.set("mcp_sql:register:ip:1.2.3.4", 5, timeout=3600)
        assert throttle.is_ip_blocked("1.2.3.4", scope="register", threshold=5) is True

    def test_below_threshold_is_not_blocked(self):
        cache.set("mcp_sql:register:ip:1.2.3.4", 4, timeout=3600)
        assert throttle.is_ip_blocked("1.2.3.4", scope="register", threshold=5) is False

    def test_cache_error_fails_open(self, monkeypatch):
        def boom(*args, **kwargs):
            raise ConnectionError

        monkeypatch.setattr(cache, "get", boom)
        assert throttle.is_ip_blocked("1.2.3.4", scope="register", threshold=1) is False


@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestRecordAttempt:
    def test_increments_per_ip_counter(self):
        count = throttle.record_attempt(
            "1.2.3.4", scope="register", window=3600, threshold=5
        )
        assert count == 1
        assert cache.get("mcp_sql:register:ip:1.2.3.4") == 1

    def test_scopes_are_independent(self):
        throttle.record_attempt("1.2.3.4", scope="register", window=3600, threshold=5)
        throttle.record_attempt("1.2.3.4", scope="bad_token", window=3600, threshold=5)
        assert cache.get("mcp_sql:register:ip:1.2.3.4") == 1
        assert cache.get("mcp_sql:bad_token:ip:1.2.3.4") == 1

    def test_cache_error_returns_zero_and_warns(self, monkeypatch, caplog):
        def boom(*args, **kwargs):
            raise ConnectionError

        monkeypatch.setattr(cache, "add", boom)
        with caplog.at_level(logging.WARNING, logger="mcp_sql.throttle"):
            count = throttle.record_attempt(
                "1.2.3.4", scope="register", window=3600, threshold=5
            )
        assert count == 0
        assert any(
            "MCP register counter increment failed" in r.message for r in caplog.records
        )

    def test_threshold_crossing_warns_exactly_once(self, caplog):
        with caplog.at_level(logging.WARNING, logger="mcp_sql.throttle"):
            for _ in range(4):
                throttle.record_attempt(
                    "1.2.3.4", scope="register", window=3600, threshold=3
                )
        engaged = [r for r in caplog.records if "silent IP block engaged" in r.message]
        assert len(engaged) == 1
        assert "register" in engaged[0].message
