"""Tests for the per-user volume tripwire (`mcp_sql.observability`).

The tripwire is exercised end-to-end through `executor._audit_safely` in
`TestAuditSafelyFeedsTripwire`; the rest pin the fixed-window primitive and
the one-shot threshold-crossing alert directly.
"""

import logging

import pytest
from django.core.cache import cache

from mcp_sql import observability


def _set_thresholds(settings, mapping):
    settings.MCP_SQL = {**settings.MCP_SQL, "VOLUME_ALERT_THRESHOLDS": mapping}


@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestRecordQueryVolume:
    def test_alerts_once_at_threshold_crossing(self, settings, caplog):
        _set_thresholds(settings, {"allowed": {3600: 3}})
        with caplog.at_level(logging.ERROR, logger="mcp_sql.observability"):
            for _ in range(5):
                observability.record_query_volume(
                    user_id=42, decision="allowed", user_label="alice@example.com"
                )
        tripped = [
            r for r in caplog.records if "query-volume tripwire" in r.getMessage()
        ]
        # Exactly one ERROR at the crossing, not on every later query.
        assert len(tripped) == 1
        msg = tripped[0].getMessage()
        # Names the user (pk + label) so the Sentry event is actionable.
        assert "pk=42" in msg
        assert "alice@example.com" in msg
        assert "decision=allowed" in msg
        # Counter kept advancing past the threshold (no reset, no re-alert).
        assert cache.get("mcp_sql:vol:allowed:3600:42") == 5

    def test_below_threshold_no_alert(self, settings, caplog):
        _set_thresholds(settings, {"allowed": {3600: 10}})
        with caplog.at_level(logging.ERROR, logger="mcp_sql.observability"):
            for _ in range(9):
                observability.record_query_volume(user_id=1, decision="allowed")
        assert not [r for r in caplog.records if "tripwire" in r.getMessage()]

    def test_multiple_windows_alert_independently(self, settings, caplog):
        _set_thresholds(settings, {"allowed": {3600: 2, 86400: 3}})
        with caplog.at_level(logging.ERROR, logger="mcp_sql.observability"):
            for _ in range(3):
                observability.record_query_volume(user_id=7, decision="allowed")
        tripped = [
            r for r in caplog.records if "query-volume tripwire" in r.getMessage()
        ]
        # Hour window crosses at 2, day window at 3 — one alert each.
        assert len(tripped) == 2
        assert cache.get("mcp_sql:vol:allowed:3600:7") == 3
        assert cache.get("mcp_sql:vol:allowed:86400:7") == 3

    def test_decisions_have_independent_counters(self, settings, caplog):
        _set_thresholds(settings, {"allowed": {3600: 2}, "rejected": {3600: 2}})
        with caplog.at_level(logging.ERROR, logger="mcp_sql.observability"):
            observability.record_query_volume(user_id=5, decision="allowed")
            observability.record_query_volume(user_id=5, decision="rejected")
        assert not [r for r in caplog.records if "tripwire" in r.getMessage()]
        assert cache.get("mcp_sql:vol:allowed:3600:5") == 1
        assert cache.get("mcp_sql:vol:rejected:3600:5") == 1

    def test_users_have_independent_counters(self, settings):
        _set_thresholds(settings, {"allowed": {3600: 100}})
        observability.record_query_volume(user_id=1, decision="allowed")
        observability.record_query_volume(user_id=2, decision="allowed")
        assert cache.get("mcp_sql:vol:allowed:3600:1") == 1
        assert cache.get("mcp_sql:vol:allowed:3600:2") == 1

    def test_unconfigured_decision_is_noop(self, settings):
        _set_thresholds(settings, {"allowed": {3600: 1}})
        # 'rejected' has no windows configured → no counter, no error.
        observability.record_query_volume(user_id=1, decision="rejected")
        assert cache.get("mcp_sql:vol:rejected:3600:1") is None

    def test_alert_without_label_falls_back_to_question_mark(self, settings, caplog):
        _set_thresholds(settings, {"allowed": {3600: 1}})
        with caplog.at_level(logging.ERROR, logger="mcp_sql.observability"):
            observability.record_query_volume(user_id=99, decision="allowed")
        tripped = [
            r for r in caplog.records if "query-volume tripwire" in r.getMessage()
        ]
        assert len(tripped) == 1
        msg = tripped[0].getMessage()
        assert "user=?" in msg  # no label given → "?" placeholder
        assert "pk=99" in msg  # the pk still identifies the user

    def test_add_failure_fails_open(self, settings, monkeypatch, caplog):
        _set_thresholds(settings, {"allowed": {3600: 1}})

        def boom(*args, **kwargs):
            raise ConnectionError

        monkeypatch.setattr(cache, "add", boom)
        with caplog.at_level(logging.WARNING, logger="mcp_sql.observability"):
            # Must not raise — observability never breaks a query.
            observability.record_query_volume(user_id=1, decision="allowed")
        assert any("counter increment failed" in r.getMessage() for r in caplog.records)

    def test_incr_value_error_fails_open(self, settings, monkeypatch, caplog):
        # `cache.incr` raises ValueError when the key is absent — the
        # TTL-expiry race between `add` and `incr`. Must fail open (warn,
        # no raise, no alert), not skip the contract.
        _set_thresholds(settings, {"allowed": {3600: 1}})

        def boom(*args, **kwargs):
            raise ValueError

        monkeypatch.setattr(cache, "incr", boom)
        with caplog.at_level(logging.WARNING, logger="mcp_sql.observability"):
            observability.record_query_volume(user_id=1, decision="allowed")
        assert any("counter increment failed" in r.getMessage() for r in caplog.records)
        assert not [r for r in caplog.records if "tripwire" in r.getMessage()]


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_mcp_cache")
class TestAuditSafelyFeedsTripwire:
    """The single chokepoint: a successful audit write counts the query."""

    def test_audit_write_increments_user_decision_counter(self, mcp_user, settings):
        from django.utils import timezone

        from mcp_sql import executor
        from mcp_sql.models import MCPQueryLog

        _set_thresholds(settings, {"allowed": {3600: 100}})
        executor._audit_safely(
            user=mcp_user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            started_at=timezone.now(),
        )
        assert cache.get(f"mcp_sql:vol:allowed:3600:{mcp_user.pk}") == 1

    def test_failed_audit_write_does_not_count(self, mcp_user, settings, monkeypatch):
        from django.db import DatabaseError
        from django.utils import timezone

        from mcp_sql import executor
        from mcp_sql.models import MCPQueryLog

        _set_thresholds(settings, {"allowed": {3600: 100}})

        def boom(**kwargs):
            raise DatabaseError

        monkeypatch.setattr(MCPQueryLog.objects, "create", boom)
        # Tripwire runs only after a SUCCESSFUL create — a failed write skips it.
        executor._audit_safely(
            user=mcp_user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            started_at=timezone.now(),
        )
        assert cache.get(f"mcp_sql:vol:allowed:3600:{mcp_user.pk}") is None
