from datetime import timedelta

import pytest
from django.utils import timezone
from mcp_sql.models import MCPQueryLog
from mcp_sql.tests.factories import UserFactory


@pytest.mark.django_db
class TestMCPQueryLog:
    """Phase 1 ships the model only; the executor in Phase 2 populates it."""

    def test_create_round_trip(self):
        user = UserFactory()
        log = MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            normalized_sql="SELECT 1",
            wrapped_sql="SELECT 1 LIMIT 10",
            started_at=timezone.now(),
            duration_ms=12,
            row_count=1,
            result_bytes=8,
        )
        assert log.pk is not None
        reloaded = MCPQueryLog.objects.get(pk=log.pk)
        assert reloaded.user == user
        assert reloaded.decision == MCPQueryLog.DECISION_ALLOWED
        assert reloaded.token_id == ""
        assert reloaded.truncated is False
        assert reloaded.error == ""

    def test_tool_defaults_to_run_query(self):
        """The `tool` field default keeps every pre-`tool`-field row (all
        executor `run_query` writes) correct, and stays in sync with the
        canonical `ToolName.RUN_QUERY` vocabulary."""
        from mcp_sql.schemas import ToolName

        assert MCPQueryLog._meta.get_field("tool").default == ToolName.RUN_QUERY

        log = MCPQueryLog.objects.create(
            user=UserFactory(),
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            started_at=timezone.now(),
        )
        assert log.tool == ToolName.RUN_QUERY

    def test_rejected_round_trip_with_reason(self):
        user = UserFactory()
        log = MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_REJECTED,
            rejection_reason="ast_table_not_in_whitelist",
            raw_sql="SELECT * FROM secrets",
            started_at=timezone.now(),
        )
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == "ast_table_not_in_whitelist"

    def test_default_ordering_is_newest_first(self):
        user = UserFactory()
        now = timezone.now()
        old = MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            started_at=now - timedelta(minutes=5),
        )
        new = MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 2",
            started_at=now,
        )
        assert list(MCPQueryLog.objects.values_list("pk", flat=True)) == [
            new.pk,
            old.pk,
        ]

    def test_indexes_declared(self):
        index_field_sets = {tuple(idx.fields) for idx in MCPQueryLog._meta.indexes}
        assert ("user", "started_at") in index_field_sets
        assert ("decision", "started_at") in index_field_sets

    def test_no_static_cohort_permission(self):
        # TIC-585: per-profile cohort permissions are config-derived and
        # provisioned by the `provision_mcp_profiles` post_migrate signal —
        # NOT declared statically here, because the package cannot know a
        # consumer's profile codenames at model-definition time.
        assert not MCPQueryLog._meta.permissions


class TestAuditClientIp:
    """Review round 18: `REMOTE_ADDR` reaches the audit tables' `inet`
    column only when it is one IP address."""

    @pytest.mark.parametrize(
        "value",
        ["127.0.0.1", "203.0.113.7", "::1", "2001:db8::7", "::ffff:192.0.2.1"],
    )
    def test_one_address_is_kept_as_given(self, value):
        from mcp_sql.models import audit_client_ip

        assert audit_client_ip(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "10.0.0.1, 10.0.0.2",
            "10.0.0.1,10.0.0.2",
            " 10.0.0.1",
            "unknown",
            "example.com",
            "10.0.0.0/8",
            "fe80::1%eth0",
            "010.0.0.1",
            "[::1]",
            "10.0.0.1:443",
            b"10.0.0.1",
            167772161,
        ],
    )
    def test_anything_else_is_none(self, value):
        from mcp_sql.models import audit_client_ip

        assert audit_client_ip(value) is None

    @pytest.mark.django_db
    @pytest.mark.parametrize(
        "value",
        [
            "127.0.0.1",
            "::ffff:192.0.2.1",
            "2001:db8::7",
            "10.0.0.1, 10.0.0.2",
            "fe80::1%eth0",
            "unknown",
        ],
    )
    def test_every_result_is_stored(self, value):
        """Whatever it returns, both audit tables store."""
        from mcp_sql.models import MCPAuthRejectionLog
        from mcp_sql.models import audit_client_ip
        from mcp_sql.schemas import AuthRejectionReason

        user = UserFactory()
        ip = audit_client_ip(value)
        MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_REJECTED,
            raw_sql="",
            started_at=timezone.now(),
            client_ip=ip,
        )
        MCPAuthRejectionLog.objects.create(
            user=user,
            reason=AuthRejectionReason.SESSION_LOGOUT,
            started_at=timezone.now(),
            client_ip=ip,
        )
        for model in (MCPQueryLog, MCPAuthRejectionLog):
            assert model.objects.get(user=user).client_ip == ip
