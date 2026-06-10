"""Tests for the read-only mcp_sql audit admins + the usage-summary view."""

from datetime import timedelta
from http import HTTPStatus

import pytest
from django.contrib import admin as django_admin
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from mcp_sql.admin import MCPAuthRejectionLogAdmin
from mcp_sql.admin import MCPQueryLogAdmin
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.models import MCPQueryLog
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.tests.factories import UserFactory


@pytest.mark.django_db
class TestReadOnlyAdmins:
    @pytest.mark.parametrize(
        ("admin_cls", "model"),
        [
            (MCPQueryLogAdmin, MCPQueryLog),
            (MCPAuthRejectionLogAdmin, MCPAuthRejectionLog),
        ],
    )
    def test_admin_is_read_only(self, admin_cls, model):
        ma = admin_cls(model, django_admin.site)
        request = RequestFactory().get("/")
        assert ma.has_add_permission(request) is False
        assert ma.has_change_permission(request) is False
        assert ma.has_delete_permission(request) is False


@pytest.mark.django_db
class TestUsageSummaryView:
    def _url(self):
        return reverse("admin:mcp_sql_usage_summary")

    def test_redirects_anonymous(self, client):
        # `admin_view` → staff_member_required → redirect to admin login.
        resp = client.get(self._url())
        assert resp.status_code == HTTPStatus.FOUND

    def test_returns_200_for_superuser(self, admin_client, mcp_mfa_on):
        resp = admin_client.get(self._url())
        assert resp.status_code == HTTPStatus.OK

    def test_staff_without_view_permission_gets_403(
        self, client, mcp_mfa_on, mcp_user_factory
    ):
        # `admin_view` lets any staff member in; the explicit
        # `has_view_permission` guard is what keeps the per-user volume data
        # behind the audit-log view permission this user lacks.
        staff = mcp_user_factory(is_active=True, is_staff=True)
        client.force_login(staff)
        resp = client.get(self._url())
        assert resp.status_code == HTTPStatus.FORBIDDEN

    def test_aggregates_per_user_per_window(self, admin_client, mcp_mfa_on):
        user = UserFactory()
        now = timezone.now()

        def _q(decision, when):
            MCPQueryLog.objects.create(
                user=user,
                decision=decision,
                raw_sql="SELECT 1",
                started_at=when,
            )

        # within 1h: 3 allowed + 2 rejected
        for _ in range(3):
            _q(MCPQueryLog.DECISION_ALLOWED, now)
        for _ in range(2):
            _q(MCPQueryLog.DECISION_REJECTED, now)
        # 2h ago: in 24h + 7d but NOT 1h
        _q(MCPQueryLog.DECISION_ALLOWED, now - timedelta(hours=2))
        # 8 days ago: outside every window
        _q(MCPQueryLog.DECISION_ALLOWED, now - timedelta(days=8))
        # one auth-rejection now (counts in every window)
        MCPAuthRejectionLog.objects.create(
            user=user,
            reason=AuthRejectionReason.NO_PERM,
            started_at=now,
        )

        resp = admin_client.get(self._url())
        rows = resp.context["rows"]
        row = next(r for r in rows if r["label"] == user.get_username())
        # cells aligned to (1h, 24h, 7d); the 8-day row is excluded everywhere.
        assert row["cells"][0] == {"allowed": 3, "rejected": 2, "auth": 1}
        assert row["cells"][1] == {"allowed": 4, "rejected": 2, "auth": 1}
        assert row["cells"][2] == {"allowed": 4, "rejected": 2, "auth": 1}

    def test_changelist_links_to_summary(self, admin_client, mcp_mfa_on):
        resp = admin_client.get(reverse("admin:mcp_sql_mcpquerylog_changelist"))
        assert reverse("admin:mcp_sql_usage_summary").encode() in resp.content
