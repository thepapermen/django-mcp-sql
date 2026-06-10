"""Tests for the `mcp_sql.signals` receivers: `user_logged_out` → revoke MCP
tokens, and the `m2m_changed` MCP-group-grant alert."""

import logging
import secrets
from datetime import timedelta

import pytest
from django.contrib.auth.signals import user_logged_out
from django.test import RequestFactory
from django.utils import timezone

from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP
from mcp_sql.tests.factories import UserFactory


def _logout_request():
    """A real `HttpRequest` that satisfies `axes`'s receiver expectations.

    `django-axes` listens on `user_logged_out` and reads `request.axes_ip_address`
    via its own middleware proxy. A bare `None` (or a non-axes-aware mock) makes
    its receiver raise `AttributeError`. Passing a real `RequestFactory` request
    keeps axes happy without needing to mock its internals.
    """
    return RequestFactory().get("/logout/")


@pytest.mark.django_db
class TestRevokeMcpTokensOnLogout:
    def _mint_token(self, user, mcp_app):
        from oauth2_provider.models import AccessToken

        return AccessToken.objects.create(
            user=user,
            token="test_" + secrets.token_urlsafe(16),
            application=mcp_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )

    def test_logout_deletes_only_calling_users_tokens(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        from oauth2_provider.models import AccessToken

        user_a = UserFactory()
        user_b = UserFactory()
        self._mint_token(user_a, mcp_app)
        self._mint_token(user_a, mcp_app)
        self._mint_token(user_b, mcp_app)

        # The revocation now runs in `transaction.on_commit`; capture+execute
        # so the deferred callback fires within the test transaction.
        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user_a), request=_logout_request(), user=user_a
            )

        assert AccessToken.objects.filter(user=user_a).count() == 0
        assert AccessToken.objects.filter(user=user_b).count() == 1
        assert "Revoked 2 MCP token(s)" in caplog.text

    def test_logout_does_not_delete_tokens_from_other_applications(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        """Scoping contract: logout deletes only `mcp-sql` Application
        tokens. If a second OAuth Application is ever added, the user's
        tokens for THAT Application must survive logout."""
        from oauth2_provider.models import AccessToken
        from oauth2_provider.models import Application

        other_app = Application.objects.create(
            name="other-app",
            client_id="other",
            client_secret="",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1",
        )
        user = UserFactory()
        self._mint_token(user, mcp_app)
        AccessToken.objects.create(
            user=user,
            token="other_" + secrets.token_urlsafe(16),
            application=other_app,
            expires=timezone.now() + timedelta(hours=1),
            scope="other:scope",
        )

        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        assert AccessToken.objects.filter(user=user, application=mcp_app).count() == 0
        assert AccessToken.objects.filter(user=user, application=other_app).count() == 1

    def test_logout_without_tokens_is_silent(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        user = UserFactory()
        with (
            caplog.at_level(logging.INFO, logger="mcp_sql.signals"),
            django_capture_on_commit_callbacks(execute=True),
        ):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        # `signals.py` logs (and writes an audit row) only when `deleted > 0`.
        assert "Revoked" not in caplog.text

    def test_logout_writes_session_logout_audit_row(
        self, mcp_app, caplog, django_capture_on_commit_callbacks
    ):
        from mcp_sql.models import MCPAuthRejectionLog
        from mcp_sql.schemas import AuthRejectionReason

        user = UserFactory()
        self._mint_token(user, mcp_app)
        self._mint_token(user, mcp_app)

        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        row = MCPAuthRejectionLog.objects.get(user=user)
        assert row.reason == AuthRejectionReason.SESSION_LOGOUT.value
        assert "Revoked 2 MCP token(s)" in row.error
        # No single token/application — it's a bulk, user-scoped revocation.
        assert row.token_pk == ""
        assert row.application_name == ""

    def test_logout_without_tokens_writes_no_audit_row(
        self, mcp_app, django_capture_on_commit_callbacks
    ):
        from mcp_sql.models import MCPAuthRejectionLog

        user = UserFactory()
        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(user), request=_logout_request(), user=user
            )

        assert not MCPAuthRejectionLog.objects.filter(user=user).exists()

    def test_anonymous_logout_is_a_noop(self):
        # Sanity: the `if user is None: return` guard fires without raising.
        # Invoking the handler directly bypasses axes (which can't handle
        # anonymous logout without further setup).
        from mcp_sql.signals import revoke_mcp_tokens_on_logout

        revoke_mcp_tokens_on_logout(sender=None, request=None, user=None)


def _cohort_alerts(caplog):
    return [r for r in caplog.records if "cohort change" in r.getMessage()]


@pytest.mark.django_db
class TestMcpGroupGrantAlert:
    """The `m2m_changed` receiver fires an ERROR only when a user is ADDED to
    the MCP group — gain-only, group-only by design."""

    def test_group_add_alerts(self, mcp_group, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(mcp_group)
        alerts = _cohort_alerts(caplog)
        assert len(alerts) == 1
        msg = alerts[0].getMessage()
        assert "GAINED" in msg
        assert user.get_username() in msg  # names the user (email)
        assert f"pk={user.pk}" in msg
        assert "default" in msg  # names the profile the user gained

    def test_group_remove_is_silent(self, mcp_group, caplog):
        user = UserFactory()
        user.groups.add(mcp_group)  # the grant alert
        # caplog accumulates ERROR records for the whole test regardless of
        # `at_level`, so drop the grant alert before exercising the remove.
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.remove(mcp_group)
        # De-escalation is out of scope — only post_add fires.
        assert _cohort_alerts(caplog) == []

    def test_direct_permission_grant_is_silent(self, use_mcp_perm, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.user_permissions.add(use_mcp_perm)
        # Direct-permission grants are out of scope (group is the canonical path).
        assert _cohort_alerts(caplog) == []

    def test_unrelated_group_add_is_silent(self, mcp_group, caplog):
        from django.contrib.auth.models import Group

        other = Group.objects.create(name="some-other-group")
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(other)
        assert _cohort_alerts(caplog) == []

    def test_reverse_group_add_alerts(self, mcp_group, caplog):
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            mcp_group.user_set.add(user)  # reverse direction
        alerts = _cohort_alerts(caplog)
        assert len(alerts) == 1
        assert f"pk={user.pk}" in alerts[0].getMessage()

    def test_two_profile_groups_fires_ambiguity_alert(self, two_profiles, caplog):
        """The paging alert (TIC-585): adding a user to a SECOND MCP profile
        group fires one extra ERROR — they are now ambiguous and will be denied
        until fixed. This is the assignment-time half of the alert split."""
        from django.contrib.auth.models import Group

        user = UserFactory()
        g_default = Group.objects.get(name="mcp_sql_users")
        g_second = Group.objects.get(name=SECOND_PROFILE_GROUP)
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(g_default, g_second)
        ambiguity = [r for r in caplog.records if "AMBIGUITY" in r.getMessage()]
        assert len(ambiguity) == 1
        msg = ambiguity[0].getMessage()
        assert f"pk={user.pk}" in msg
        assert "default" in msg
        assert "second_profile" in msg
        # The gain alert still fires exactly once (and lists both profiles).
        assert len(_cohort_alerts(caplog)) == 1

    def test_missing_group_is_noop(self, db, caplog):
        # No `mcp_group` fixture → the MCP group does not exist (mirrors a
        # fresh DB before migration 0004). The receiver must no-op, not crash.
        from django.contrib.auth.models import Group

        other = Group.objects.create(name="unrelated")
        user = UserFactory()
        with caplog.at_level(logging.ERROR, logger="mcp_sql.signals"):
            user.groups.add(other)
        assert _cohort_alerts(caplog) == []


@pytest.mark.django_db
class TestProvisionMcpProfilesIdempotency:
    """The zero-data-migration upgrade story rests on `get_or_create`
    reasoning — pin it: re-running the receiver must neither duplicate nor
    mutate the Permission/Group rows."""

    def test_second_run_creates_nothing_new(self):
        from django.apps import apps as django_apps
        from django.contrib.auth.models import Group
        from django.contrib.auth.models import Permission

        from mcp_sql.signals import provision_mcp_profiles

        sender = django_apps.get_app_config("mcp_sql")
        provision_mcp_profiles(sender=sender)
        provision_mcp_profiles(sender=sender)

        assert (
            Permission.objects.filter(
                codename="use_mcp_session",
                content_type__app_label="mcp_sql",
                content_type__model="mcpquerylog",
            ).count()
            == 1
        )
        assert Group.objects.filter(name="mcp_sql_users").count() == 1
        group = Group.objects.get(name="mcp_sql_users")
        assert group.permissions.filter(codename="use_mcp_session").count() == 1
