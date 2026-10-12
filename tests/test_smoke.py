"""`mcp_sql_smoke` profile-selection contract (`--profile`).

The Phase-1 read-path / audit-unreadable / write-rejected verifiers need a
live `mcp_readonly` alias bound to a restricted role + applied grants — the
deployment topology the standalone test settings deliberately omit (and whose
DB-enforced invariants `test_profiles_isolation.py` proves directly). These
tests cover the infrastructure-free contract instead: profile selection, the
alias-absent skip, the `--run-query` audit-attribution resolution, and the
empty-`ALLOWED_MODELS` guard.
"""

import io
from unittest.mock import MagicMock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from mcp_sql.executor import ExecutorMisconfiguredError
from mcp_sql.management.commands import mcp_sql_smoke
from mcp_sql.management.commands.mcp_sql_smoke import Command
from mcp_sql.schemas import QueryResult


class TestSmokeProfileSelection:
    def test_defaults_to_default_profile(self):
        assert Command._smoke_profile(None).name == "default"

    @pytest.mark.django_db
    def test_explicit_name_selects_that_profile(self, two_profiles):
        assert Command._smoke_profile("second_profile").name == "second_profile"

    def test_unknown_name_raises_with_declared_profiles(self):
        with pytest.raises(CommandError, match="Unknown profile"):
            Command._smoke_profile("no_such_tier")


class TestSmokeHandleSkips:
    def test_skips_when_readonly_alias_absent(self):
        """The standalone settings define no `mcp_readonly` alias, so the whole
        command no-ops with a skip notice rather than erroring."""
        out = io.StringIO()
        call_command("mcp_sql_smoke", stdout=out)
        assert "Skipping smoke check" in out.getvalue()


class TestFirstWhitelistedTable:
    @pytest.mark.django_db
    def test_empty_allowed_models_raises(self):
        """The default test profile declares no models; the read-path check
        needs an actually-granted table, so this is a hard error, not a skip."""
        profile = Command._smoke_profile(None)
        with pytest.raises(
            CommandError, match="empty\n? *ALLOWED_MODELS|ALLOWED_MODELS"
        ):
            Command._first_whitelisted_table(profile)

    @pytest.mark.django_db
    def test_returns_first_declared_table(self, two_profiles):
        """With a non-empty whitelist, the first declared model's db_table is
        what the read-path check SELECTs from."""
        assert (
            Command._first_whitelisted_table(two_profiles["default"])
            == "mcp_sql_testapp_widget"
        )


class TestRunQueryAttribution:
    """`--run-query` resolves the user the audit row is attributed to before
    handing off to the executor (mocked here — the executor's own behaviour is
    covered by `test_executor.py`)."""

    @pytest.fixture
    def captured_run_query(self, monkeypatch):
        calls = {}

        def _fake(**kwargs):
            calls.update(kwargs)
            return QueryResult(columns=["x"], rows=[[1]], row_count=1)

        monkeypatch.setattr(mcp_sql_smoke, "run_query", _fake)
        return calls

    def _cmd(self):
        return Command(stdout=io.StringIO())

    @pytest.mark.django_db
    def test_explicit_as_user_email_attributes_to_that_user(
        self, captured_run_query, mcp_user_factory
    ):
        mcp_user_factory(email="oncall@example.com")
        cmd = self._cmd()
        cmd._run_query(
            "SELECT 1",
            None,
            profile=Command._smoke_profile(None),
            as_user_email="oncall@example.com",
        )
        assert captured_run_query["user"].email == "oncall@example.com"
        assert "run_query attributed to" in cmd.stdout.getvalue()

    @pytest.mark.django_db
    def test_unknown_as_user_email_raises(self, mcp_user_factory):
        cmd = self._cmd()
        with pytest.raises(CommandError, match="No user with email"):
            cmd._run_query(
                "SELECT 1",
                None,
                profile=Command._smoke_profile(None),
                as_user_email="ghost@example.com",
            )

    @pytest.mark.django_db
    def test_falls_back_to_staff_user(self, captured_run_query, mcp_user_factory):
        staff = mcp_user_factory(is_staff=True)
        mcp_user_factory(is_staff=False)  # a non-staff user that must NOT win
        cmd = self._cmd()
        cmd._run_query(
            "SELECT 1", None, profile=Command._smoke_profile(None), as_user_email=None
        )
        assert captured_run_query["user"].pk == staff.pk

    @pytest.mark.django_db
    def test_falls_back_to_any_user_when_no_staff(
        self, captured_run_query, mcp_user_factory
    ):
        only = mcp_user_factory(is_staff=False)
        cmd = self._cmd()
        cmd._run_query(
            "SELECT 1", None, profile=Command._smoke_profile(None), as_user_email=None
        )
        assert captured_run_query["user"].pk == only.pk

    @pytest.mark.django_db
    def test_no_user_at_all_raises(self):
        cmd = self._cmd()
        with pytest.raises(CommandError, match="No user in the DB"):
            cmd._run_query(
                "SELECT 1",
                None,
                profile=Command._smoke_profile(None),
                as_user_email=None,
            )

    @pytest.mark.django_db
    def test_executor_misconfigured_becomes_command_error(
        self, monkeypatch, mcp_user_factory
    ):
        mcp_user_factory(is_staff=True)
        boom = MagicMock(side_effect=ExecutorMisconfiguredError("alias missing"))
        monkeypatch.setattr(mcp_sql_smoke, "run_query", boom)
        cmd = self._cmd()
        with pytest.raises(CommandError, match="alias missing"):
            cmd._run_query(
                "SELECT 1",
                None,
                profile=Command._smoke_profile(None),
                as_user_email=None,
            )
