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
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.db import transaction
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.executor import ExecutorMisconfiguredError
from mcp_sql.management.commands import mcp_sql_smoke
from mcp_sql.management.commands.mcp_sql_smoke import Command
from mcp_sql.management.commands.mcp_sql_smoke import public_may_create_in
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
    def test_user_model_without_is_staff_falls_back_to_any_user(
        self, captured_run_query, mcp_user_factory, monkeypatch
    ):
        # MCP access no longer needs `is_staff`, so a custom user model may not
        # define it; the attribution fallback must not filter on a missing field.
        from django.contrib.auth import get_user_model

        first = mcp_user_factory(is_staff=False)
        mcp_user_factory(is_staff=True)  # would win if the staff filter still ran
        user_model = get_user_model()
        fields = [f for f in user_model._meta.get_fields() if f.name != "is_staff"]
        monkeypatch.setattr(user_model._meta, "get_fields", lambda **_: fields)
        cmd = self._cmd()
        cmd._run_query(
            "SELECT 1", None, profile=Command._smoke_profile(None), as_user_email=None
        )
        assert captured_run_query["user"].pk == first.pk

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


class _AliasedConnections:
    """`django.db.connections` with the read alias served by the test DB's
    own connection (the standalone settings define no `mcp_readonly`)."""

    def __init__(self):
        self.databases = {mcp_sql_settings.DB_ALIAS: {}}

    def __getitem__(self, alias):
        assert alias == mcp_sql_settings.DB_ALIAS
        return connection


@pytest.mark.django_db
class TestPublicSchemaCreate:
    """Overload hijacking (CVE-2018-1058 class): a role with CREATE on
    `public` can plant `public.lower(varchar)`, which beats
    `pg_catalog.lower(text)` for a varchar argument, pinned `search_path` or
    not. PostgreSQL 14 and earlier grant `PUBLIC` that CREATE by default (CI
    runs 14, 15 and 16), so every test sets the ACL itself; the test
    transaction's rollback restores it."""

    @staticmethod
    def _public_create(*, granted: bool, schema: str = "public") -> None:
        with connection.cursor() as cur:
            if granted:
                cur.execute(f"GRANT CREATE ON SCHEMA {schema} TO PUBLIC")
            else:
                cur.execute(f"REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC")

    @pytest.mark.parametrize("granted", [True, False])
    def test_reads_public_create_on_public(self, granted):
        self._public_create(granted=granted)
        with connection.cursor() as cur:
            assert public_may_create_in(cur) is granted

    def test_null_acl_is_the_owner_only_default(self):
        # A schema created without grants has `nspacl IS NULL`, which means
        # `acldefault` (owner only) on every version — not PUBLIC CREATE.
        with connection.cursor() as cur:
            cur.execute("CREATE SCHEMA mcp_sql_smoke_null_acl")
            cur.execute(
                "SELECT nspacl IS NULL FROM pg_namespace "
                "WHERE nspname = 'mcp_sql_smoke_null_acl'"
            )
            assert cur.fetchone() == (True,)
            assert public_may_create_in(cur, "mcp_sql_smoke_null_acl") is False
        self._public_create(granted=True, schema="mcp_sql_smoke_null_acl")
        with connection.cursor() as cur:
            assert public_may_create_in(cur, "mcp_sql_smoke_null_acl") is True

    def test_missing_schema_is_not_exposed(self):
        with connection.cursor() as cur:
            assert public_may_create_in(cur, "mcp_sql_no_such_schema") is False

    def test_usage_alone_is_not_create(self):
        self._public_create(granted=False)
        with connection.cursor() as cur:
            cur.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
            assert public_may_create_in(cur) is False

    @pytest.mark.parametrize(
        ("granted", "expected", "absent"),
        [
            (True, "WARNING: PUBLIC holds CREATE on schema public", "holds no CREATE"),
            (False, "Schema public: PUBLIC holds no CREATE", "WARNING"),
        ],
    )
    def test_check_reports_on_the_read_alias(
        self, monkeypatch, granted, expected, absent
    ):
        monkeypatch.setattr(mcp_sql_smoke, "connections", _AliasedConnections())
        self._public_create(granted=granted)
        cmd = Command(stdout=io.StringIO())
        cmd._check_public_schema_create()  # a warning never raises
        out = cmd.stdout.getvalue()
        assert expected in out
        assert absent not in out

    def test_default_mode_runs_the_check_last(self, monkeypatch):
        monkeypatch.setattr(mcp_sql_smoke, "connections", _AliasedConnections())
        calls = []
        for step in ("_verify_read_path", "_verify_write_rejected"):
            monkeypatch.setattr(
                Command, step, lambda self, *a, step=step: calls.append(step)
            )
        monkeypatch.setattr(
            Command,
            "_verify_audit_unreadable",
            lambda self, *a: calls.append("_verify_audit_unreadable"),
        )
        monkeypatch.setattr(
            Command,
            "_check_public_schema_create",
            lambda self: calls.append("_check_public_schema_create"),
        )
        call_command("mcp_sql_smoke", table="t", stdout=io.StringIO())
        assert calls == [
            "_verify_read_path",
            "_verify_audit_unreadable",
            "_verify_write_rejected",
            "_check_public_schema_create",
        ]


@pytest.mark.django_db
class TestReadPathMissingTable:
    """An unqualified whitelisted `db_table` whose table is only in another
    schema (`mcp_sql.E001`) made the read-path check fail with a bare
    `ProgrammingError`."""

    def test_names_the_relation_and_e001(self, monkeypatch):
        monkeypatch.setattr(mcp_sql_smoke, "connections", _AliasedConnections())
        monkeypatch.setattr(
            mcp_sql_smoke,
            "transaction",
            SimpleNamespace(atomic=lambda using: transaction.atomic()),
        )
        cmd = Command(stdout=io.StringIO())
        profile = Command._smoke_profile(None)
        with pytest.raises(CommandError) as exc:
            cmd._verify_read_path(profile, "mcp_sql_smoke_no_such_table")
        message = str(exc.value)
        assert message.startswith("mcp_sql_smoke_no_such_table does not exist")
        assert "mcp_sql.E001" in message
        assert "check --database default" in message


@pytest.mark.django_db
class TestReadPathFirstRunErrors:
    """The other first-run states (grants not applied, role not created)
    escaped as a bare `ProgrammingError` too."""

    @pytest.fixture
    def cmd(self, monkeypatch):
        monkeypatch.setattr(mcp_sql_smoke, "connections", _AliasedConnections())
        monkeypatch.setattr(
            mcp_sql_smoke,
            "transaction",
            SimpleNamespace(atomic=lambda using: transaction.atomic()),
        )
        return Command(stdout=io.StringIO())

    def test_a_table_the_role_cannot_read_names_grants_apply(self, cmd):
        with connection.cursor() as cur:
            cur.execute("CREATE TABLE mcp_sql_smoke_ungranted (id int)")
        profile = Command._smoke_profile(None)
        with pytest.raises(CommandError) as exc:
            cmd._verify_read_path(profile, "mcp_sql_smoke_ungranted")
        assert "mcp_sql_grants --apply" in str(exc.value)

    def test_a_missing_role_names_role_setup(self, cmd):
        profile = replace(Command._smoke_profile(None), role="mcp_sql_no_such_role")
        with pytest.raises(CommandError) as exc:
            cmd._verify_read_path(profile, "auth_group")
        assert "Cannot enter role mcp_sql_no_such_role" in str(exc.value)
        assert "role_setup.sql" in str(exc.value)
