from dataclasses import asdict

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.db import connections
from django.db import transaction
from mcp_sql import grants
from mcp_sql.conf import Profile
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.executor import ExecutorMisconfiguredError
from mcp_sql.executor import pgcode
from mcp_sql.executor import run_query
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import session_drift

# PG SQLSTATEs we expect when the readonly guard or grants reject a write.
PGCODE_READ_ONLY_SQL_TRANSACTION = "25006"
PGCODE_INSUFFICIENT_PRIVILEGE = "42501"
EXPECTED_REJECTION_PGCODES = frozenset(
    {PGCODE_READ_ONLY_SQL_TRANSACTION, PGCODE_INSUFFICIENT_PRIVILEGE}
)
AUDIT_TABLE = "mcp_sql_mcpquerylog"


class Command(BaseCommand):
    help = (
        "Smoke-check the MCP SQL pipeline. Phase 1 default mode opens the "
        "mcp_readonly alias, enters the read-only session, verifies GUC "
        "drift, proves the audit table is unreadable, and proves a write is "
        "rejected. Pass --run-query <sql> to exercise the Phase 2 executor "
        "end-to-end: parse → LIMIT N+1 → readonly tx → row caps → audit."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--table",
            default=None,
            help=(
                "Override the table to SELECT from in the Phase 1 read-path "
                "check. Defaults to the first table on the smoked profile's "
                "ALLOWED_MODELS (the `default` profile, else the first). There "
                "is no fallback to a non-whitelisted table — the smoke needs an "
                "actual SELECT grant to exercise the read path."
            ),
        )
        parser.add_argument(
            "--run-query",
            default=None,
            help=(
                "If set, run the given SQL through the Phase 2 executor and "
                "print the QueryResult. Skips the Phase 1 checks; use the "
                "no-arg invocation for those. The query is audited like a "
                "real MCP call: parser rejects, executor errors, and "
                "successful results all write one MCPQueryLog row."
            ),
        )
        parser.add_argument(
            "--limit",
            default=None,
            type=int,
            help="Override the row LIMIT passed to run_query (clamped server-side).",
        )
        parser.add_argument(
            "--profile",
            default=None,
            help=(
                "Name of the MCP_SQL[PROFILES] entry to smoke (its role, GUC "
                "guards, and audit-unreadability invariant). Defaults to "
                "'default' if defined, else the first declared profile. A "
                "multi-tier deployment should smoke each live tier."
            ),
        )
        parser.add_argument(
            "--as-user",
            default=None,
            help=(
                "Attribute the audit row to the user with this email. "
                "Recommended for prod / stage smoke runs so audit attribution "
                "is explicit (e.g. a dedicated on-call mailbox) rather than "
                "landing on an arbitrary staff user. If omitted, falls back "
                "to the first staff user, then any user — fine for local dev only."
            ),
        )

    def handle(self, *args, **options):
        db_alias = mcp_sql_settings.DB_ALIAS
        if db_alias not in connections.databases:
            self.stdout.write(
                f"MCP_READONLY_DATABASE_URL is not set; {db_alias!r} alias "
                "absent. Skipping smoke check."
            )
            return

        profile = self._smoke_profile(options["profile"])
        self.stdout.write(f"Smoking profile {profile.name!r} (role {profile.role}).")

        if options["run_query"]:
            self._run_query(
                options["run_query"],
                options["limit"],
                profile=profile,
                as_user_email=options["as_user"],
            )
            return

        table = options["table"] or self._first_whitelisted_table(profile)
        self._verify_read_path(profile, table)
        self._verify_audit_unreadable(profile)
        self._verify_write_rejected(profile, table)

    @staticmethod
    def _smoke_profile(name: str | None) -> Profile:
        """The profile this smoke run exercises. Explicit `--profile NAME`
        wins; otherwise `default` if defined, else the first declared
        profile. Smoke is a single-tier contract check — run once per live
        tier on a multi-tier deployment."""
        profiles = mcp_sql_settings.profiles()
        if name is not None:
            try:
                return profiles[name]
            except KeyError:
                msg = (
                    f"Unknown profile {name!r}; declared profiles: "
                    f"{', '.join(sorted(profiles))}"
                )
                raise CommandError(msg) from None
        return profiles.get("default") or next(iter(profiles.values()))

    def _run_query(
        self,
        raw_sql: str,
        limit: int | None,
        *,
        profile: Profile,
        as_user_email: str | None,
    ) -> None:
        user_model = get_user_model()
        if as_user_email:
            user = user_model.objects.filter(email=as_user_email).first()
            if user is None:
                msg = (
                    f"No user with email {as_user_email!r} exists. Pre-create "
                    "the attribution user (a dedicated on-call mailbox is "
                    "recommended) before running smoke on stage/prod so the "
                    "audit trail is clean."
                )
                raise CommandError(msg)
        else:
            user = user_model.objects.filter(is_staff=True).first()
            if user is None:
                user = user_model.objects.first()
            if user is None:
                msg = (
                    "No user in the DB to attribute the audit row to. Create at "
                    "least one user (a staff user is preferred) before running "
                    "--run-query, or pass --as-user <email>."
                )
                raise CommandError(msg)
        try:
            result = run_query(user=user, raw_sql=raw_sql, limit=limit, profile=profile)
        except ExecutorMisconfiguredError as exc:
            raise CommandError(str(exc)) from exc
        # Render compactly: header + columns / rows / flags.
        as_dict = asdict(result)
        rows = as_dict.pop("rows")
        self.stdout.write(self.style.SUCCESS(f"run_query attributed to: {user}"))
        for key, value in as_dict.items():
            self.stdout.write(f"  {key}: {value!r}")
        self.stdout.write(f"  rows ({len(rows)}):")
        for row in rows:
            self.stdout.write(f"    {row!r}")

    @staticmethod
    def _first_whitelisted_table(profile: Profile) -> str:
        for db_table in grants.declared_tables(profile).values():
            return db_table
        msg = (
            f"No --table was given and profile {profile.name!r} has an empty "
            "ALLOWED_MODELS. Add at least one model (e.g. ['auth.Permission']) "
            "to the profile, run mcp_sql_grants --apply, then re-run smoke. The "
            "smoke command must hit a table the role actually has SELECT "
            "on; otherwise the read-path assertion is meaningless."
        )
        raise CommandError(msg)

    def _verify_read_path(self, profile: Profile, table: str) -> None:
        with (
            transaction.atomic(using=mcp_sql_settings.DB_ALIAS),
            connections[mcp_sql_settings.DB_ALIAS].cursor() as cur,
        ):
            enter_readonly_session(cur, role=profile.role)
            drift = session_drift(cur, profile.role)
            if drift:
                msg = (
                    "Session GUC drift after enter_readonly_session: "
                    f"{drift}. The role / SET LOCAL contract is not in sync "
                    "with sql/role_setup.sql; review session.EXPECTED_SESSION_GUCS."
                )
                raise CommandError(msg)
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,)
            cur.execute(f'SELECT 1 FROM "{table}" LIMIT 1')  # noqa: S608
            cur.fetchall()
        self.stdout.write(
            self.style.SUCCESS(
                f"Read path ok: SET LOCAL ROLE + 4 GUCs verified, "
                f"SELECT FROM {table} ok"
            )
        )

    def _verify_audit_unreadable(self, profile: Profile) -> None:
        try:
            with (
                transaction.atomic(using=mcp_sql_settings.DB_ALIAS),
                connections[mcp_sql_settings.DB_ALIAS].cursor() as cur,
            ):
                enter_readonly_session(cur, role=profile.role)
                cur.execute(f'SELECT 1 FROM "{AUDIT_TABLE}" LIMIT 1')  # noqa: S608
                # The fetch is unreachable on a healthy install; the execute
                # raises 42501 first. Force rollback if we somehow got here.
                cur.fetchall()
                transaction.set_rollback(True, using=mcp_sql_settings.DB_ALIAS)
        except DatabaseError as exc:
            code = pgcode(exc)
            if code == PGCODE_INSUFFICIENT_PRIVILEGE:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Audit table {AUDIT_TABLE} unreadable (pgcode=42501) — "
                        "0002_revoke_audit_grants is in effect."
                    )
                )
                return
            msg = (
                f"Audit table read failed with unexpected pgcode {code!r}: "
                f"{exc.__class__.__name__}: {exc}. Expected 42501 "
                "(insufficient_privilege)."
            )
            raise CommandError(msg) from exc
        msg = (
            f"SECURITY ALARM: audit table {AUDIT_TABLE} is READABLE from "
            "mcp_readonly_role. Migration 0002_revoke_audit_grants did not "
            "take effect; the agent could read its own audit trail."
        )
        raise CommandError(msg)

    def _verify_write_rejected(self, profile: Profile, table: str) -> None:
        try:
            with (
                transaction.atomic(using=mcp_sql_settings.DB_ALIAS),
                connections[mcp_sql_settings.DB_ALIAS].cursor() as cur,
            ):
                enter_readonly_session(cur, role=profile.role)
                cur.execute(f'INSERT INTO "{table}" DEFAULT VALUES')
                # INSERT did not raise. Force rollback so any side effect (in
                # case the readonly guard is bypassed AND grants are
                # misconfigured AND no NOT NULL columns block the row) is
                # discarded before we surface the alarm.
                transaction.set_rollback(True, using=mcp_sql_settings.DB_ALIAS)
        except DatabaseError as exc:
            code = pgcode(exc)
            if code in EXPECTED_REJECTION_PGCODES:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Write attempt rejected as expected: "
                        f"{exc.__class__.__name__} (pgcode={code})"
                    )
                )
                return
            msg = (
                f"Write was rejected, but by an unexpected pgcode {code!r}: "
                f"{exc.__class__.__name__}: {exc}. The readonly guard should "
                "reject with 25006 (read_only_sql_transaction) and grants "
                "should reject with 42501 (insufficient_privilege). Anything "
                "else (e.g. 23502 not_null_violation) means the write reached "
                "row evaluation, which is a security boundary breach."
            )
            raise CommandError(msg) from exc
        msg = (
            "SECURITY ALARM: write to a whitelisted table was NOT rejected "
            "after enter_readonly_session. Verify role_setup.sql was applied, "
            "the SET LOCAL guards in session.py match it, and "
            "mcp_sql_grants --apply did NOT grant INSERT."
        )
        raise CommandError(msg)
