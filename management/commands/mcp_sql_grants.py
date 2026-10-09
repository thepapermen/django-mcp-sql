from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.grants import GrantsReconcileError
from mcp_sql.grants import reconcile_grants
from mcp_sql.grants import relation_display
from mcp_sql.grants import relation_sql


class Command(BaseCommand):
    help = (
        "Reconcile per-profile SELECT grants against each profile's "
        'MCP_SQL["PROFILES"][...]["ALLOWED_MODELS"]. Read-only by default: '
        "prints the diff and exits non-zero if drift exists (CI / pre-deploy "
        "gate). Pass --apply to execute GRANT / REVOKE statements (idempotent; "
        "intended as a deploy-pipeline step right after `migrate`). Strict "
        "mode — raises if any profile's role is missing or the app role lacks "
        "membership. Curated MCPxxx view ↔ unmanaged-model column parity is "
        "verified as part of the same reconcile (drift in either layer is a "
        "single MCP-surface-invariant violation)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help=(
                "Execute GRANT / REVOKE for any drift. Without this flag the "
                "command is read-only and exits 1 on drift (intended as a "
                "CI / pre-deploy gate)."
            ),
        )

    def handle(self, *args, **options):
        apply = options["apply"]
        try:
            result = reconcile_grants(strict=True, apply=apply)
        except GrantsReconcileError as exc:
            raise CommandError(str(exc)) from exc

        # Profile/table matrix: emit each role's GRANT/REVOKE statements.
        profiles = mcp_sql_settings.profiles()
        for name, drift in result.per_profile.items():
            role = profiles[name].role
            for relation in drift.granted:
                grant = f"GRANT SELECT ON {relation_sql(relation)} TO {role};"
                self.stdout.write(grant)
            for relation in drift.revoked:
                revoke = f"REVOKE SELECT ON {relation_sql(relation)} FROM {role};"  # noqa: S608
                self.stdout.write(revoke)

        if not result.changed:
            self.stdout.write(self.style.SUCCESS("Grants in sync; no action."))
            return

        if apply:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Applied: +{result.granted_count} grant(s), "
                    f"-{result.revoked_count} revoke(s) across "
                    f"{len(result.per_profile)} profile(s)."
                )
            )
            return

        # Read-only mode + drift detected → exit non-zero so deploy gates fail.
        parts = []
        for name, drift in result.per_profile.items():
            if drift.granted:
                shown = ", ".join(map(relation_display, drift.granted))
                parts.append(f"[{name}] declared but not granted: {shown}")
            if drift.revoked:
                shown = ", ".join(map(relation_display, drift.revoked))
                parts.append(f"[{name}] granted but not declared: {shown}")
        raise CommandError(
            "Grants drift detected — "
            + "; ".join(parts)
            + ". Re-run with --apply to reconcile."
        )
