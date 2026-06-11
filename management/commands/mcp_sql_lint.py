import os
import re
import subprocess
from pathlib import Path

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from mcp_sql.conf import mcp_sql_settings

ADD_FIELD_RE = re.compile(
    r"migrations\.AddField\(\s*model_name\s*=\s*['\"](?P<model>\w+)['\"]",
)
MCP_OK_RE = re.compile(r"#\s*MCP-OK:\s*\S")
MIGRATION_PATH_RE = re.compile(
    r"^source/(?:[^/]+/)*(?P<app>[^/]+)/migrations/\d{4}_[^/]+\.py$"
)


def _resolve_base() -> str:
    env_base = os.environ.get("MCP_LINT_BASE", "").strip()
    if env_base:
        return env_base
    for ref in ("origin/stage", "origin/main"):
        if (
            subprocess.run(  # noqa: S603
                ["git", "rev-parse", "--verify", "--quiet", ref],  # noqa: S607
                capture_output=True,
                check=False,
            ).returncode
            == 0
        ):
            return ref
    raise CommandError(  # noqa: TRY003
        "Could not resolve a base ref. Set MCP_LINT_BASE or fetch origin/stage."
    )


def _new_migration_files(base: str) -> list[Path]:
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "diff",
            "--name-only",
            "--diff-filter=A",
            f"{base}...HEAD",
            "--",
            "source/**/migrations/*.py",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [Path(line) for line in result.stdout.splitlines() if line.strip()]


def _whitelist_lower() -> set[str]:
    return {
        entry.lower()
        for profile in mcp_sql_settings.profiles().values()
        for entry in profile.allowed_models
    }


class Command(BaseCommand):
    help = (
        "Fail if any new migration adds columns to a table on any MCP profile's "
        "ALLOWED_MODELS without a # MCP-OK: <reason> annotation. Local pre-commit aid "
        "(not wired into bitbucket-pipelines yet) — run before opening a PR "
        "that adds columns to a whitelisted model to surface the deliberate-choice "
        "requirement at code-review time rather than waiting for production drift."
    )

    def handle(self, *args, **options):
        whitelist = _whitelist_lower()
        if not whitelist:
            self.stdout.write("No MCP-exposed models declared; skipping lint.")
            return

        base = _resolve_base()
        violations: list[str] = []

        for path in _new_migration_files(base):
            match = MIGRATION_PATH_RE.match(str(path))
            if not match:
                continue
            app_label = match.group("app")
            text = path.read_text(encoding="utf-8")
            for add_field in ADD_FIELD_RE.finditer(text):
                key = f"{app_label}.{add_field.group('model')}".lower()
                if key in whitelist and not MCP_OK_RE.search(text):
                    violations.append(
                        f"{path}: AddField on MCP-exposed {key} lacks "
                        "'# MCP-OK: <reason>' annotation"
                    )
                    break

        if violations:
            raise CommandError("\n".join(violations))
        self.stdout.write(self.style.SUCCESS("MCP migration lint clean."))
