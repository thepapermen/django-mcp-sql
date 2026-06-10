import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError


def _make_migration(tmp_path: Path, body: str) -> Path:
    app_dir = tmp_path / "fake_app" / "migrations"
    app_dir.mkdir(parents=True)
    migration = app_dir / "0042_add_column.py"
    migration.write_text(body)
    return migration


def _diff_returning(paths: list[Path]):
    """Build a fake subprocess.run side-effect for the lint command's git calls."""

    def runner(cmd, *args, **kwargs):
        if cmd[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:2] == ["git", "diff"]:
            return subprocess.CompletedProcess(
                cmd, 0, stdout="\n".join(str(p) for p in paths) + "\n", stderr=""
            )
        msg = f"unexpected subprocess call: {cmd}"
        raise AssertionError(msg)

    return runner


def _migration_body_with_addfield(model_name: str, *, annotated: bool) -> str:
    note = (
        "    # MCP-OK: backfilled with empty string per migration policy\n"
        if annotated
        else ""
    )
    return (
        "from django.db import migrations, models\n\n\n"
        "class Migration(migrations.Migration):\n"
        "    dependencies = [('fake_app', '0041_prev')]\n"
        f"{note}"
        "    operations = [\n"
        "        migrations.AddField(\n"
        f"            model_name='{model_name}',\n"
        "            name='note',\n"
        "            field=models.CharField(max_length=64, default=''),\n"
        "        ),\n"
        "    ]\n"
    )


@pytest.fixture
def patched_path_root(tmp_path, monkeypatch):
    """Make the lint command's relative migration paths resolve under tmp_path."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def whitelist_fake_model(settings):
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "PROFILES": {
            "default": {
                "ROLE": "mcp_readonly_role",
                "PERMISSION_CODENAME": "use_mcp_session",
                "GROUP_NAME": "mcp_sql_users",
                "ALLOWED_MODELS": ["fake_app.AddColumn"],
            }
        },
    }


def _run_lint() -> None:
    call_command("mcp_sql_lint")


class TestMcpSqlLint:
    def test_passes_when_whitelist_empty(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "ALLOWED_MODELS": []}
        # no subprocess calls expected; the command early-returns.
        with patch("subprocess.run") as run:
            _run_lint()
            run.assert_not_called()

    def test_fails_on_unannotated_addfield(
        self, patched_path_root, whitelist_fake_model
    ):
        rel = Path("source/fake_app/migrations/0042_add_column.py")
        full = patched_path_root / rel
        full.parent.mkdir(parents=True)
        full.write_text(_migration_body_with_addfield("addcolumn", annotated=False))

        with (
            patch("subprocess.run", side_effect=_diff_returning([rel])),
            pytest.raises(CommandError) as exc,
        ):
            _run_lint()

        assert "AddField on MCP-exposed fake_app.addcolumn" in str(exc.value)
        assert "MCP-OK" in str(exc.value)

    def test_passes_with_mcp_ok_annotation(
        self, patched_path_root, whitelist_fake_model
    ):
        rel = Path("source/fake_app/migrations/0042_add_column.py")
        full = patched_path_root / rel
        full.parent.mkdir(parents=True)
        full.write_text(_migration_body_with_addfield("addcolumn", annotated=True))

        with patch("subprocess.run", side_effect=_diff_returning([rel])):
            _run_lint()

    def test_ignores_addfield_on_non_whitelisted_model(
        self, patched_path_root, whitelist_fake_model
    ):
        rel = Path("source/fake_app/migrations/0042_add_column.py")
        full = patched_path_root / rel
        full.parent.mkdir(parents=True)
        full.write_text(
            _migration_body_with_addfield("someothermodel", annotated=False)
        )

        with patch("subprocess.run", side_effect=_diff_returning([rel])):
            _run_lint()  # should not raise

    def test_skips_paths_outside_app_migrations_layout(
        self, patched_path_root, whitelist_fake_model
    ):
        # Paths that don't match `source/.../<app>/migrations/NNNN_*.py` are
        # silently ignored — they can't be resolved to an app label.
        rel = Path("scripts/oneoff_data_fix.py")
        full = patched_path_root / rel
        full.parent.mkdir(parents=True)
        full.write_text(_migration_body_with_addfield("addcolumn", annotated=False))

        with patch("subprocess.run", side_effect=_diff_returning([rel])):
            _run_lint()  # should not raise
