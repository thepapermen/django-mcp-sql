"""`session.enter_readonly_session` SESSION_CONTEXT hook — dormant by default,
parameterized + namespace-checked when set (TIC-585)."""

import ast
import os
import re
from pathlib import Path
from unittest.mock import MagicMock

import mcp_sql
import pytest
from django.db import connection
from django.db import transaction
from mcp_sql.session import EXPECTED_SESSION_GUCS
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import session_drift


def _executed_sql(cursor: MagicMock) -> list[str]:
    return [call.args[0] for call in cursor.execute.call_args_list]


def test_dormant_by_default_issues_no_set_config():
    cur = MagicMock()
    enter_readonly_session(cur, role="mcp_readonly_role")
    sql = _executed_sql(cur)
    assert any("SET LOCAL ROLE mcp_readonly_role" in s for s in sql)
    # The static guard GUCs, and nothing via set_config.
    assert not any("set_config" in s for s in sql)


def test_hook_sets_each_guc_via_parameterized_set_config():
    cur = MagicMock()
    enter_readonly_session(
        cur,
        role="mcp_ro_second_profile",
        session_context={"mcp_sql.tenant": "42"},
    )
    set_config_calls = [
        call for call in cur.execute.call_args_list if "set_config" in call.args[0]
    ]
    assert len(set_config_calls) == 1
    # transaction-local (third arg true), value bound as a param — never
    # interpolated into the SQL text.
    assert set_config_calls[0].args[0] == "SELECT set_config(%s, %s, true)"
    assert set_config_calls[0].args[1] == ["mcp_sql.tenant", "42"]


def test_hook_rejects_guc_name_outside_mcp_sql_namespace():
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(
            cur,
            role="r",
            session_context={"statement_timeout": "0"},
        )


def test_hook_rejects_injection_shaped_guc_name():
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(
            cur,
            role="r",
            session_context={"mcp_sql.x; DROP TABLE": "1"},
        )


@pytest.mark.parametrize(
    "name",
    [
        "mcp_sql.Tenant",  # uppercase — outside [a-z_]
        "mcp_sql.",  # empty suffix
        "mcp_sql..x",  # double dot
        "mcp_sql.x.y",  # nested namespace
        "",  # empty string
    ],
)
def test_hook_rejects_boundary_shaped_guc_names(name):
    """`_SAFE_CONTEXT_GUC_NAME` is the sole gate on hook-supplied GUC names;
    pin the boundary shapes, not just the obvious non-namespaced/injection
    cases above."""
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(cur, role="r", session_context={name: "1"})


_ROLE = "mcp_readonly_role"


class TestSessionDrift:
    """`session_drift` is the smoke/executor pre-flight check that the read
    connection actually entered the role + every `SET LOCAL` guard.
    Exercised against a real connection (the in-package readonly role is
    bootstrapped by `sql/role_setup.sql`, per CONTRIBUTING)."""

    @pytest.mark.django_db
    def test_no_drift_after_enter_readonly_session(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            assert session_drift(cur, _ROLE) == {}

    @pytest.mark.django_db
    def test_wrong_expected_role_reported_as_current_user_drift(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            drift = session_drift(cur, "some_other_role")
        assert drift["current_user"] == ("some_other_role", _ROLE)
        # The GUCs still match — only current_user drifted.
        assert set(drift) == {"current_user"}

    @pytest.mark.django_db
    def test_guc_drift_detected(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            # Override one guard transaction-locally to force a mismatch.
            cur.execute("SET LOCAL statement_timeout = '99s'")
            drift = session_drift(cur, _ROLE)
        expected = EXPECTED_SESSION_GUCS["statement_timeout"]
        assert drift["statement_timeout"] == (expected, "99s")
        assert "current_user" not in drift


# A statement that starts with `SET` and is not `SET LOCAL` (a session-level
# setting): the word `SET` (or `SET"name"`) where a statement starts — the
# start of the text (after any replacement fields an f-string or a `+` chain
# starts with, `{…}`), after a `;`, inside a PL/pgSQL body (after `BEGIN`,
# `THEN`, `ELSE`, `LOOP` or a dollar quote) or a string that dynamic SQL
# runs (`EXECUTE 'SET …'`) — followed by anything but `LOCAL`, the end of
# the text too (review rounds 18-20). Also any such `SET` in a function or
# procedure definition (its `SET` clause, its body). Comments are blanked
# first (`_without_comments`), so one in front hides nothing.
#
# A lexical heuristic, not a SQL parser: it reads the text as written
# (`"SE" "T"` and `+` chains are joined by `_string_literals`), but SQL
# built by `.format()` / `%`, a `SET` in an English sentence after "then",
# or an E-string with `\'` inside are beyond it.
_BARE_SET = re.compile(
    r"(?:\A(?:\s*\{…\})*|;|\$(?:[^\W\d]\w*)?\$|'|\b(?:BEGIN|THEN|ELSE|LOOP)\b)"
    r"\s*SET(?=[\s;\"]|\Z)(?!\s+LOCAL\b)"
    r"|\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b.*?"
    r"\bSET(?=[\s;\"]|\Z)(?!\s+LOCAL\b)",
    re.IGNORECASE | re.DOTALL,
)


def _without_comments(text: str) -> str:
    """`text` with each SQL comment replaced by a space: `-- …` to the end
    of the line, `/* … */` nested as Postgres nests them. A `'…'` or `"…"`
    is read whole (`''` / `""` inside), so `'--'` starts no comment."""
    out, i = [], 0
    while i < len(text):
        if text.startswith(("--", "/*"), i):
            out.append(" ")
            i = _comment_end(text, i)
        elif text[i] in "'\"":
            end = _quoted_end(text, i)
            out.append(text[i:end])
            i = end
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _comment_end(text: str, start: int) -> int:
    """Where the comment at `start` ends (`--` or a nested `/*`)."""
    if text.startswith("--", start):
        end = text.find("\n", start)
        return len(text) if end == -1 else end
    depth, i = 0, start
    while i < len(text):
        if text.startswith("/*", i):
            depth, i = depth + 1, i + 2
        elif text.startswith("*/", i):
            depth, i = depth - 1, i + 2
            if depth == 0:
                return i
        else:
            i += 1
    return i


def _quoted_end(text: str, start: int) -> int:
    """Where the `'…'` / `"…"` at `start` ends (a doubled quote inside)."""
    quote, i = text[start], start + 1
    while i < len(text):
        if text.startswith(quote * 2, i):
            i += 2
        elif text[i] == quote:
            return i + 1
        else:
            i += 1
    return i


def _bare_set(text: str) -> bool:
    return _BARE_SET.search(_without_comments(text)) is not None


def _production_files(suffix: str) -> list[Path]:
    """The package's own files (not its tests, the example project or
    dot-directories), without following symlinks."""
    root = Path(mcp_sql.__file__).parent
    found = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(
            d
            for d in subdirectories
            if not d.startswith(".")
            and not (Path(directory) == root and d in ("tests", "example"))
        )
        found.extend(Path(directory) / f for f in sorted(files) if f.endswith(suffix))
    return found


def _string_literals(path: Path) -> list[tuple[int, str]]:
    """Each string literal in `path`, an f-string with `{…}` for each
    replacement field (scanned whole, not part by part), and each `+` chain
    with a string in it as one text (`"SET" + f" x = {v}"`), any operand
    that is not a string being `{…}`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parts = {
        id(value)
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        for value in node.values
    }
    chained = {
        id(operand)
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        for operand in (node.left, node.right)
        if isinstance(operand, ast.BinOp) and isinstance(operand.op, ast.Add)
    }

    def text(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(text(value) or "{…}" for value in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = text(node.left), text(node.right)
            if left is None and right is None:
                return None
            return (left or "{…}") + (right or "{…}")
        return None

    literals = []
    for node in ast.walk(tree):
        if id(node) in parts or id(node) in chained:
            continue
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            found = text(node)
            if found is not None:
                literals.append((node.lineno, found))
    return literals


def test_no_production_code_issues_a_bare_set():
    """CLAUDE.md invariant: only `SET LOCAL`, never bare `SET` — behind a
    transaction-mode pgbouncer a session-level setting leaks onto the next
    client of the backend (review round 18: replacing the revocation's
    `SET LOCAL lock_timeout` with `SET` failed no test). Every string
    literal in the package's Python (f-string parts included) and every
    statement line of its `.sql` files."""
    offenders = []
    python = _production_files(".py")
    assert {p.name for p in python} >= {"session.py", "signals.py", "executor.py"}
    for path in python:
        for line, text in _string_literals(path):
            if _bare_set(text):
                offenders.append(f"{path.name}:{line}: {text[:60]!r}")
    sql = _production_files(".sql")
    assert {p.name for p in sql} >= {"role_setup.sql"}
    # The whole file: a statement may span lines (`SET\n  x = 1`).
    offenders.extend(
        path.name for path in sql if _bare_set(path.read_text(encoding="utf-8"))
    )
    assert offenders == []


@pytest.mark.parametrize(
    "text",
    [
        "SET lock_timeout = '5s'",
        "  set statement_timeout TO 0",
        "BEGIN; SET ROLE x",
        "SET SESSION ROLE x",
        # Review round 19: a comment in front, a statement on several
        # lines, `SET` alone, after a replacement field.
        "/* bounded */ SET lock_timeout = '5s'",
        "-- c\nSET lock_timeout = '5s'",
        "SELECT 1; /* a */ -- b\n set x = 1",
        "SET\n  lock_timeout = '5s'",
        "SET",
        "SET;",
        "{…}SET lock_timeout = '5s'",
        "SELECT {…}; SET x = 1",
        "{…} {…}SET x = 1",
        # Review round 20: inside PL/pgSQL and dynamic SQL, a function's
        # own `SET`, a quoted name, nested comments, `--` in a string.
        "DO $$ BEGIN SET ROLE x; END $$",
        "BEGIN\nSET ROLE x",
        "DO $body$ BEGIN IF a THEN SET ROLE x; END IF; END $body$",
        "LOOP set x = 1; END LOOP",
        "EXECUTE 'SET ROLE ' || quote_ident(r)",
        "CREATE FUNCTION f() RETURNS int AS $$ SET ROLE x $$ LANGUAGE sql",
        "CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql\n"
        "SET search_path = public AS $$ SELECT 1 $$",
        "CREATE PROCEDURE p() SET work_mem = '1MB' AS $$ SELECT 1 $$",
        'SET"lock_timeout" = 1',
        "/* a /* b */ c */ SET lock_timeout = 1",
        "SELECT '--'; SET lock_timeout = 1",
        "SELECT 'it''s'; SET x = 1",
    ],
)
def test_the_bare_set_scan_finds(text):
    assert _bare_set(text)


@pytest.mark.parametrize(
    "text",
    [
        "SET LOCAL lock_timeout = '5s'",
        "set local role x",
        "SET\n  LOCAL x = 1",
        "SET/**/LOCAL x = 1",
        "/* SET x = 1 */ SELECT 1",
        "-- SET x = 1\nSELECT 1",
        "ALTER ROLE r SET lock_timeout = '1s'",
        "UPDATE t SET a = 1",
        "RESET ROLE",
        "SET LOCAL never bare SET",
        "SETTINGS",
        "Set-returning functions are refused; SET-like words are not",
        "ALTER ROLE {…} SET {…} = {…};",
        "SELECT set_config('a', 'b', true)",
        "DO $$ BEGIN SET LOCAL ROLE x; END $$",
        "EXECUTE 'SET LOCAL ROLE x'",
        "IF a THEN RAISE NOTICE 'the SET ROLE will fail'; END IF",
        "SELECT '$$' AS a, 'SETTINGS' AS b",
        "/* nested /* SET x */ SET y */ SELECT 1",
        "SELECT 'a -- b' AS c; SET LOCAL x = 1",
    ],
)
def test_the_bare_set_scan_ignores(text):
    assert not _bare_set(text)


@pytest.mark.parametrize(
    ("source", "found"),
    [
        ('x = "SET" + f" lock_timeout = {t}"', True),
        ('x = "SE" "T lock_timeout"', True),
        ('x = prefix + "SET x = 1"', True),
        ('x = f"{prefix}SET x = 1"', True),
        ('x = f"/* {why} */ SET x = 1"', True),
        ('x = "SET LOCAL " + name', False),
        ('x = f"{a} {b}"', False),
    ],
)
def test_the_scan_reads_python_strings_whole(tmp_path, source, found):
    path = tmp_path / "m.py"
    path.write_text(source + "\n", encoding="utf-8")
    assert any(_bare_set(text) for _, text in _string_literals(path)) is found
