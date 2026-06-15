"""Pin the docs' copy-paste `MCP_SQL` config against the real validator.

The README's Installation section is the snippet a new adopter pastes into
their settings. If it drifts from `validate_mcp_sql_settings` (e.g. a
settings-shape refactor updates the code + architecture.md but not the
install snippet), the adopter's project fails to boot with
`ImproperlyConfigured` — the worst possible first experience. These tests
extract the complete `MCP_SQL = {...}` blocks straight from the shipped
Markdown and run them through the same validator `apps.ready()` calls, so a
drift fails CI here instead of in someone's project.

Only *complete* config blocks are checked: an `MCP_SQL = {...}` literal,
extracted from any ```python fence, whose dict body carries no `...`
placeholder. Illustrative blocks that use `...` (e.g. architecture.md's
"Settings shape" sketch) are deliberately skipped — they are not meant to
be pasted verbatim. The README's install fence bundles `MCP_SQL` alongside
an illustrative `DATABASES = { ... }`, so we extract the `MCP_SQL` literal
on its own rather than exec'ing the whole fence.
"""

import re
from pathlib import Path

import pytest
from mcp_sql.validation import validate_mcp_sql_settings

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Markdown files that carry copy-paste `MCP_SQL` config.
_DOC_FILES = [
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "docs" / "architecture.md",
    _REPO_ROOT / "docs" / "oauth.md",
    _REPO_ROOT / "docs" / "role-setup.md",
]

_PY_FENCE_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)


def _extract_mcp_sql_literal(text: str) -> str | None:
    """Return the `MCP_SQL = {...}` dict literal in `text`, brace-balanced.

    Returns None if `text` has no `MCP_SQL = {` assignment.
    """
    marker = "MCP_SQL = {"
    start = text.find(marker)
    if start == -1:
        return None
    open_brace = start + len(marker) - 1
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    msg = "unbalanced braces in MCP_SQL literal"
    raise AssertionError(msg)


def _complete_mcp_sql_blocks(markdown: str) -> list[str]:
    """Return paste-ready `MCP_SQL = {...}` literals from all python fences.

    "Complete" = the dict body has no `...` placeholder, so it can be exec'd
    into a real dict and validated.
    """
    blocks = []
    for body in _PY_FENCE_RE.findall(markdown):
        literal = _extract_mcp_sql_literal(body)
        if literal is not None and "..." not in literal:
            blocks.append(literal)
    return blocks


def _exec_mcp_sql(block: str) -> dict:
    """Exec an MCP_SQL literal in an isolated namespace and return the dict."""
    ns: dict = {}
    exec(block, ns)  # noqa: S102 — trusted, repo-owned doc content
    return ns["MCP_SQL"]


def _iter_doc_blocks():
    for path in _DOC_FILES:
        if not path.exists():  # installed-wheel test run without the docs tree
            continue
        for i, block in enumerate(_complete_mcp_sql_blocks(path.read_text())):
            yield pytest.param(block, id=f"{path.name}#{i}")


_DOC_BLOCKS = list(_iter_doc_blocks())


@pytest.mark.parametrize("block", _DOC_BLOCKS)
def test_doc_config_block_passes_validator(block):
    """Every paste-ready MCP_SQL block in the docs validates cleanly and uses
    the current PROFILES shape (not the pre-refactor flat ALLOWED_MODELS)."""
    cfg = _exec_mcp_sql(block)
    assert "PROFILES" in cfg, (
        "doc config uses the pre-PROFILES flat shape; it will not boot"
    )
    assert "ALLOWED_MODELS" not in cfg, (
        "top-level ALLOWED_MODELS is no longer a valid MCP_SQL key — it lives "
        "inside each PROFILES entry"
    )
    validate_mcp_sql_settings(cfg)


def test_readme_ships_a_complete_config_block():
    """Guard the guard: if the README's install snippet is renamed or dropped,
    the parametrized test above would silently shrink to zero cases. Pin that
    the README still carries at least one paste-ready config."""
    readme = _REPO_ROOT / "README.md"
    if not readme.exists():
        pytest.skip("README.md not present (installed-wheel test run)")
    assert _complete_mcp_sql_blocks(readme.read_text()), (
        "README.md no longer contains a complete, paste-ready MCP_SQL config "
        "block — the install-snippet regression guard is now inert"
    )
