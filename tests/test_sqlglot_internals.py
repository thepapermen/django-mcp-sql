"""`FaithfulPostgres` overrides private sqlglot internals, and sqlglot moves
those between minor releases (kubedo8 on #5). Its bases are typed `Any`, so
mypy does not see a rename or a new parameter: an override of a method that
no longer exists silently stops applying, and valid queries could start
being refused or rendered differently. These tests turn that into a failure
on whatever sqlglot CI resolves (including the weekly scheduled run)."""

import inspect

import pytest
from mcp_sql.parser import FaithfulPostgres
from sqlglot.dialects.postgres import Postgres

# Names `FaithfulPostgres.Parser` adds itself; every other name it defines
# must override one sqlglot's Postgres parser has. A new helper goes here.
_OWN_PARSER_HELPERS = frozenset({
    "_ARROWS", "_adjacent", "_array_bound", "_array_keyword", "_array_suffix",
    "_arrow_operand", "_at", "_bit_varying", "_interval_alias",
    "_interval_field", "_interval_qualifier", "_is_unquoted",
    "_key_keyword_argument", "_nchar_varying", "_no_array_typed_literal",
    "_no_interval_constant", "_no_more_fields", "_number_as_written",
    "_operator_name", "_parse_at_operator", "_parse_json_object_or_call",
    "_parse_not_or_bang", "_parse_prefix_qualified_operator",
    "_plain_arguments", "_prefix_run", "_quoted_type", "_reading_type",
    "_second_precision", "_starts_with_operator", "_unrestricted",
    "_wrote_is_not",
})  # fmt: skip

_PARTS = [
    ("Parser", _OWN_PARSER_HELPERS),
    ("Generator", frozenset()),
]


def _defined(part: str) -> dict[str, object]:
    return {
        name: attr
        for name, attr in vars(getattr(FaithfulPostgres, part)).items()
        if not name.startswith("__")
    }


@pytest.mark.parametrize(("part", "own"), _PARTS, ids=[p for p, _ in _PARTS])
def test_every_override_still_has_its_sqlglot_counterpart(part, own):
    base = getattr(Postgres, part)
    orphans = sorted(
        name for name in _defined(part) if name not in own and not hasattr(base, name)
    )
    assert orphans == [], (
        f"FaithfulPostgres.{part} overrides names sqlglot's Postgres.{part} "
        f"no longer has (renamed or removed upstream?): {orphans}"
    )


@pytest.mark.parametrize(("part", "own"), _PARTS, ids=[p for p, _ in _PARTS])
def test_own_helpers_shadow_nothing(part, own):
    # A helper that sqlglot later adds under the same name would replace
    # sqlglot's own method for every caller: rename ours.
    base = getattr(Postgres, part)
    assert sorted(name for name in own if hasattr(base, name)) == []
    assert own <= set(_defined(part)), sorted(own - set(_defined(part)))


@pytest.mark.parametrize(("part", "own"), _PARTS, ids=[p for p, _ in _PARTS])
def test_overridden_methods_take_what_sqlglot_passes(part, own):
    base = getattr(Postgres, part)
    mismatched = []
    for name, attr in _defined(part).items():
        if name in own or not inspect.isfunction(attr):
            continue
        ours = inspect.signature(attr).parameters
        if any(p.kind is p.VAR_KEYWORD for p in ours.values()):
            continue
        theirs = inspect.signature(getattr(base, name)).parameters
        missing = [
            p
            for p in theirs
            if p not in ours
            and theirs[p].kind not in (theirs[p].VAR_POSITIONAL, theirs[p].VAR_KEYWORD)
        ]
        if missing:
            mismatched.append(f"{name}: {missing}")
    assert mismatched == [], mismatched


def test_the_tokenizer_is_sqlglots_own():
    # `FaithfulPostgres` reuses Postgres's tokenizer; a subclass would need
    # its own rows above.
    assert FaithfulPostgres.Tokenizer is Postgres.Tokenizer
