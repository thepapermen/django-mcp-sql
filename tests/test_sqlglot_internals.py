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
    "_interval_field", "_interval_qualifier", "_is_unquoted", "_joins_parsed",
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


def _named(parameters) -> list[inspect.Parameter]:
    return [
        p
        for name, p in parameters.items()
        if name != "self" and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
    ]


def _signature_problems(
    ours: inspect.Signature, theirs: inspect.Signature
) -> list[str]:
    """What breaks when sqlglot calls our override as it calls its own:
    - each parameter we name is sqlglot's parameter at the same position,
      under the same name (an inserted, removed or renamed one upstream
      would otherwise bind an argument to the wrong name, or to none);
    - each parameter sqlglot has that we do not name reaches us through
      `*args` (any) or `**kwargs` (passed by keyword: sqlglot passes these
      by keyword, a positional call remains this test's blind spot)."""
    problems = []
    ours_named, theirs_named = _named(ours.parameters), _named(theirs.parameters)
    for position, parameter in enumerate(ours_named):
        if position >= len(theirs_named):
            problems.append(f"{parameter.name!r} is not sqlglot's")
        elif theirs_named[position].name != parameter.name:
            problems.append(
                f"position {position}: ours {parameter.name!r}, "
                f"sqlglot's {theirs_named[position].name!r}"
            )
    kinds = {p.kind for p in ours.parameters.values()}
    for parameter in theirs_named[len(ours_named) :]:
        if inspect.Parameter.VAR_POSITIONAL in kinds:
            continue
        if (
            inspect.Parameter.VAR_KEYWORD in kinds
            and parameter.kind is not parameter.POSITIONAL_ONLY
        ):
            continue
        problems.append(f"sqlglot's {parameter.name!r} does not reach the override")
    return problems


@pytest.mark.parametrize(("part", "own"), _PARTS, ids=[p for p, _ in _PARTS])
def test_overridden_methods_take_what_sqlglot_passes(part, own):
    base = getattr(Postgres, part)
    mismatched = []
    for name, attr in _defined(part).items():
        if name in own or not inspect.isfunction(attr):
            continue
        problems = _signature_problems(
            inspect.signature(attr), inspect.signature(getattr(base, name))
        )
        mismatched += [f"{name}: {problem}" for problem in problems]
    assert mismatched == [], mismatched


def _sig(text: str) -> inspect.Signature:
    namespace: dict = {}
    exec(f"def f{text}: pass", namespace)  # noqa: S102 — fixed test strings
    return inspect.signature(namespace["f"])


@pytest.mark.parametrize(
    ("theirs", "problem"),
    [
        # an upstream parameter inserted before ones we name
        ("(self, new, check_func=False, schema=False)", "position 0"),
        # renamed upstream
        ("(self, check=False, schema=False)", "position 0"),
        # removed upstream: we still name it
        ("(self, check_func=False)", "'schema' is not sqlglot's"),
    ],
)
def test_the_signature_rule_catches(theirs, problem):
    ours = _sig("(self, check_func=False, schema=False, **kwargs)")
    assert any(problem in p for p in _signature_problems(ours, _sig(theirs)))


def test_the_signature_rule_accepts_forwarded_extras():
    ours = _sig("(self, this, *args, **kwargs)")
    assert _signature_problems(ours, _sig("(self, this, a=1, *, b=2)")) == []
    keywords = _sig("(self, this, **kwargs)")
    assert _signature_problems(keywords, _sig("(self, this, a=1)")) == []
    assert _signature_problems(keywords, _sig("(self, this, a, /)")) != []


def test_the_tokenizer_is_sqlglots_own():
    # `FaithfulPostgres` reuses Postgres's tokenizer; a subclass would need
    # its own rows above.
    assert FaithfulPostgres.Tokenizer is Postgres.Tokenizer
