"""sqlglot AST validators for the MCP read-only SQL surface. Pure (no DB,
no Django imports). See `docs/architecture.md` for design /
"Watch out" / parser-check ordering rules."""

import itertools
import re
from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import sqlglot
import sqlglot.errors
from mcp_sql.schemas import OutcomeReason
from sqlglot import exp
from sqlglot.dialects.postgres import Postgres
from sqlglot.errors import ErrorLevel
from sqlglot.generator import Generator
from sqlglot.tokens import Token
from sqlglot.tokens import TokenType

DENIED_FUNCTIONS_EXACT: frozenset[str] = frozenset(
    {
        "copy",
        "current_setting",
        "set_config",
        # `dblink(text, text)` — bare two-arg overload — opens a one-shot
        # PG connection to an arbitrary remote host and ships SQL there.
        # The `dblink_*` prefix below catches `dblink_open` /
        # `dblink_connect` / `dblink_exec`, but the bare `dblink` is an
        # exact-name function. If the extension is installed, an MCP token
        # holder could exfiltrate through the DB host's network.
        "dblink",
        # `query_to_xml(text, ...)`, `table_to_xml(regclass, ...)`,
        # `cursor_to_xml(...)` and their `_schema` / `_and_xmlschema`
        # variants accept SQL as a text argument and EXECUTE it under
        # `mcp_readonly_role`. The inner SQL never enters this parser, so
        # every whitelist / SELECT_* / deny-list check is bypassed for the
        # nested query. The outer query also returns one XML scalar, so
        # per-row truncation is meaningless and per-cell byte cap is the
        # only remaining brake. Reject at the wrapper layer.
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "table_to_xml",
        "table_to_xmlschema",
        "table_to_xml_and_xmlschema",
        "cursor_to_xml",
        "cursor_to_xmlschema",
        # Server-state / identity leaks. PG returns version banners, role
        # names, and network topology via these built-ins — useful for an
        # attacker doing reconnaissance about what role the executor runs
        # as (the post-`SET LOCAL ROLE` view is `mcp_readonly_role`, but
        # `session_user` still leaks the underlying app login role) or
        # what PG version / patchset is deployed (CVE targeting).
        # None of these are needed by an LLM-driven business-table query.
        # Both spellings are listed where sqlglot maps the user-facing
        # form to a different canonical SQL name (e.g. `version()` parses
        # as `exp.CurrentVersion` whose `sql_name()` is `CURRENT_VERSION`).
        "version",
        "current_version",
        "current_database",
        "current_schema",
        "current_schemas",
        "current_user",
        "session_user",
        "user",
        "current_role",
        "current_catalog",
        "inet_server_addr",
        "inet_server_port",
        "inet_client_addr",
        "inet_client_port",
        "txid_current",
        "txid_current_snapshot",
        "row_security_active",
        # Sequence introspection / mutation. `mcp_readonly_role` has no
        # UPDATE grants so `setval` / `nextval` already 42501 at PG; the
        # parser-layer reject yields a clearer audit reason and stops
        # `currval`-style introspection too.
        "nextval",
        "setval",
        "currval",
    }
)
# Bare-keyword PG built-ins parse as `exp.Column(name=<keyword>, table=None)`
# when written without parentheses (`SELECT current_user` not
# `SELECT current_user()`). The function-deny-list walk doesn't see Column
# nodes, so the bare form would otherwise leak right past it.
DENIED_BARE_KEYWORDS: frozenset[str] = frozenset(
    {
        "current_user",
        "session_user",
        "user",
        "current_role",
        "current_catalog",
        "current_schema",
        "current_database",
    }
)
# `pg_*` covers `pg_read_file`, `pg_ls_dir`, `pg_database_size`,
# `pg_relation_size`, `pg_get_userbyid`, `pg_typeof`, … — many leak server
# state or table metadata even when direct catalog reads are blocked at the
# role-grant layer. `has_*` covers `has_table_privilege` /
# `has_database_privilege` / … — those return per-(role, object) privilege
# bits and are introspection tools, not query helpers. Both prefixes are
# opt-out: there is no allowlist today, since an agent doing exploration of
# whitelisted business tables does not need any of them. Revisit if a
# legitimate use case appears.
DENIED_FUNCTIONS_PREFIX: tuple[str, ...] = ("dblink_", "lo_", "pg_", "has_")
# Set-returning functions (SRFs). In a FROM clause these are caught by the
# empty-name `exp.Table` guard in `_check_tables`; in the PROJECTION they are
# not, and they fan one input row out to many — `generate_series` is the
# unbounded DoS amplifier, the json/regexp expanders fan out by their input
# size. sqlglot maps `generate_series`/`unnest` to TYPED nodes
# (`exp.GenerateSeries` / `exp.UDTF`, matched structurally in
# `_check_no_denied_functions`) only when written unqualified, so they are
# listed by name too (`pg_catalog.generate_series(...)`, review round 5);
# every other PG SRF parses as `exp.Anonymous` and is matched here by name.
# The LIMIT-injection + 5s `statement_timeout` already bound these —
# rejecting them at the parser yields a clean
# `DISALLOWED_CONSTRUCT` audit reason instead of a wasted backend slot, and an
# LLM business-table query never legitimately needs row-expansion built-ins.
# Not exhaustive of every PG SRF (extensions add more); the timeout/LIMIT
# backstop covers anything unlisted. Revisit if a legitimate use case appears.
DENIED_SRF_FUNCTIONS: frozenset[str] = frozenset(
    {
        "generate_series",
        "unnest",
        "generate_subscripts",
        "regexp_split_to_table",
        "regexp_matches",
        "json_array_elements",
        "json_array_elements_text",
        "jsonb_array_elements",
        "jsonb_array_elements_text",
        "json_each",
        "json_each_text",
        "jsonb_each",
        "jsonb_each_text",
        "json_object_keys",
        "jsonb_object_keys",
        "json_to_recordset",
        "jsonb_to_recordset",
        "json_populate_recordset",
        "jsonb_populate_recordset",
    }
)
SYSTEM_SCHEMAS: frozenset[str] = frozenset({"pg_catalog", "information_schema"})
# Postgres reads `x.f` / `(expr).f` as the call `f(x)` when `x` has no column
# `f` ("attribute notation"): `('server_version'::text).current_setting` is
# `current_setting('server_version')`. So a qualified name that is a denied
# function is refused like the call (review round 5) — except the denied
# functions attribute notation cannot reach, because they take no argument
# or need two or more (all of `has_*`), whose names are also ordinary column
# names (`t.version`, `t.user`, `t.has_access`).
_NOT_CALLABLE_AS_FIELD: frozenset[str] = frozenset(
    {
        "version",
        "current_version",
        "current_database",
        "current_schema",
        "current_user",
        "session_user",
        "user",
        "current_role",
        "current_catalog",
        "inet_server_addr",
        "inet_server_port",
        "inet_client_addr",
        "inet_client_port",
        "txid_current",
        "txid_current_snapshot",
        "set_config",
        "setval",
    }
)
# Functions that, called on a row through attribute notation (`t.to_jsonb`),
# return the whole row: refused as `SELECT_STAR` like `to_jsonb(t)`.
_WHOLE_ROW_FIELD_FUNCTIONS: frozenset[str] = frozenset(
    {
        "concat",
        "quote_literal",
        "quote_nullable",
        "record_out",
        "record_send",
        "to_json",
        "to_jsonb",
        "row_to_json",
        "json_agg",
        "jsonb_agg",
        "array_agg",
        "json_build_array",
        "jsonb_build_array",
        "json_build_object",
        "jsonb_build_object",
        "hstore",
    }
)


def _keep_precision(name: str) -> Callable[[Generator, exp.Func], str]:
    def render(self: Generator, node: exp.Func) -> str:
        precision = self.sql(node, "this")
        return f"{name}({precision})" if precision else name

    return render


def _json_arrow(operator: str, base: Any) -> Callable[[Generator, exp.Expression], str]:
    """Render `a -> b` / `a ->> b` with the right operand as written (the
    parser keeps it raw: see `FaithfulPostgres`)."""

    def render(self: Generator, node: exp.Expression) -> str:
        if isinstance(node.expression, exp.JSONPath):
            return str(base(self, node))
        return f"{self.sql(node, 'this')} {operator} {self.sql(node, 'expression')}"

    return render


# Postgres reads a run of these characters as ONE operator (`~-`, `-~`,
# `%-`), see `_check_operator_runs`.
_OPERATOR_CHARS = frozenset("+-*/<>=~!@#%^&|`?")
# A multi-character operator may end in `+` / `-` only if it contains one of
# these (otherwise Postgres drops the trailing `+` / `-` from it).
_OPERATOR_KEEPS_SIGN = frozenset("~!@#%^&|`?")


def _cast_bound_operand(build: Any) -> Callable[[Any, Any, Any], Any]:
    def parse(self: Any, this: Any, operand: Any) -> Any:
        return build(self, this, self._arrow_operand(operand))

    return parse


def _parenthesised_not(base: Any) -> Callable[[Generator, exp.Expression], str]:
    def render(self: Generator, node: exp.Expression) -> str:
        text = str(base(self, node))
        parent = node.parent
        operand = isinstance(
            parent, (exp.Binary, exp.Unary, exp.In, exp.Between, _IsNot)
        ) and not isinstance(parent, (exp.Connector, exp.Not, exp.Paren))
        return f"({text})" if operand else text

    return render


def _prefix_operator(symbol: str) -> Callable[[Generator, exp.Expression], str]:
    """Render a prefix operator, with a space before an operand that starts
    with an operator character: `~ -1` must not come back as `~-1`, which
    Postgres reads as the (non-existent) prefix operator `~-`."""

    def render(self: Generator, node: exp.Expression) -> str:
        operand = self.sql(node, "this")
        gap = " " if operand[:1] in _OPERATOR_CHARS else ""
        return f"{symbol}{gap}{operand}"

    return render


def _number_as_written_or(base: Any) -> Callable[[Any, Token], Any]:
    """A primary parser for a number / bit-string token: the constant as
    written (`_number_as_written`), else sqlglot's own `base` reading."""

    def parse(self: Any, token: Token) -> Any:
        return self._number_as_written(token) or base(self, token)

    return parse


_IS_NOT_TOKENS = 3  # `IS`, `NOT` and the value


class _IsNot(exp.Expression, exp.Condition):
    """`x IS NOT NULL` / `x NOTNULL` / `x IS NOT TRUE` / `x IS NOT FALSE` as
    written. sqlglot builds `NOT (x IS ...)` for them (`IS NOT NULL` only on
    versions without `Is(negate=...)`, 30.7) and renders `NOT x IS ...`:
    different for a row value (`(1, NULL) IS NOT NULL` is false, `NOT
    (1, NULL) IS NULL` true), and inside a comparison or an IS chain
    Postgres then reads the `NOT` elsewhere (`y > 2 IS NOT TRUE` came back
    `y > NOT 2 IS TRUE`)."""

    arg_types = {"this": True, "expression": True}


# Everything Postgres accepts as a numeric constant, including the PG16 forms
# (`0x1F`, `0o17`, `0b101`, `1_000`, `1_000.5e1_0`).
_PG_NUMBER_RE = re.compile(
    r"0[xX](?:_?[0-9a-fA-F])+|0[oO](?:_?[0-7])+|0[bB](?:_?[01])+"
    r"|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][-+]?\d(?:_?\d)*)?"
)
# sqlglot reads `0x1F` / `0b101` as the bit strings `x'1F'` / `b'101'`.
_PG_PREFIXED_NUMBER = ("0x", "0X", "0b", "0B")

# The postgres dialect's parser / generator classes, as bases (sqlglot types
# them as class attributes, which mypy will not take as a base class).
_PostgresParser: Any = Postgres.Parser
_PostgresGenerator: Any = Postgres.Generator

# The only function names sqlglot still builds into its own node classes:
# the ones the checks below match structurally (`COUNT(*)`'s star carve-out,
# the set-returning `generate_series` / `unnest`). See `FaithfulPostgres`.
_TYPED_FUNCTIONS = frozenset({"COUNT", "GENERATE_SERIES", "UNNEST"})
# Postgres's keyword-syntax functions (`EXTRACT(year FROM d)`,
# `SUBSTRING(s FROM 2 FOR 3)`, `TRIM(BOTH 'x' FROM s)`, `CAST(x AS t)`, the
# SQL/JSON constructors, ...), which only sqlglot's own parsers can read.
_SYNTAX_FUNCTIONS = frozenset(
    {
        "CAST",
        "EXTRACT",
        "JSON_OBJECT",
        "JSON_OBJECTAGG",
        "JSON_TABLE",
        "NORMALIZE",
        "OVERLAY",
        "POSITION",
        "SUBSTRING",
        "TRIM",
        "XMLELEMENT",
        "XMLTABLE",
    }
)
_SYNTAX_NO_PAREN_FUNCTIONS = frozenset({"ANY", "CASE", "VARIADIC"})
# Words that make a `json_object(...)` call the SQL/JSON constructor
# (`json_object('a': 1)`, `json_object(KEY 'a' VALUE 1 RETURNING jsonb)`)
# rather than Postgres's `json_object(text[] [, text[]])` function.
_SQL_JSON_WORDS = frozenset(
    {"ABSENT", "FORMAT", "KEY", "ON", "RETURNING", "UNIQUE", "VALUE", "WITH", "WITHOUT"}
)


class FaithfulPostgres(Postgres):
    """sqlglot's postgres dialect, reading and rendering Postgres SQL as
    written. The executor runs sqlglot's rendering of the query, so any
    "normalising" rewrite that is not exact is a wrong answer (or a wrong
    column name). What it changes from the stock dialect:

    - Function calls stay as written. Stock sqlglot maps hundreds of names
      onto its own node classes and renders them back in its canonical
      spelling, which is not always the same function or the same column
      name: `like(a, b)` → `b LIKE a` (arguments swapped), `regexp_like(x,
      p, 'i')` → `x ~ p` (flags dropped), `date_part` → `EXTRACT` (numeric,
      not double precision), `log10(x)` → `LOG(10, x)` (numeric),
      `to_char(d, '%Y')` → `TO_CHAR(d, 'YYYY')` (format "translated"),
      `date_add(t, i, zone)` → `t + i` (zone dropped), `strpos` →
      `POSITION` and `now()` → `CURRENT_TIMESTAMP` (other column names),
      `nvl` / `iif` / `last_day` → their Postgres equivalents (where Postgres
      itself rejects the call). Every plain call `name(args)` now parses as
      `exp.Anonymous` and renders exactly as written, except the few the
      checks match structurally (`_TYPED_FUNCTIONS`) and Postgres's
      keyword-syntax functions (`_SYNTAX_FUNCTIONS`), whose renderings mean
      the same to Postgres. `json_object(a, b)` (the plain function) is told
      apart from the SQL/JSON constructor by its arguments.
    - `INTERVAL '1 day 02:03:04'` / `INTERVAL '3 days ago'` keep their
      string: sqlglot canonicalised them to their first `<n> <unit>` part.
    - `j -> k` / `j ->> k` keep their right operand as written: sqlglot
      turned it into a JSON path, dropping an empty key (`j -> ''`) and, on
      30.7, a quote inside the key.
    - A quoted type name stays quoted (`x::"char"`, `x::"Numeric"(10, 2)`):
      sqlglot folded it onto its builtin (`CHAR`, `DECIMAL`), a different
      type or one Postgres does not have under that spelling.
    - `bit '011'` / `char 'abc'` (no length) keep their full value: sqlglot
      rendered `CAST('011' AS BIT)`, which Postgres reads as `bit(1)`.
    - Numeric constants keep their spelling, including the PG16 forms
      (`0x1F`, `0o17`, `0b101`, `1_000`), which sqlglot read as a bit
      string or as a number with an alias (`1 AS _000`). Postgres then reads
      the text it would have read from the agent.
    - `x IS NOT NULL` / `x NOTNULL` stay as written on sqlglot versions that
      build `NOT x IS NULL` (different for a row value).
    - `current_timestamp` / `current_time` keep the precision written.

    Used for every parse, tokenization and rendering in this module. The
    tokenizers are the postgres dialect's own classes, assigned rather than
    inherited: sqlglot's dialect metaclass derives a fresh tokenizer class
    for a subclass that does not name one, and that derived class reads
    `E'\\''` differently (verified on 30.7 and 30.21).
    """

    Tokenizer = Postgres.Tokenizer
    JSONPathTokenizer = Postgres.jsonpath_tokenizer_class

    class Parser(_PostgresParser):
        FUNCTIONS = {
            name: build
            for name, build in Postgres.Parser.FUNCTIONS.items()
            if name in _TYPED_FUNCTIONS
        }
        FUNCTION_PARSERS = {
            **{
                name: parse
                for name, parse in Postgres.Parser.FUNCTION_PARSERS.items()
                if name in _SYNTAX_FUNCTIONS
            },
            "JSON_OBJECT": lambda self: self._parse_json_object_or_call(),
        }
        NO_PAREN_FUNCTION_PARSERS = {
            name: parse
            for name, parse in Postgres.Parser.NO_PAREN_FUNCTION_PARSERS.items()
            if name in _SYNTAX_NO_PAREN_FUNCTIONS
        }
        # `QUALIFY` is not Postgres SQL, and `qualify` is an ordinary name to
        # Postgres (`FROM t qualify (c1)`). sqlglot read it as the clause and
        # moved the LIMIT before the filter; it is a name here, so the clause
        # is a syntax error, as in Postgres.
        QUERY_MODIFIER_PARSERS = {
            kind: parse
            for kind, parse in Postgres.Parser.QUERY_MODIFIER_PARSERS.items()
            if kind != TokenType.QUALIFY
        }
        ID_VAR_TOKENS = Postgres.Parser.ID_VAR_TOKENS | {TokenType.QUALIFY}
        TABLE_ALIAS_TOKENS = Postgres.Parser.TABLE_ALIAS_TOKENS | {TokenType.QUALIFY}
        PRIMARY_PARSERS = {
            **Postgres.Parser.PRIMARY_PARSERS,
            **{
                kind: _number_as_written_or(Postgres.Parser.PRIMARY_PARSERS[kind])
                for kind in (
                    TokenType.NUMBER,
                    TokenType.HEX_STRING,
                    TokenType.BIT_STRING,
                )
            },
        }
        TYPE_LITERAL_PARSERS = {
            **Postgres.Parser.TYPE_LITERAL_PARSERS,
            exp.DType.BIT: lambda self, this, to: self._unrestricted(this, to, "bit"),
            exp.DType.CHAR: lambda self, this, to: self._unrestricted(
                this, to, "bpchar"
            ),
            exp.DType.NCHAR: lambda self, this, to: self._unrestricted(
                this, to, "bpchar"
            ),
        }
        # sqlglot 30.21 parses `->` / `->>` at the binary-operator tier
        # (`JSON_OPERATORS`), 30.7 as column operators: keep the right
        # operand raw in whichever table this sqlglot uses.
        _ARROWS = {
            TokenType.ARROW: lambda self, this, path: self.expression(
                exp.JSONExtract(this=this, expression=self._arrow_operand(path))
            ),
            TokenType.DARROW: lambda self, this, path: self.expression(
                exp.JSONExtractScalar(this=this, expression=self._arrow_operand(path))
            ),
        }
        if getattr(Postgres.Parser, "JSON_OPERATORS", None):
            JSON_OPERATORS = {**Postgres.Parser.JSON_OPERATORS, **_ARROWS}
        else:
            # Every operator parsed this way (`#>`, `#>>`, `?`, ...) gets its
            # right operand's `::type` (see `_arrow_operand`).
            COLUMN_OPERATORS = {
                **{
                    kind: (
                        build
                        if kind in {TokenType.DCOLON, TokenType.DOT, TokenType.DOTCOLON}
                        or build is None
                        else _cast_bound_operand(build)
                    )
                    for kind, build in Postgres.Parser.COLUMN_OPERATORS.items()
                },
                **_ARROWS,
            }

        def _arrow_operand(self, path: exp.Expression) -> exp.Expression:
            """The right operand of a JSON operator. Where sqlglot parses
            them as column operators (30.7), a `::type` right after the
            operand was applied to the whole `j -> 'a'` / `j #> '{a}'` /
            `j ? 'k'`; Postgres binds `::` tighter (`j -> ('a'::text)`), so
            it is taken onto the operand."""
            if getattr(Postgres.Parser, "JSON_OPERATORS", None):
                return path  # 30.21: the operand was parsed as a full term
            tokens = self._tokens
            while (
                self._index < len(tokens)
                and tokens[self._index].token_type == TokenType.DCOLON
            ):
                self._advance()
                to = self._parse_types()
                if to is None:
                    self.raise_error("Expected type after '::'")
                path = self.expression(exp.Cast(this=path, to=to))
            return path

        def _number_as_written(self, token: Token) -> exp.Expression | None:
            """A numeric constant spelled the way Postgres reads it, or
            `None` to keep sqlglot's reading. sqlglot splits `1_000` into
            `1` and `_000` (an alias) and reads `0x1F` as a bit string; the
            whole constant is taken as one literal, rendered verbatim."""
            sql = self.sql
            prefixed = token.token_type in {TokenType.HEX_STRING, TokenType.BIT_STRING}
            if (
                prefixed
                and sql[token.start : token.start + 2] not in _PG_PREFIXED_NUMBER
            ):
                return None  # x'1F' / b'101': a real bit string
            match = _PG_NUMBER_RE.match(sql, token.start)
            if match is None or (not prefixed and match.end() <= token.end + 1):
                return None  # sqlglot read it whole already
            end = match.end()
            if end < len(sql) and (sql[end].isalnum() or sql[end] in "_$"):
                return None  # "trailing junk" to PG16: keep sqlglot's reading
            index, tokens = self._index, self._tokens
            while self._index < len(tokens) and tokens[self._index].start < end:
                self._advance()
            if tokens[self._index - 1].end != end - 1:
                self._retreat(index)
                return None
            return exp.Literal.number(sql[token.start : end])

        def _parse_primary(self) -> exp.Expression | None:
            # `.5_0` (PG16): sqlglot reads `.5` and then an alias `_0`.
            tokens, index = self._tokens, self._index
            curr = tokens[index] if index < len(tokens) else None
            nxt = tokens[index + 1] if index + 1 < len(tokens) else None
            if (
                curr is not None
                and nxt is not None
                and curr.token_type == TokenType.DOT
                and nxt.token_type == TokenType.NUMBER
                and nxt.start == curr.end + 1
            ):
                self._advance()
                literal = self._number_as_written(curr)
                if literal is not None:
                    return literal
                self._retreat(index)
            primary: exp.Expression | None = super()._parse_primary()
            return primary

        def _unrestricted(
            self, this: exp.Expression, to: exp.DataType, type_name: str
        ) -> exp.Expression:
            """`bit '011'` / `char 'abc'`: a typed literal without a length
            keeps its whole value, which `CAST(... AS BIT)` / `CHAR` (length
            1) would not. The quoted catalog name means the same
            unrestricted type to Postgres."""
            if not to.expressions:
                to = exp.DataType(
                    this=exp.DType.USERDEFINED,
                    kind=exp.to_identifier(type_name, quoted=True),
                )
            cast: exp.Expression = self.expression(exp.Cast(this=this, to=to))
            return cast

        def _parse_types(self, *args: Any, **kwargs: Any) -> exp.Expression | None:
            index = self._index
            token = self._tokens[index] if index < len(self._tokens) else None
            parsed: exp.Expression | None = super()._parse_types(*args, **kwargs)
            if (
                token is not None
                and token.token_type == TokenType.IDENTIFIER
                and isinstance(parsed, exp.DataType)
            ):
                _keep_quoted_type(parsed, token)
            return parsed

        def _parse_interval_span(
            self, this: exp.Expression, *args: Any, **kwargs: Any
        ) -> exp.Interval:
            written = this.name if this is not None and this.is_string else None
            interval: exp.Interval = super()._parse_interval_span(this, *args, **kwargs)
            if (
                written is not None
                and len(exp.INTERVAL_STRING_RE.findall(written)) == 1
                and not exp.INTERVAL_STRING_RE.fullmatch(written)
                and not isinstance(interval.args.get("unit"), exp.IntervalSpan)
            ):
                # sqlglot kept only the first `<n> <unit>` of the string.
                interval.set("this", exp.Literal.string(written))
                interval.set("unit", None)
            return interval

        def _parse_json_object_or_call(self) -> exp.Expression | None:
            if self._json_key_keyword():
                # `json_object(KEY 'a' VALUE 1)`: Postgres has no `KEY` here
                # (it reads `KEY 'a'` as a literal of a type `key`); sqlglot
                # would run the SQL/JSON constructor.
                self.raise_error("KEY ... VALUE is not PostgreSQL syntax")
            if self._plain_call_arguments():
                args = self._parse_csv(self._parse_assignment)
                call: exp.Expression = self.expression(
                    exp.Anonymous(this="json_object", expressions=args)
                )
                return call
            constructor: exp.Expression | None = self._parse_json_object()
            return constructor

        def _json_key_keyword(self) -> bool:
            tokens, depth, j = self._tokens, 0, self._index
            while j < len(tokens):
                kind = tokens[j].token_type
                if kind == TokenType.R_PAREN and depth == 0:
                    return False
                depth += (kind == TokenType.L_PAREN) - (kind == TokenType.R_PAREN)
                if (
                    depth == 0
                    and tokens[j].text.upper() == "KEY"
                    and not _alone_in_argument(tokens, j, self._index)
                ):
                    return True
                j += 1
            return False

        def _plain_call_arguments(self) -> bool:
            """True if the tokens up to the closing parenthesis are plain
            comma-separated arguments (no SQL/JSON key-value syntax)."""
            tokens, depth, j = self._tokens, 0, self._index
            if j >= len(tokens) or tokens[j].token_type == TokenType.R_PAREN:
                return False
            while j < len(tokens):
                kind = tokens[j].token_type
                if kind == TokenType.R_PAREN and depth == 0:
                    return True
                depth += (kind == TokenType.L_PAREN) - (kind == TokenType.R_PAREN)
                if depth == 0 and (
                    kind == TokenType.COLON
                    or (
                        tokens[j].text.upper() in _SQL_JSON_WORDS
                        and not _alone_in_argument(tokens, j, self._index)
                    )
                ):
                    return False
                j += 1
            return False

        def expression(self, instance: Any, *args: Any, **kwargs: Any) -> Any:
            if (
                type(instance) is exp.Not
                and type(instance.this) is exp.Is
                and not instance.this.args.get("negate")  # `NOT x IS NOT NULL`
                and isinstance(instance.this.expression, (exp.Null, exp.Boolean))
                and self._wrote_is_not()
            ):
                instance = _IsNot(
                    this=instance.this.this, expression=instance.this.expression
                )
            return super().expression(instance, *args, **kwargs)

        def _wrote_is_not(self) -> bool:
            """The tokens just read are `IS NOT NULL|UNKNOWN|TRUE|FALSE` or
            `NOTNULL` (not `NOT x IS ...`). `IS NOT UNKNOWN` is kept as `IS
            NOT NULL`, the same test at the same precedence."""
            tokens, end = self._tokens, self._index
            last = tokens[max(0, end - 3) : end]
            kinds = [token.token_type for token in last]
            if kinds[-1:] == [TokenType.NOTNULL]:
                return True
            return (
                kinds[:2] == [TokenType.IS, TokenType.NOT]
                and len(last) == _IS_NOT_TOKENS
                and last[2].text.upper() in {"NULL", "UNKNOWN", "TRUE", "FALSE"}
            )

    class Generator(_PostgresGenerator):
        # `string_agg(DISTINCT a, ',')`: Postgres takes DISTINCT over several
        # aggregate arguments; stock sqlglot rewrites it into a CASE tuple.
        MULTI_ARG_DISTINCT = True
        TRANSFORMS = {
            **Postgres.Generator.TRANSFORMS,
            exp.CurrentTimestamp: _keep_precision("CURRENT_TIMESTAMP"),
            exp.CurrentTime: _keep_precision("CURRENT_TIME"),
            exp.JSONExtract: _json_arrow(
                "->", Postgres.Generator.TRANSFORMS[exp.JSONExtract]
            ),
            exp.JSONExtractScalar: _json_arrow(
                "->>", Postgres.Generator.TRANSFORMS[exp.JSONExtractScalar]
            ),
            _IsNot: lambda self, node: (
                f"{self.sql(node, 'this')} IS NOT {self.sql(node, 'expression')}"
            ),
            # A `NOT` that is an operand (`(g NOT LIKE 'a%') IS TRUE`, which
            # sqlglot 30.7 holds as `NOT (g LIKE ...)`) keeps its scope:
            # rendered bare, Postgres would read it as applying to the rest.
            exp.Not: _parenthesised_not(Postgres.Generator.not_sql),
            # `a ^ b` as written (sqlglot: `POWER(a, b)`, another column name,
            # and `~2 ^ 2` read with sqlglot's precedence, not Postgres's).
            exp.Pow: lambda self, node: (
                f"{self.sql(node, 'this')} ^ {self.sql(node, 'expression')}"
            ),
            # sqlglot flattens a chain of `IS` into one operator, so
            # `x IS NOT NULL IS TRUE` (30.13+) came back `x IS NULL IS TRUE`.
            exp.Is: lambda self, node: (
                f"{self.sql(node, 'this')} "
                f"{'IS NOT' if node.args.get('negate') else 'IS'} "
                f"{self.sql(node, 'expression')}"
            ),
            exp.BitwiseNot: _prefix_operator("~"),
            exp.Neg: _prefix_operator("-"),
        }


def _alone_in_argument(tokens: list[Token], j: int, first: int) -> bool:
    """True if `tokens[j]` is a whole argument on its own (a column named
    `value` / `key`), not a keyword inside one."""
    before = tokens[j - 1].token_type if j > first else TokenType.COMMA
    after = tokens[j + 1].token_type if j + 1 < len(tokens) else TokenType.R_PAREN
    return before == TokenType.COMMA and after in {TokenType.COMMA, TokenType.R_PAREN}


def _keep_quoted_type(parsed: exp.DataType, token: Token) -> None:
    """Make the type `parsed` from the double-quoted name `token` render as
    that quoted name (Postgres resolves it case-sensitively, as written)."""
    base = parsed
    while base.this == exp.DType.ARRAY and base.expressions:
        inner = base.expressions[0]
        if not isinstance(inner, exp.DataType):
            return
        base = inner
    if base.this == exp.DType.USERDEFINED:
        return  # already the name as written
    name = exp.to_identifier(token.text, quoted=True)
    name.update_positions(token)
    base.set("this", exp.DType.USERDEFINED)
    base.set("kind", name)


class QueryRejectedError(Exception):
    """Raised by `parse_and_validate` on any AST-layer reject.

    `reason` is the closed `OutcomeReason` value that goes into
    `MCPQueryLog.rejection_reason`. `detail` is the human message that
    surfaces in the `hint` field returned to the agent and in the audit
    row's `error` field for triage.
    """

    def __init__(self, reason: OutcomeReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ParsedQuery:
    """Immutable parser output. Frozen so executor never mutates the AST or
    normalised SQL between parsing and audit-row write."""

    ast: exp.Query
    normalized_sql: str
    referenced_tables: set[str]


def parse_and_validate(
    raw_sql: str,
    *,
    allowed_tables: set[str],
    ban_select_star: bool = True,
    table_columns: Mapping[str, frozenset[str]] | None = None,
) -> ParsedQuery:
    """Parse `raw_sql` and run every AST-layer check.

    `allowed_tables` is the set of `db_table` names the agent may read,
    pre-resolved by the caller (`mcp_sql.grants.declared_tables`).
    Matching is case-insensitive on the table name only (schema is rejected
    unconditionally when it's a system schema).

    `table_columns` maps a whitelisted `db_table` (lowercase) to its column
    names (lowercase), so that `t.name` is known to be a column when `t`
    has one (`_attribute_calls`); a table missing from it is treated as
    having no columns of a denied function's name.

    Raises only `QueryRejectedError`. sqlglot fails on hostile input with
    far more than `ParseError`: the tokenizer's `TokenError` (an
    unterminated literal), a bare `re.error` for some `UESCAPE` clauses,
    and (before `FaithfulPostgres` kept calls as written) plain
    `ValueError` / `TypeError` / `IndexError` / `KeyError` /
    `decimal.InvalidOperation` from its function builders. Every exception
    other than our own rejection becomes a `PARSE_ERROR`, so `run_query`
    audits it like any other rejection instead of letting it escape
    unaudited.
    """
    return _checked(
        raw_sql,
        allowed_tables=allowed_tables,
        ban_select_star=ban_select_star,
        normalize=True,
        table_columns=table_columns or {},
    )


def _checked(
    raw_sql: str,
    *,
    allowed_tables: set[str],
    ban_select_star: bool,
    normalize: bool,
    table_columns: Mapping[str, frozenset[str]],
) -> ParsedQuery:
    """`_parse_and_validate`, with any non-rejection exception mapped to
    `PARSE_ERROR` (see `parse_and_validate`)."""
    try:
        return _parse_and_validate(
            raw_sql,
            allowed_tables=allowed_tables,
            ban_select_star=ban_select_star,
            normalize=normalize,
            table_columns=table_columns,
        )
    except QueryRejectedError:
        raise
    except Exception as exc:
        msg = f"SQL could not be parsed ({type(exc).__name__}): {exc}"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg) from exc


def _parse_and_validate(
    raw_sql: str,
    *,
    allowed_tables: set[str],
    ban_select_star: bool,
    normalize: bool,
    table_columns: Mapping[str, frozenset[str]],
) -> ParsedQuery:
    try:
        parsed = sqlglot.parse(raw_sql, dialect=FaithfulPostgres)
    except sqlglot.errors.ParseError as exc:
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, str(exc)) from exc
    except RecursionError as exc:
        # sqlglot's parser is recursive descent; a deeply-nested SELECT
        # (thousands of parens / subqueries, well within the auth-layer
        # 64 KiB body cap) overflows Python's recursion limit. RecursionError
        # is NOT a ParseError, so without this it escapes `run_query`'s
        # `except QueryRejectedError`, surfaces as an unaudited 500, and
        # tears down the per-request FastMCP lifespan mid-dispatch. Convert
        # it to a normal PARSE_ERROR reject so every adversarial input still
        # writes exactly one audit row. The handler does minimal work (a
        # short constant message) so it stays within the stack headroom
        # Python restores after the RecursionError.
        msg = "SQL nesting is too deep to parse"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg) from exc

    # sqlglot emits `exp.Semicolon` nodes for trailing `;` and similar
    # whitespace artefacts. Filtering on `is not None` alone would treat
    # `SELECT 1;` as a two-statement payload and reject as MULTI_STATEMENT.
    statements = [
        p for p in parsed if p is not None and not isinstance(p, exp.Semicolon)
    ]
    if not statements:
        msg = "Empty SQL input"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg)
    if len(statements) > 1:
        msg = f"Got {len(statements)} statements; only one is allowed"
        raise QueryRejectedError(OutcomeReason.MULTI_STATEMENT, msg)

    ast = statements[0]

    # Root must be a SELECT-shaped query (Select / Union / Intersect / Except).
    # exp.Query is the sqlglot base class for these; INSERT/UPDATE/DELETE and
    # Command-shaped statements (EXPLAIN, CALL, DO, SET, BEGIN, ...) are not.
    if not isinstance(ast, exp.Query):
        msg = f"Root is {type(ast).__name__}, not a SELECT-shaped query"
        raise QueryRejectedError(OutcomeReason.NON_SELECT_ROOT, msg)

    # Order matters: security-relevant checks fire before ergonomic ones so
    # the audit reason names the actual problem. WRITEABLE_CTE before any
    # RETURNING-bearing construct so a `WITH a AS (DELETE ... RETURNING ...)`
    # attributes to the writeable CTE, not the incidentally-present
    # RETURNING (which the bare top-level path can't reach anyway —
    # `exp.Returning` only appears under write nodes, which NON_SELECT_ROOT
    # rejects first). Tables before SELECT_STAR so `SELECT * FROM pg_class`
    # attributes to the system schema, not the ergonomic star rule.
    tokens = _check_lexical_fidelity(raw_sql, ast)
    _check_ctes_read_only(ast)
    _check_no_recursive_cte(ast)
    _check_no_select_into(ast)
    _check_no_offset(ast)
    _check_no_fetch(ast)
    _check_no_locking_reads(ast)
    referenced_tables = _check_tables(ast, allowed_tables=allowed_tables)
    _check_no_denied_functions(ast, table_columns)
    _check_no_denied_calls(tokens, ast)
    _check_no_bare_keyword_columns(ast)
    if ban_select_star:
        _check_no_select_star(ast)
        _check_no_whole_row_refs(ast, table_columns)

    # The AST-walk checks above are iterative (sqlglot's `find_all` uses an
    # explicit stack), so they can't overflow. `Generator.sql()` recurses by
    # tree depth, though — a parseable-but-pathologically-deep AST can survive
    # `sqlglot.parse` yet overflow here. Convert that to a PARSE_ERROR reject
    # so `parse_and_validate` NEVER leaks `RecursionError` to its callers.
    if not normalize:  # re-validating rendered text: nobody reads it
        return ParsedQuery(
            ast=ast, normalized_sql="", referenced_tables=referenced_tables
        )
    try:
        normalized_sql = ast.sql(dialect=FaithfulPostgres, normalize=True)
    except RecursionError as exc:
        msg = "SQL nesting is too deep to serialize"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg) from exc
    return ParsedQuery(
        ast=ast,
        normalized_sql=normalized_sql,
        referenced_tables=referenced_tables,
    )


# What PostgreSQL accepts as an unquoted identifier: a letter (any Unicode
# letter) or underscore, then letters, digits, underscores or `$`.
_UNQUOTED_IDENTIFIER_RE = re.compile(r"[^\W\d]\w*(?:[$]\w*)*")


def _check_lexical_fidelity(raw_sql: str, ast: exp.Query) -> list[Token]:
    """Reject input whose re-serialization by sqlglot is not faithful.

    The executor sends sqlglot's re-emission of the checked AST to
    Postgres, not `raw_sql`, so what runs is only what was checked if the
    re-emission means the same thing to Postgres. The known gaps (ledger
    F32 and its variants, review rounds 2-3), across the supported sqlglot
    range:

    - An escape-string literal (`E'…'`, any case — sqlglot's `BYTE_STRING`
      token in the postgres dialect) is decoded on parse but re-emitted with
      its backslashes un-escaped: `E'\\\\'` (one backslash) comes back as
      `e'\\'`, which swallows its closing quote and turns later literal text
      into SQL; `E'a\\\\nb'` comes back as a newline. Any such literal
      containing a backslash is rejected; one without (`E'it''s'`) is
      faithful and allowed. Checked on the raw token text, because the
      parsed value no longer shows which escapes were written.
    - An identifier written as a string constant (`AS $$…$$`,
      `AS $t$…$t$`, `AS 'x'`, `AS E'x'`) — which Postgres itself refuses —
      becomes an identifier whose text sqlglot re-emits, unquoted for the
      dollar forms, so `AS $$x, version() AS v$$` re-emits as two
      projections and `AS $$x; RESET ROLE; …$$` as several statements.
      Every identifier must be written as a plain or double-quoted
      identifier (checked on its source text, via sqlglot's position
      metadata).
    - A Unicode-escape literal or identifier (`U&'…'`, `U&"…"`, any case):
      sqlglot 30.7 tokenizes it as a column `U`, a bitwise `&` and a plain
      string, and re-emits `U & '…'`, which Postgres then evaluates as
      exactly that — different rows than the original text. Rejected on
      every sqlglot version, by its source text: the `U` / `u` adjacent to
      `&` adjacent to a quote, or (newer sqlglot) one `UNICODE_STRING`
      token. `U & 'x'` with spaces is a real operator and stays allowed.
    - A double-quoted name followed by `(` that sqlglot does not keep as
      written: Postgres resolves `"Count"(x)` / `"Extract"(...)`
      case-sensitively (no such function), but sqlglot folds the few names
      it still builds into its own nodes (`FaithfulPostgres`) onto the
      builtin. Judged on the parsed tree: the quoted name is fine where the
      tree keeps it — a function sqlglot keeps as written
      (`"lower"(x)`, `public."Lower"(x)`), an alias's or CTE's column list
      (`AS "s"(c1)`, `WITH "q"(c1) AS (...)`), a quoted type with modifiers
      (`::"numeric"(10, 2)`) — and refused anywhere else.
    - Adjacent string constants (`'a' 'b'`): sqlglot always reads them as
      `CONCAT('a', 'b')`; Postgres joins them only across a newline (on one
      line it is a syntax error) and names the column differently.
    - A dollar-quote tag Postgres does not accept (`$u&$...$u&$`, a tag
      starting with a digit): sqlglot reads a string where Postgres refuses
      the statement.
    - Operator characters written together that Postgres reads as one
      operator and sqlglot as several (`2 %-3`: Postgres `%-`, sqlglot
      `% -`; `~-1`): `_check_operator_runs`.

    Returns the tokens (the denied-call check reuses them).

    The executor's round-trip check (`parser.render_for_execution`) is the
    backstop for anything else of this class.
    """
    tokens = FaithfulPostgres().tokenize(raw_sql)
    # Where the tree keeps a quoted name as written (see above).
    kept_names = {
        ident.meta.get("start")
        for ident in ast.find_all(exp.Identifier)
        if isinstance(ident.parent, (exp.Anonymous, exp.DataType, exp.TableAlias))
    }
    for i in range(len(tokens)):
        problem = _token_problem(raw_sql, tokens, i, kept_names)
        if problem is not None:
            raise QueryRejectedError(OutcomeReason.UNSAFE_LITERAL, problem)
    _check_operator_runs(raw_sql, tokens)
    for ident in ast.find_all(exp.Identifier):
        start, end = ident.meta.get("start"), ident.meta.get("end")
        written = (
            raw_sql[start : end + 1] if start is not None and end is not None else None
        )
        if written is not None:
            # As written: a plain identifier or a double-quoted one.
            faithful = written.startswith('"') or bool(
                _UNQUOTED_IDENTIFIER_RE.fullmatch(written)
            )
        else:
            # No source position (sqlglot synthesized it): judge the name.
            faithful = ident.quoted or bool(
                _UNQUOTED_IDENTIFIER_RE.fullmatch(ident.name)
            )
        if not faithful:
            msg = (
                f"Identifier {written or ident.name!r} is written as a string "
                "constant; use a plain or double-quoted identifier"
            )
            raise QueryRejectedError(OutcomeReason.UNSAFE_LITERAL, msg)
    return tokens


# String-constant tokens of sqlglot's postgres dialect (on every 30.x).
_STRING_TOKENS = frozenset(
    {
        TokenType.STRING,
        TokenType.BYTE_STRING,
        TokenType.HEREDOC_STRING,
        TokenType.NATIONAL_STRING,
        TokenType.RAW_STRING,
        TokenType.BIT_STRING,
        TokenType.HEX_STRING,
        TokenType.UNICODE_STRING,
    }
)
# A Postgres dollar-quote opener: `$$` or `$tag$`, the tag an identifier
# without `$` (sqlglot also accepts `$u&$...$u&$`, which Postgres rejects).
_DOLLAR_TAG_RE = re.compile(r"\$(?:[^\W\d]\w*)?\$")


# Postgres operators sqlglot reads from several tokens and puts back
# together (`!~` is `!` and `~` to its tokenizer, a negated regex match to
# its parser). `^@` (starts with) is not put back together — it renders as
# invalid SQL and fails at execution, as before — but it is not refused.
_REASSEMBLED_OPERATORS = frozenset({"!~", "!~*", "!~~", "!~~*", "<<", ">>", "^@"})


def _check_operator_runs(raw_sql: str, tokens: list[Token]) -> None:
    """Refuse operator characters written together that Postgres lexes into
    different operators than sqlglot reads. Postgres takes the longest run
    of operator characters as one operator name (keeping a trailing `+` /
    `-` only when the run contains one of `~!@#%^&|`?`): `2 %-3` is the
    operator `%-`, `y=~1` the operator `=~`, `-~y` the prefix operator `-~`
    (none exist: errors), while sqlglot reads `2 % -3`, `y = ~1`, `- ~y` and
    would run them."""
    i = 0
    while i < len(tokens):
        j = i
        if _is_operator_token(raw_sql, tokens[i]):
            while (
                j + 1 < len(tokens)
                and _is_operator_token(raw_sql, tokens[j + 1])
                and tokens[j + 1].start == tokens[j].end + 1
            ):
                j += 1
        if j > i:
            _check_operator_run(raw_sql, tokens[i : j + 1])
        i = j + 1


def _check_operator_run(raw_sql: str, run: list[Token]) -> None:
    text = raw_sql[run[0].start : run[-1].end + 1]
    pieces = [raw_sql[token.start : token.end + 1] for token in run]
    position = 0
    while pieces:
        operator = _postgres_operator(text[position:])
        taken = ""
        count = 0
        while pieces and len(taken) < len(operator):
            taken += pieces.pop(0)
            count += 1
        if taken != operator or (count > 1 and operator not in _REASSEMBLED_OPERATORS):
            msg = (
                f"{text!r} reads as the operator {operator!r} to Postgres, not "
                "as sqlglot reads it; put spaces between the operators"
            )
            raise QueryRejectedError(OutcomeReason.UNSAFE_LITERAL, msg)
        position += len(operator)


def _postgres_operator(text: str) -> str:
    """The operator Postgres's lexer takes from the start of `text` (a run
    of operator characters): up to a comment start, then without trailing
    `+` / `-` unless it contains a character that keeps them."""
    for comment in ("--", "/*"):
        cut = text.find(comment, 1)
        if cut != -1:
            text = text[:cut]
    if len(text) > 1 and not _OPERATOR_KEEPS_SIGN & set(text):
        while len(text) > 1 and text[-1] in "+-":
            text = text[:-1]
    return text


def _is_operator_token(raw_sql: str, token: Token) -> bool:
    text = raw_sql[token.start : token.end + 1]
    return bool(text) and all(char in _OPERATOR_CHARS for char in text)


def _denial(name: str) -> tuple[OutcomeReason, str] | None:
    """The rejection for calling the function `name` (lowercase), if it is
    denied: a set-returning one (`DISALLOWED_CONSTRUCT`) or one on the deny
    list (`DISALLOWED_FUNCTION`)."""
    if name in DENIED_SRF_FUNCTIONS:
        msg = (
            f"Set-returning function '{name}' is not supported on the MCP "
            "surface; query a whitelisted table instead."
        )
        return OutcomeReason.DISALLOWED_CONSTRUCT, msg
    if name in DENIED_FUNCTIONS_EXACT:
        return (
            OutcomeReason.DISALLOWED_FUNCTION,
            f"Function '{name}' is on the deny list",
        )
    for prefix in DENIED_FUNCTIONS_PREFIX:
        if name.startswith(prefix):
            msg = f"Function '{name}' (prefix '{prefix}*') is on the deny list"
            return OutcomeReason.DISALLOWED_FUNCTION, msg
    return None


def _check_no_denied_calls(tokens: list[Token], ast: exp.Query) -> None:
    """Refuse a denied function name written as a call (`name (`) wherever
    the parsed tree does not show it as one. sqlglot reads some such calls
    as something else — `copy(x)` in a subquery as a column `copy` with an
    alias list `AS (x)` — which the tree walk in `_check_no_denied_functions`
    never sees (review round 5). A name before `(` that the tree keeps as an
    alias's or CTE's column list (`FROM t AS copy(a)`) is not a call."""
    aliases = {
        ident.meta.get("start")
        for ident in ast.find_all(exp.Identifier)
        if isinstance(ident.parent, exp.TableAlias)
    }
    for token, nxt in itertools.pairwise(tokens):
        if (
            nxt.token_type != TokenType.L_PAREN
            or token.token_type in {TokenType.IDENTIFIER, *_STRING_TOKENS}
            or token.start in aliases
        ):
            continue
        denial = _denial(token.text.lower())
        if denial is not None:
            raise QueryRejectedError(*denial)


def _token_problem(
    raw_sql: str, tokens: list[Token], i: int, kept_names: set[int | None]
) -> str | None:
    """Why `tokens[i]` (with its neighbours) is a source form sqlglot and
    Postgres read differently, or `None`. `kept_names`: the source offsets
    of the quoted names the parsed tree keeps as written. See
    `_check_lexical_fidelity`."""

    def source(token: Token) -> str:
        return raw_sql[token.start : token.end + 1]

    token = tokens[i]
    text = source(token)
    nxt = tokens[i + 1 : i + 3]
    if token.token_type == TokenType.BYTE_STRING and "\\" in text:
        return (
            "Escape-string literals containing a backslash (E'...\\...') "
            "are not supported; use a standard string literal (use chr(10) "
            "for a newline, chr(9) for a tab, '' for a quote)"
        )
    if (
        text[:2].lower() == "u&"
        or (
            text.lower() == "u"
            and len(nxt) == 2  # noqa: PLR2004 — `&` and the quoted token
            and source(nxt[0]) == "&"
            and nxt[0].start == token.end + 1
            and nxt[1].start == nxt[0].end + 1
            and source(nxt[1])[:1] in {"'", '"'}
        )
    ):
        return (
            "Unicode-escape literals and identifiers (U&'...', U&\"...\") "
            "are not supported; write the characters directly"
        )
    if (
        text.startswith('"')
        and nxt
        and nxt[0].token_type == TokenType.L_PAREN
        and token.start not in kept_names
    ):
        return (
            f"{text}(...) reads as a quoted call of a built-in that would run "
            "unquoted; write the function name unquoted"
        )
    if token.token_type == TokenType.HEREDOC_STRING and not _DOLLAR_TAG_RE.match(text):
        return (
            f"Dollar-quote tag in {text[:20]!r} is not a valid Postgres tag "
            "(letters, digits, underscores; not starting with a digit)"
        )
    if (
        token.token_type in _STRING_TOKENS
        and nxt
        and nxt[0].token_type in _STRING_TOKENS
    ):
        return (
            "Adjacent string constants are not supported (Postgres joins them "
            "only across a newline, sqlglot always); concatenate with ||"
        )
    return None


def inject_limit(ast: exp.Query, n: int) -> exp.Query:
    """`ast` with `LIMIT n` on its root. Returns a modified copy.

    A plain integer LIMIT the agent wrote is replaced (the executor has
    already folded it into `n`: see `extract_limit`). Any other LIMIT
    expression (`LIMIT 3.5`, `LIMIT 2 + 3`, `LIMIT (SELECT ...)`,
    `LIMIT -1`) is kept and capped: `LIMIT LEAST(<as written>, n)`, so
    Postgres evaluates it as it would have (rounding `3.5` to 4, rejecting
    a negative or a `text` value) and the cap still holds. A value that is
    numeric as written (number literals, arithmetic on them, a cast to a
    numeric type) is first cast to bigint — for those, an explicit cast is
    exactly Postgres's own LIMIT coercion, and `LEAST` over a float would
    turn `'NaN'` / `'Infinity'` (an error in a LIMIT) into n. Anything else
    is left to Postgres's type resolution (an explicit cast would widen it:
    `'3'::text::bigint` runs where `LIMIT '3'::text` is an error). `LIMIT NULL` / `LIMIT
    ALL` mean no limit, so they become `LIMIT n`. A query wrapped in
    parentheses as a whole (`(SELECT ... LIMIT 5)`) is unwrapped first:
    Postgres refuses a second LIMIT after the parenthesis.
    """
    root = _limit_root(ast)
    written = _written_limit(root)
    if (
        written is None
        or extract_limit(root) is not None
        or isinstance(written, exp.Null)
        or (isinstance(written, exp.Column) and written.sql().upper() == "ALL")
    ):
        return root.limit(n)
    value = written.copy()
    if _numeric_as_written(written):
        value = exp.Cast(this=value, to=exp.DataType.build("BIGINT"))
    capped = exp.Anonymous(this="LEAST", expressions=[value, exp.Literal.number(n)])
    return root.limit(capped)


# The numeric types an explicit cast to bigint treats exactly like Postgres's
# assignment coercion of a LIMIT (not `bit` / `money` / text types).
_NUMERIC_LIMIT_TYPES = frozenset(
    {
        exp.DType.SMALLINT,
        exp.DType.INT,
        exp.DType.BIGINT,
        exp.DType.DECIMAL,
        exp.DType.DOUBLE,
        exp.DType.FLOAT,
    }
)


def _numeric_as_written(node: exp.Expression) -> bool:
    """True if `node` is numeric by how it is written: number literals,
    arithmetic on them, a cast to a numeric type."""
    if isinstance(node, exp.Literal):
        return not node.is_string
    if isinstance(node, (exp.Paren, exp.Neg)):
        return _numeric_as_written(node.this)
    if isinstance(node, (exp.Add, exp.Sub, exp.Mul, exp.Div, exp.Mod)):
        return _numeric_as_written(node.this) and _numeric_as_written(node.expression)
    if isinstance(node, exp.Cast):
        return isinstance(node.to, exp.DataType) and node.to.this in (
            _NUMERIC_LIMIT_TYPES
        )
    return False


def _limit_root(ast: exp.Query) -> exp.Query:
    """`ast` without the parentheses around a whole query (`(SELECT ...)`)."""
    while (
        isinstance(ast, exp.Subquery)
        and isinstance(ast.this, exp.Query)
        and not any(value for key, value in ast.args.items() if key != "this")
    ):
        ast = ast.this
    return ast


def _written_limit(ast: exp.Query) -> exp.Expression | None:
    """The expression of the root's LIMIT, or `None`."""
    body = ast.this if isinstance(ast, exp.With) else ast
    limit_node = body.args.get("limit") if hasattr(body, "args") else None
    return getattr(limit_node, "expression", None)


def _injected_limit(ast: exp.Query) -> int | None:
    """The cap `inject_limit` put on the root (`LIMIT n` or
    `LIMIT LEAST(..., n)`), or `None`."""
    written = _written_limit(ast)
    if (
        isinstance(written, exp.Anonymous)
        and written.name.upper() == "LEAST"
        and written.expressions
    ):
        written = written.expressions[-1]
    if isinstance(written, exp.Literal) and _PLAIN_INTEGER_RE.fullmatch(written.name):
        return int(written.name)
    return None


def render_for_execution(
    ast: exp.Query,
    limit: int,
    *,
    allowed_tables: set[str],
    ban_select_star: bool = True,
    table_columns: Mapping[str, frozenset[str]] | None = None,
) -> str:
    """The SQL to send to Postgres: `ast` with `LIMIT limit`, rendered once
    and validated AS RENDERED.

    The executor never sends the agent's text; it sends sqlglot's rendering
    of the validated tree, and that rendering is not always faithful (ledger
    F32 and its variants). So the rendered text is what gets checked:

    1. Render the LIMIT-wrapped tree as written (`normalize_functions=False`
       keeps function-name case) and WITHOUT comments (sqlglot rewrites `--`
       comments as `/* */`; their text is not part of the tree, so it can
       never be checked).
    2. Run the full `parse_and_validate` on that text, with the same
       whitelist — every check the agent's text passed, now on the text
       that will run. A rendering that smuggles in a statement, a table off
       the whitelist or a denied function fails here (a harmless extra
       projection would pass every check and run as rendered — what runs is
       always what was checked).
    3. Render the re-parsed tree again and require the identical string
       (and that it still ends in exactly `LIMIT limit`):
       sqlglot reads its own output back as exactly what it wrote (a
       fixpoint), so the text that ran the checks is the text executed.
       A rendering from the agent's tree can still differ in spelling from
       one of its own output (`y > SOME(...)` renders `ANY(...)`, then
       `ANY (...)`), so if the first re-render differs, that text becomes
       the candidate and is validated and re-rendered in turn — up to
       `_MAX_RENDER_ROUNDS` times; the text executed is always one that
       passed every check and re-renders to itself.

    Any failure is `QueryRejectedError(ROUNDTRIP_MISMATCH)` naming the
    step; nothing runs. That includes a construct sqlglot cannot express in
    Postgres (it would otherwise drop it — `IGNORE NULLS` — see `_render`).
    Respellings that keep the meaning — an expanded window frame, `SOME` →
    `ANY`, `x::int` → `CAST(x AS INT)` — validate and run; everything else
    is rendered as written by `FaithfulPostgres`.
    `tests/test_sql_functional_corpus.py` pins that ordinary analytics
    return what Postgres returns for the original text.

    The residual: the checks prove what sqlglot reads in the executed text,
    not what Postgres's lexer reads, and the result values are only as
    faithful as sqlglot's generator. Where the two lexers disagree on a
    source form, the parser refuses that form up front
    (`_check_lexical_fidelity`); a disagreement nobody has found yet would
    not be caught here.

    `RecursionError` (a pathologically deep tree) propagates; the caller
    audits it.
    """
    sql = _render(inject_limit(ast, limit))
    for _ in range(_MAX_RENDER_ROUNDS):
        try:
            rendered = _checked(
                sql,
                allowed_tables=allowed_tables,
                ban_select_star=ban_select_star,
                normalize=False,
                table_columns=table_columns or {},
            )
        except QueryRejectedError as exc:
            msg = (
                f"The rendered SQL does not pass validation ({exc.reason}: "
                f"{exc.detail}): {sql}"
            )
            raise QueryRejectedError(OutcomeReason.ROUNDTRIP_MISMATCH, msg) from exc
        again = _render(rendered.ast)
        if again == sql:
            if _injected_limit(rendered.ast) != limit:
                # The cap must apply to the whole query (sqlglot once moved
                # it into a subquery for `QUALIFY`, now refused up front).
                msg = f"The rendered SQL does not end in LIMIT {limit}: {sql}"
                raise QueryRejectedError(OutcomeReason.ROUNDTRIP_MISMATCH, msg)
            return sql
        sql = again
    msg = f"The rendered SQL is not stable: it keeps changing, last as {sql!r}"
    raise QueryRejectedError(OutcomeReason.ROUNDTRIP_MISMATCH, msg)


# Rendering normally reaches its fixpoint on the first or second round.
_MAX_RENDER_ROUNDS = 3


def _render(tree: exp.Query) -> str:
    """The tree as Postgres SQL. `unsupported_level=RAISE`: where sqlglot
    knows it cannot express something in Postgres it would otherwise drop it
    with a warning (`IGNORE NULLS` / `RESPECT NULLS`) and run something
    else; that is a `ROUNDTRIP_MISMATCH` instead. Any other generator failure
    is one too; only `RecursionError` propagates (the caller audits it)."""
    try:
        return tree.sql(
            dialect=FaithfulPostgres,
            comments=False,
            normalize_functions=False,
            unsupported_level=ErrorLevel.RAISE,
        )
    except RecursionError:
        raise
    except Exception as exc:
        msg = (
            "The query cannot be rendered as Postgres SQL "
            f"({type(exc).__name__}): {exc}"
        )
        raise QueryRejectedError(OutcomeReason.ROUNDTRIP_MISMATCH, msg) from exc


_PLAIN_INTEGER_RE = re.compile(r"[0-9]+")
_BIGINT_MAX = 2**63 - 1


def extract_limit(ast: exp.Query) -> int | None:
    """Return the root's LIMIT when the agent wrote a plain integer
    (`LIMIT 5`), else `None`.

    Used by the executor to honor a user-supplied `LIMIT N` smaller than
    the server's `DEFAULT_LIMIT` / `HARD_LIMIT`. Without this, the
    executor would clobber the user's `LIMIT 3` with `LIMIT 11` and the
    user gets 10 rows + `truncated=True` instead of 3 rows. The
    most-restrictive-wins resolution lives in `executor.run_query`; this
    function just reads what the user wrote.

    A `WITH ... SELECT ... LIMIT N` construct stores the LIMIT on the
    body `Select`, not on the wrapping `With`, and `(SELECT ... LIMIT N)`
    on the query inside the parentheses; both are unwrapped. Any other
    LIMIT (`3.5`, `2 + 3`, a subquery, `-1`, `0x10`) returns `None`:
    `inject_limit` keeps it for Postgres to evaluate, capped.
    """
    written = _written_limit(_limit_root(ast))
    if (
        isinstance(written, exp.Literal)
        and not written.is_string
        and _PLAIN_INTEGER_RE.fullmatch(written.name)
        and int(written.name) <= _BIGINT_MAX  # beyond: Postgres errors
    ):
        return int(written.name)
    return None


def _check_no_select_into(ast: exp.Query) -> None:
    for sel in ast.find_all(exp.Select):
        if sel.args.get("into") is not None:
            msg = "SELECT INTO writes a new table and is not allowed"
            raise QueryRejectedError(OutcomeReason.SELECT_INTO, msg)


def _check_no_offset(ast: exp.Query) -> None:
    """Reject OFFSET — there is no server-side pagination tool surface.

    The truncation `hint` already steers the agent toward keyset pagination
    (`WHERE id > <last_seen_id> ORDER BY id LIMIT N`); OFFSET would push
    them toward unstable, slow OFFSET pagination. Caught at parser layer so
    the audit row carries the right reason.
    """
    if ast.find(exp.Offset) is not None:
        msg = (
            "OFFSET is not supported. Use keyset pagination "
            "(WHERE id > <last_seen_id> ORDER BY id LIMIT N) instead."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_no_fetch(ast: exp.Query) -> None:
    """Reject `FETCH FIRST/NEXT N ROWS ONLY` — SQL-standard pagination.

    Cousin of OFFSET: same agent-friendly-but-server-hostile pattern. Use
    LIMIT N (which `inject_limit` clamps server-side anyway). Caught at
    parser layer so the closed "no pagination" promise in the truncation
    hint doesn't lie to the agent.
    """
    if ast.find(exp.Fetch) is not None:
        msg = (
            "FETCH FIRST/NEXT ROWS is not supported. Use LIMIT N instead; "
            "the server clamps it to the configured cap."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_no_locking_reads(ast: exp.Query) -> None:
    """Reject `FOR UPDATE` / `FOR SHARE` / `FOR NO KEY UPDATE` / `FOR KEY SHARE`.

    The `mcp_readonly_role` has no UPDATE / DELETE grants, so PG would
    reject these at execution. Catching at parser layer is defense in depth
    and yields a clearer audit reason than `EXECUTION_ERROR` would.
    """
    if ast.find(exp.Lock) is not None:
        msg = (
            "Locking reads (FOR UPDATE / FOR SHARE) are not supported on the "
            "read-only MCP surface."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_ctes_read_only(ast: exp.Query) -> None:
    for cte in ast.find_all(exp.CTE):
        body = cte.this
        if not isinstance(body, exp.Query):
            alias = cte.alias or "<unnamed>"
            msg = (
                f"CTE '{alias}' body is {type(body).__name__}; "
                "INSERT/UPDATE/DELETE inside WITH is not allowed"
            )
            raise QueryRejectedError(OutcomeReason.WRITEABLE_CTE, msg)


def _check_no_select_star(ast: exp.Query) -> None:
    """Reject every `Star` that reaches a `Select` projection.

    Looking at `Star.parent` alone is not enough — three real bypass
    shapes nest the `Star` deeper than the direct parent:

    - `SELECT (t.*) FROM ... t`            — `Star → Column → Paren → Select`
    - `SELECT to_jsonb(t.*) FROM ... t`    — `Star → Column → Anonymous → Select`
    - `SELECT json_agg(t.*) FROM ... t`    — `Star → Column → Anonymous → Select`

    All three land every column of the referenced row in one scalar and
    would render the "agents must enumerate columns explicitly" defense
    cosmetic. The companion `_check_no_whole_row_refs` catches the
    no-Star variants (`row_to_json(t)`, `SELECT t`, `CAST(t AS TEXT)`,
    `json_agg(t)`).

    Walk the ancestor chain of every `Star`. If we hit `exp.Count` first,
    accept (the only PG aggregate that legitimately takes `*`). If we hit
    a `Select` first, reject — the Star is in a projection. Walking the
    chain (rather than picking specific node classes) is intentionally
    structural: any wrapper sqlglot introduces between projection and
    Star (Paren, Anonymous, Cast, …) is treated the same way.
    """
    for star in ast.find_all(exp.Star):
        cur = star.parent
        while cur is not None:
            if isinstance(cur, exp.Count) or (
                # `pg_catalog.count(*)`: kept as written (`exp.Anonymous`).
                isinstance(cur, exp.Anonymous) and cur.name.lower() == "count"
            ):
                # COUNT(*) (and COUNT(DISTINCT *)) are the only typed
                # aggregate where `*` is the canonical argument. Every
                # other aggregate (SUM/AVG/MIN/MAX/...) takes a column
                # expression — `*` is either a parser-ambiguous shape
                # or a wrapped-row attempt. Restricting the carve-out
                # to Count keeps the rule narrow.
                break
            if isinstance(cur, exp.Select):
                qualifier = star.parent
                if isinstance(qualifier, exp.Column):
                    name = (
                        qualifier.args.get("table") and qualifier.args["table"].name
                    ) or "?"
                    msg = (
                        f"Qualified '{name}.*' is rejected; enumerate "
                        "columns explicitly"
                    )
                else:
                    msg = "Bare SELECT * is rejected; enumerate columns explicitly"
                raise QueryRejectedError(OutcomeReason.SELECT_STAR, msg)
            cur = cur.parent


def _check_no_whole_row_fields(
    ast: exp.Query, table_columns: Mapping[str, frozenset[str]]
) -> None:
    """`t.to_jsonb` is `to_jsonb(t)` to Postgres (attribute notation): the
    whole row, refused like the call (review round 5) — unless `t` has a
    column of that name (`_attribute_calls`)."""
    for name in _attribute_calls(ast, table_columns):
        if name in _WHOLE_ROW_FIELD_FUNCTIONS:
            msg = (
                f"`x.{name}` is {name}(x) to Postgres and returns the whole "
                "row; enumerate columns explicitly"
            )
            raise QueryRejectedError(OutcomeReason.SELECT_STAR, msg)


def _check_no_whole_row_refs(
    ast: exp.Query, table_columns: Mapping[str, frozenset[str]]
) -> None:
    """Reject bare-table-alias columns in any Select's projection list.

    The Star check above catches every shape with an `exp.Star` node, but
    several PG expressions return whole-row tuples without using `*`:

    - `SELECT t FROM ... t`              — bare row alias as a Column
    - `SELECT row_to_json(t) FROM ... t` — alias inside an Anonymous func
    - `SELECT to_jsonb(t) FROM ... t`
    - `SELECT json_agg(t) FROM ... t`
    - `SELECT array_agg(t) FROM ... t`
    - `SELECT CAST(t AS TEXT) FROM ... t` — PG renders the row as text

    All five land every column of the row in a single value. Same
    defense intent as the SELECT * ban; same audit reason
    (`SELECT_STAR`) so the agent's hint is consistent.

    Approach: build the set of every `Table.alias_or_name` anywhere in
    the AST (covers FROM and JOIN aliases plus CTE references), then for
    each `Select`'s projection list, recursively find every `exp.Column`
    that has no `table` qualifier and whose name matches a known alias.
    The match is conservative — a real column whose name collides with a
    FROM alias would be a false positive, but in practice curated-view
    columns do not collide with their own FROM aliases.
    """
    table_aliases: set[str] = set()
    for table in ast.find_all(exp.Table):
        alias_or_name = (table.alias_or_name or "").lower()
        if alias_or_name:
            table_aliases.add(alias_or_name)

    _check_no_whole_row_fields(ast, table_columns)
    if not table_aliases:
        return

    for sel in ast.find_all(exp.Select):
        for projection in sel.expressions:
            for col in projection.find_all(exp.Column):
                if col.args.get("table") is not None:
                    # Qualified column (`t.id`, `auth_permission.codename`).
                    # The qualifier is the table alias; the column itself
                    # is not a whole-row reference.
                    continue
                col_name = (col.name or "").lower()
                if col_name in table_aliases:
                    msg = (
                        f"Bare reference to row alias '{col_name}' returns "
                        "the whole row; enumerate columns explicitly"
                    )
                    raise QueryRejectedError(OutcomeReason.SELECT_STAR, msg)


def _check_no_denied_functions(
    ast: exp.Query, table_columns: Mapping[str, frozenset[str]]
) -> None:
    """Walk every function-call node and reject anything on the deny list.

    `exp.Func` is sqlglot's base class for both typed function nodes
    (`Count`, `Sum`, `CurrentUser`, `Version`, …) and `exp.Anonymous`
    (functions sqlglot has no canonical class for). The previous walk
    over `Anonymous` only missed typed nodes — `SELECT version()`,
    `SELECT current_user`, `SELECT inet_server_addr()` all parse as
    typed Func subclasses and bypassed the Anonymous-only check entirely.
    Walking `Func` covers both.

    Match on `.sql_name()` lowercased: sqlglot renders the canonical PG
    identifier regardless of how the user wrote it (camelCase, mixed
    case, dialect-quirky variants). For Anonymous nodes `.sql_name()`
    falls back to the `name` attribute.
    """
    for func in ast.find_all(exp.Func):
        # Set-returning / table functions used in the PROJECTION (not FROM)
        # escape the empty-name `exp.Table` guard in `_check_tables` (which
        # only sees them in a FROM clause). `generate_series` / `unnest` map to
        # TYPED sqlglot nodes whose `sql_name()` is an internal token, not the
        # user-facing name, so the name deny-list below cannot catch them —
        # match them on the public base classes instead (robust across sqlglot
        # versions). The remaining PG SRFs (json/regexp expanders) parse as
        # `exp.Anonymous` and fall through to `DENIED_SRF_FUNCTIONS` in the
        # name check below. `SELECT generate_series(1, 1e9)` is the documented
        # DoS-amplifier shape; the LIMIT-injection + 5s `statement_timeout`
        # already bound it, but rejecting it here yields a clean
        # `DISALLOWED_CONSTRUCT` audit reason instead of a wasted backend slot.
        if isinstance(func, (exp.GenerateSeries, exp.UDTF)):
            msg = (
                "Set-returning / table functions (e.g. generate_series, "
                "unnest) are not supported on the MCP surface; query a "
                "whitelisted table instead."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)
        # `exp.Anonymous` keeps the actual function name in `.name` (the
        # `this` arg); its `sql_name()` returns the useless "ANONYMOUS"
        # default. Typed Func subclasses (Count, CurrentUser, Version,
        # InetServerAddr, ...) put the canonical SQL identifier in
        # `sql_name()`; their `.name` is often the FIRST ARGUMENT (e.g.
        # `Count.name == '*'` for `COUNT(*)`), not the function name.
        # Pick the right attribute per node kind.
        name = (
            (func.name if isinstance(func, exp.Anonymous) else func.sql_name()) or ""
        ).lower()
        if not name:
            continue
        # Anonymous-mapped set-returning functions (json/regexp expanders, a
        # schema-qualified `generate_series`) get the same closed-construct
        # reason as the typed ones above.
        denial = _denial(name)
        if denial is not None:
            raise QueryRejectedError(*denial)
    for name in _attribute_calls(ast, table_columns):
        if name in _NOT_CALLABLE_AS_FIELD or name.startswith("has_"):
            continue
        denial = _denial(name)
        if denial is not None:
            reason, msg = denial
            msg = f"{msg} (written as a field, `x.{name}`, Postgres calls {name}(x))"
            raise QueryRejectedError(reason, msg)


def _attribute_calls(
    ast: exp.Query, table_columns: Mapping[str, frozenset[str]]
) -> list[str]:
    """The lowercase names Postgres reads as attribute-notation CALLS:
    `x.f` / `(expr).f` is `f(x)` unless `x` is a FROM item with a column
    `f`. A qualified name that resolves to a column of its FROM item (a
    derived table's or CTE's output column, an alias column list, a
    whitelisted table's column per `table_columns`) is a column and not
    listed; a name inside a type (`pg_catalog.pg_lsn`) is not a call."""
    names = []
    for col in ast.find_all(exp.Column):
        qualifier = col.args.get("table")
        if qualifier is None or isinstance(col.this, exp.Star):
            continue
        name = col.name.lower()
        if not _is_column_of(col, qualifier.name.lower(), name, table_columns):
            names.append(name)
    for dot in ast.find_all(exp.Dot):
        if not isinstance(dot.expression, exp.Identifier):
            continue
        if dot.find_ancestor(exp.DataType) is not None:
            continue
        name = dot.expression.name.lower()
        row = _row_reference(dot.this)
        if row is None or not _is_column_of(dot, row, name, table_columns):
            names.append(name)
    return names


def _row_reference(node: exp.Expression) -> str | None:
    """The FROM-item name `node` denotes as a whole row (`(t)`, `(t.*)`),
    or None."""
    while isinstance(node, exp.Paren):
        node = node.this
    if not isinstance(node, exp.Column):
        return None
    if isinstance(node.this, exp.Star):
        table = node.args.get("table")
        return table.name.lower() if table is not None else None
    if node.args.get("table") is None:
        return node.name.lower()
    return None


def _is_column_of(
    node: exp.Expression,
    item: str,
    name: str,
    table_columns: Mapping[str, frozenset[str]],
) -> bool:
    """True if the FROM item `item`, in scope at `node`, has a column
    `name`."""
    scope = node.parent
    while scope is not None:
        if isinstance(scope, exp.Select):
            source = _from_item(scope, item)
            if source is not None:
                return name in _item_columns(source, table_columns)
        scope = scope.parent
    return False


def _from_item(select: exp.Select, item: str) -> exp.Expression | None:
    from_ = select.args.get("from_") or select.args.get("from")
    sources = [from_.this] if from_ is not None else []
    sources += [join.this for join in select.args.get("joins") or []]
    for source in sources:
        if (source.alias_or_name or "").lower() == item:
            found: exp.Expression = source
            return found
    return None


def _item_columns(
    source: exp.Expression, table_columns: Mapping[str, frozenset[str]]
) -> frozenset[str]:
    alias = source.args.get("alias")
    if isinstance(alias, exp.TableAlias) and alias.columns:
        return frozenset(column.name.lower() for column in alias.columns)
    if isinstance(source, exp.Subquery):
        return _output_names(source.this)
    if isinstance(source, exp.Table):
        cte = _cte_named(source, source.name.lower())
        if cte is not None:
            cte_alias = cte.args.get("alias")
            if isinstance(cte_alias, exp.TableAlias) and cte_alias.columns:
                return frozenset(c.name.lower() for c in cte_alias.columns)
            return _output_names(cte.this)
        return table_columns.get(source.name.lower(), frozenset())
    return frozenset()


def _cte_named(table: exp.Expression, name: str) -> exp.CTE | None:
    """The CTE `name` in scope for `table` (see `_resolves_to_cte`)."""
    node = table.parent
    while node is not None:
        for cte in getattr(node, "ctes", ()):
            if cte.alias and cte.alias.lower() == name:
                found: exp.CTE = cte
                return found
        node = node.parent
    return None


def _output_names(query: exp.Expression) -> frozenset[str]:
    """The column names a query produces, as Postgres names them (an alias,
    a column's name, a function call's name)."""
    while isinstance(query, exp.SetOperation):
        query = query.this
    if not isinstance(query, exp.Select):
        return frozenset()
    names = set()
    for projection in query.expressions:
        name = _output_name(projection)
        if name:
            names.add(name)
    return frozenset(names)


def _output_name(node: exp.Expression) -> str | None:
    if isinstance(node, exp.Alias):
        return str(node.alias).lower()
    while isinstance(
        node, (exp.Paren, exp.Cast, exp.Window, exp.WithinGroup, exp.Filter)
    ):
        node = node.this
    name = None
    if (
        isinstance(node, exp.Column) and not isinstance(node.this, exp.Star)
    ) or isinstance(node, exp.Anonymous):
        name = node.name
    elif isinstance(node, exp.Func):
        name = node.sql_name()
    return name.lower() if name else None


def _check_no_bare_keyword_columns(ast: exp.Query) -> None:
    """Reject parenthesis-less PG built-ins (`SELECT current_user FROM ...`).

    PG accepts several built-ins as bare identifiers — no parentheses.
    sqlglot parses these as `exp.Column(name='current_user', table=None)`,
    which the function-deny-list walk above cannot see (it only walks
    `exp.Func` nodes). The companion check here closes that gap by
    looking at unqualified Column nodes whose name matches a known
    server-identity keyword.

    Qualified Columns (`t.current_user` — i.e. an actual column happening
    to share a name with a PG keyword) are ignored: the qualifier proves
    the reference is to a table column, not the bare keyword form.
    """
    for col in ast.find_all(exp.Column):
        if col.args.get("table") is not None:
            continue
        name = (col.name or "").lower()
        if name in DENIED_BARE_KEYWORDS:
            msg = (
                f"Built-in '{name}' leaks server identity; the "
                "function-deny-list rejects both bare and parenthesised forms."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_FUNCTION, msg)


def _check_no_recursive_cte(ast: exp.Query) -> None:
    """Reject `WITH RECURSIVE ...` queries.

    Recursive CTEs are a power-user feature unnecessary for the LLM-driven
    read-only use case. They also enable a parameterless DoS shape — the
    minimal `WITH RECURSIVE t(n,s) AS (VALUES (1, repeat('a', 4000))
    UNION ALL SELECT n+1, s||s FROM t WHERE n<30) SELECT n, s FROM t`
    burns memory exponentially up to `work_mem` x the statement_timeout
    window without ever referencing a whitelisted table (the only `Table`
    in the AST is the CTE alias `t`, which the table-whitelist check
    correctly skips). The recursive-CTE-no-table bypass cannot be closed
    by tightening the table check alone — it needs a structural reject
    here. Agents that need recursive aggregation should be rewritten as
    iterative GROUP BY / window functions.
    """
    for with_node in ast.find_all(exp.With):
        if with_node.args.get("recursive"):
            msg = (
                "WITH RECURSIVE is not supported on the MCP surface. "
                "Use iterative aggregation (GROUP BY, window functions) "
                "or escalate to operators."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _resolves_to_cte(table: exp.Expression, name: str) -> bool:
    """True if `table`'s name resolves to a CTE that is IN SCOPE for it.

    CTE names are lexically scoped, so a flat "is this name a CTE anywhere
    in the statement" test is unsound: an inner-scoped CTE that happens to
    share a real table's name would mask an OUTER-scope reference to that
    real table, letting a non-whitelisted table slip past the whitelist
    check (the role grants still reject it, but the parser layer must not
    blindly defer). Confirmed bypass shape:

        SELECT s.x FROM secret_table s
        JOIN (WITH secret_table AS (SELECT 1 AS x) SELECT x FROM secret_table) q
        ON TRUE

    The outer `FROM secret_table` is a real table; the inner CTE only
    shadows the name *inside the subquery*. So resolve scope explicitly:
    walk the node's ancestors and treat `name` as a CTE reference only when
    an enclosing query defines a CTE of that name. sqlglot attaches a `WITH`
    to the query it decorates (a sibling of that query's `FROM`, not an
    ancestor of the table), so we read each ancestor query's `.ctes` — the
    public accessor that stays correct across sqlglot versions (the internal
    arg key for the `WITH` has changed between releases). Walking to the root
    query also covers a table inside a later CTE body referencing an earlier
    sibling CTE, since the owning query's `.ctes` lists both.
    """
    node = table.parent
    while node is not None:
        for cte in getattr(node, "ctes", ()):
            if cte.alias and cte.alias.lower() == name:
                return True
        node = node.parent
    return False


def _check_tables(
    ast: exp.Query,
    *,
    allowed_tables: set[str],
) -> set[str]:
    """Validate every table reference and return the set of touched tables.

    References that resolve to an IN-SCOPE CTE are skipped (they look like
    `exp.Table(name='q')` but resolve to the CTE body, which has already
    been walked) — see `_resolves_to_cte` for why scope matters. System
    catalogs (`pg_catalog`, `information_schema`, anything in the `pg_*`
    namespace) are rejected even when nominally on the whitelist.
    """
    allowed_lower = {t.lower() for t in allowed_tables}
    referenced: set[str] = set()

    for table in ast.find_all(exp.Table):
        schema = (table.db or "").lower()
        name = (table.name or "").lower()
        if not name:
            # sqlglot represents table-valued constructs in FROM clauses
            # as `exp.Table(name="")` — `FROM generate_series(1, N)`,
            # `FROM unnest(...)`, `FROM json_to_recordset(...)`, and the
            # bare `FROM dblink(text, text)`. An empty-name Table would
            # satisfy the whitelist check trivially (no name to compare),
            # and the function deny-list only walks `exp.Anonymous` so
            # functions used as table-valued constructs in FROM never reach
            # it. Without this guard, `generate_series(1, 10_000_000)` is a
            # DoS amplifier and `dblink` is an egress channel. Reject as a
            # closed construct so the audit row carries `DISALLOWED_CONSTRUCT`
            # rather than a "table not on whitelist" misattribution.
            msg = (
                "Table-valued functions in FROM (e.g. generate_series, "
                "unnest, dblink, json_to_recordset) are not supported on "
                "the MCP surface; query a whitelisted table instead."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)
        if schema in SYSTEM_SCHEMAS or schema.startswith("pg_"):
            msg = f"Schema '{schema}' is off limits"
            raise QueryRejectedError(OutcomeReason.SYSTEM_SCHEMA, msg)
        if not schema and name.startswith("pg_"):
            msg = f"Table '{name}' is in the pg_* namespace"
            raise QueryRejectedError(OutcomeReason.SYSTEM_SCHEMA, msg)
        if _resolves_to_cte(table, name):
            continue
        if name not in allowed_lower:
            msg = f"Table '{name}' is not on the MCP whitelist"
            raise QueryRejectedError(OutcomeReason.DISALLOWED_TABLE, msg)
        referenced.add(name)
    return referenced
