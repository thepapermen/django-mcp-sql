"""`SET LOCAL ROLE` + per-transaction GUC literals for the readonly read
path. Single source of truth — executor + smoke command both call
`enter_readonly_session`. See `docs/architecture.md` for the
"role-level GUCs are inert under SET ROLE" + "SET LOCAL never bare SET"
invariants."""

import re
from collections.abc import Mapping
from collections.abc import Sequence
from typing import Protocol


class SQLCursor(Protocol):
    """The cursor surface this module needs: any DB-API cursor satisfies it
    structurally — Django's `CursorWrapper` (every in-tree caller), a raw
    psycopg cursor, or a test double. Narrower than the full DB-API so the
    contract a consumer must meet to call `enter_readonly_session` directly
    is explicit rather than `Any`.

    `execute`'s `params` is `Sequence[str]` — the only shape this module ever
    binds — rather than the DB-API's wide scalar union, so a real
    `CursorWrapper` (whose `execute` accepts that union) is a structural
    subtype. `fetchone`/`fetchall` are satisfied by `CursorWrapper.__getattr__`.
    """

    def execute(self, sql: str, params: Sequence[str] | None = ...) -> object: ...
    def fetchone(self) -> tuple[object, ...] | None: ...
    def fetchall(self) -> Sequence[tuple[object, ...]]: ...


EXPECTED_SESSION_GUCS: dict[str, str] = {
    "statement_timeout": "5s",
    "lock_timeout": "1s",
    "idle_in_transaction_session_timeout": "10s",
    "default_transaction_read_only": "on",
    # The parser (sqlglot) reads `'a\b'` as a backslash and a `b`, which is
    # what Postgres reads only with `standard_conforming_strings` on. A
    # database- or login-role-level `off` would make Postgres treat
    # backslashes in standard strings as escapes, so the executed SQL would
    # no longer mean what was checked (`'a\' AS x, '...'` shifts quotes).
    # Pinned per transaction, like every guard.
    "standard_conforming_strings": "on",
    # Where an unqualified relation name resolves. The parser matches `FROM t`
    # against the whitelisted relation in `public` (`parser.DEFAULT_SCHEMA`);
    # the login's own `search_path` (a `"$user"` schema — under `SET ROLE`,
    # one named after the profile role — a database- or role-level setting,
    # a connection option) could otherwise resolve it to a same-named
    # relation elsewhere. `pg_temp` is listed last so a temporary table
    # cannot shadow it either (unlisted, it is searched first). A list: see
    # `guc_value_sql`.
    "search_path": "public, pg_temp",
}

# Per-transaction only, never a role default. `default_transaction_read_only`
# above is read when a transaction STARTS, and the executor's transaction has
# already started (Django's `atomic` BEGIN) when it is set, so on its own it
# left the running transaction read-WRITE: a SECURITY DEFINER function owned
# by a privileged role could write, and the write committed (ledger F01).
# `transaction_read_only` is the running transaction's own flag; with it on,
# any write — inside a SECURITY DEFINER function too — fails with SQLSTATE
# 25006 (read_only_sql_transaction).
TRANSACTION_GUCS: dict[str, str] = {"transaction_read_only": "on"}

# `SET LOCAL` does not accept parameter binding, so the GUC name/value above
# are f-string-interpolated into SQL. Validate at import that every key and
# value is a safe identifier — a future contributor who slips `"; SELECT 1 --`
# into the dict should fail at module load, not at the next cursor open.
_SAFE_GUC_NAME = re.compile(r"^[a-z_]+$")
_SAFE_GUC_VALUE = re.compile(r"^[a-z0-9_]+(, [a-z0-9_]+)*$")
for _name, _value in (EXPECTED_SESSION_GUCS | TRANSACTION_GUCS).items():
    if not _SAFE_GUC_NAME.fullmatch(_name):
        _msg = f"unsafe GUC name in EXPECTED_SESSION_GUCS: {_name!r}"
        raise ValueError(_msg)
    if not _SAFE_GUC_VALUE.fullmatch(_value):
        _msg = f"unsafe GUC value in EXPECTED_SESSION_GUCS: {_value!r}"
        raise ValueError(_msg)


def guc_value_sql(value: str) -> str:
    """A guard's value as the right-hand side of `SET` / `ALTER ROLE ... SET`:
    each list element quoted on its own (`'public', 'pg_temp'`; one quoted
    string `'public, pg_temp'` would be a single schema of that name). The
    values are the validated constants above, never input."""
    return ", ".join(f"'{item}'" for item in value.split(", "))


# SESSION_CONTEXT hook GUC names. The hook is consumer code; its values are
# bound as `set_config` params (never interpolated), and the name is bound
# too — but we additionally restrict it to the `mcp_sql.*` custom-GUC
# namespace so a hook cannot touch a built-in GUC (e.g. flip
# `default_transaction_read_only` back off).
_SAFE_CONTEXT_GUC_NAME = re.compile(r"^mcp_sql\.[a-z_]+$")


def validate_session_context(session_context: object) -> None:
    """Raise on a malformed SESSION_CONTEXT hook result.

    `TypeError` for a non-Mapping, `ValueError` for a GUC name outside the
    `mcp_sql.*` namespace. The single shape gate, used twice: the executor
    calls it EAGERLY right after invoking the hook — before any DB work —
    so a bad result is audited as hook misconfiguration and can never
    surface as an exception from inside the read transaction; and
    `enter_readonly_session` re-runs it for direct callers (smoke command,
    consumer code).
    """
    if not isinstance(session_context, Mapping):
        msg = (
            "SESSION_CONTEXT hook must return a Mapping (or None), got "
            f"{type(session_context).__name__}"
        )
        raise TypeError(msg)
    for name in session_context:
        if not isinstance(name, str) or not _SAFE_CONTEXT_GUC_NAME.fullmatch(name):
            msg = f"unsafe SESSION_CONTEXT GUC name: {name!r}"
            raise ValueError(msg)


def enter_readonly_session(
    cursor: SQLCursor,
    *,
    role: str,
    session_context: Mapping[str, str] | None = None,
) -> None:
    """`SET LOCAL ROLE <role>` + each guard, then any per-profile context.

    Must be called inside a transaction. `role` is the bound profile's
    Postgres role. `session_context` is the already-resolved output of the
    profile's optional `SESSION_CONTEXT` hook (`{guc_name: value}` or None,
    the dormant default). Each context GUC is set transaction-locally via
    parameterized `set_config(name, value, true)` — value bound as a param
    (never interpolated), name restricted to the `mcp_sql.*` namespace.
    """
    cursor.execute(f"SET LOCAL ROLE {role}")
    for name, value in (EXPECTED_SESSION_GUCS | TRANSACTION_GUCS).items():
        cursor.execute(f"SET LOCAL {name} = {guc_value_sql(value)}")
    if session_context:
        validate_session_context(session_context)
        for name, value in session_context.items():
            cursor.execute("SELECT set_config(%s, %s, true)", [name, str(value)])


def session_drift(cursor: SQLCursor, expected_role: str) -> dict[str, tuple[str, str]]:
    """Return `{guc_name: (expected, actual)}` for any GUC that does not match.

    `expected_role` is the profile role the caller entered via
    `enter_readonly_session`. Empty dict means the session matches both that
    role, `EXPECTED_SESSION_GUCS` and `TRANSACTION_GUCS` — the LIVE
    `transaction_read_only` flag included, not only its default. Use this in
    smoke / executor pre-flight to catch a connection that did not enter the
    session correctly.
    """
    drift: dict[str, tuple[str, str]] = {}
    cursor.execute("SELECT current_user")
    row = cursor.fetchone()
    assert row is not None  # SELECT current_user always returns exactly one row
    actual_role = str(row[0])
    if actual_role != expected_role:
        drift["current_user"] = (expected_role, actual_role)
    for name, expected in (EXPECTED_SESSION_GUCS | TRANSACTION_GUCS).items():
        cursor.execute(f"SHOW {name}")
        row = cursor.fetchone()
        assert row is not None  # SHOW always returns exactly one row
        actual = str(row[0])
        if actual != expected:
            drift[name] = (expected, actual)
    return drift
