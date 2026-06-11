"""Per-user MCP query-volume tripwires.

Synchronous, in-request fixed-window counters (Django cache / Redis) that
emit exactly one `logger.error` per (user, decision, window) when a per-window
threshold is crossed. `logger.error` is the Sentry-event channel — the
consuming project's logging integration turns it into an event; this package
never imports `sentry_sdk` (extractability). One alert per window crossing,
not per request, is the aggregate-alert shape.

This is an ALERT, not a block: `record_query_volume` never refuses a query.
It mirrors `throttle`'s fixed-window primitive (`cache.add` SETNX seed +
`cache.incr` + a one-shot message at the threshold-crossing transition), but
keys per (user, decision) for volume observability rather than per-IP for
silent blocking.

Thresholds come from `MCP_SQL["VOLUME_ALERT_THRESHOLDS"]`, a
`{decision: {window_seconds: threshold}}` map (read via `mcp_sql_config()`,
the typed view of the raw `settings.MCP_SQL`, like the executor reads
`LIMITS` — it is a required key, not one of the accessor's defaulted keys).
`record_query_volume` is called
from `executor._audit_safely` after each `MCPQueryLog` row is written, so
every audited query — `run_query` plus the metadata tools, allowed and
rejected alike — counts toward its decision's windows. (The rare
executor-misconfig row counts as a `rejected` query too, consistent with
counting every rejected row; it is independently escalated via its own
`logger.error`, so the extra increment is accepted noise, not a second
signal.) The alert names the user — pk plus `get_username()` (the email for
an email-keyed user model) —
so a responder can act without a DB lookup; this is appropriate because the
MCP surface is staff-only (employees, not clients). It never includes the
SQL text.
"""

import logging

from django.core.cache import cache
from mcp_sql.conf import mcp_sql_config

logger = logging.getLogger(__name__)


def _volume_key(decision: str, window: int, user_id) -> str:
    return f"mcp_sql:vol:{decision}:{window}:{user_id}"


def record_query_volume(*, user_id, decision: str, user_label: str = "") -> None:
    """Count one audited query toward this user's per-window volume counters.

    For each `{window_seconds: threshold}` configured for `decision`,
    increment a fixed-window counter (anchored at the user's first query in
    the window, like `throttle`) and emit one `logger.error` near the
    threshold crossing — once per window, not on every later query. The
    seed+incr is two cache round-trips, so a Redis blip or a TTL-expiry race
    between them can drop a count or skip the exact-equality alert; that is
    acceptable for an alert (it never blocks) and is the same tradeoff
    `throttle` carries. Fail-open on cache trouble: observability must never
    break a query, so a Redis blip logs a sub-Sentry WARNING and returns.

    The counter keys on `user_id` (the stable pk); `user_label`
    (`get_username()`) is carried only for the alert message so the Sentry
    event names a person, not just a number.
    """
    windows = mcp_sql_config()["VOLUME_ALERT_THRESHOLDS"].get(decision)
    if not windows:
        return
    for window, threshold in windows.items():
        key = _volume_key(decision, window, user_id)
        try:
            cache.add(key, 0, timeout=window)
            count = cache.incr(key)
        except (ConnectionError, ValueError):
            logger.warning(
                "MCP volume counter increment failed (user=%s decision=%s window=%ds)",
                user_id,
                decision,
                window,
            )
            continue
        if count == threshold:
            logger.error(
                "MCP query-volume tripwire: user=%s (pk=%s) decision=%s reached "
                "%d within a %ds window (threshold=%d) — alert only, the query "
                "was not blocked.",
                user_label or "?",
                user_id,
                decision,
                count,
                window,
                threshold,
            )
