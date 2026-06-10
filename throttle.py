"""Shared per-IP fixed-window throttle backed by the Django cache (Redis).

Two MCP surfaces share this machinery, both blocking **silently** (the
blocked response is indistinguishable from a normal one, so an attacker
can neither fingerprint the block nor pace just under the threshold):

- `auth.MCPOAuth2Authentication` — bad-token probing on `/mcp/sql/`
  (scope `"bad_token"`); the silent response is a generic 401.
- `views.registration.register_client` — registration spam on `/o/register`
  (scope `"register"`); the silent response is a synthesized 201 that
  persists no `Application` row.

Both surfaces share the same `MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]` /
`["BAD_TOKEN_IP_WINDOW_SECONDS"]` knobs — the per-IP limit that's safe for
one is safe for the other, and registration is rare enough that the high
default never collateral-blocks a legitimate developer. The keys are
scope-namespaced so a flood on one surface never depletes the other's
budget.

**The IP this keys on is only trustworthy behind a hardened edge proxy.**
Callers pass `request.META["REMOTE_ADDR"]`, which `RealIPMiddleware` has
already rewritten to the ipware-derived client IP from `X-Forwarded-For`.
That value is the genuine client only because the edge proxy (Traefik,
`forwardedHeaders.insecure: false` + no `trustedIPs`) discards
client-supplied `X-Forwarded-*` and the app port is never published past
the proxy. If that invariant ever loosens, `REMOTE_ADDR` becomes
attacker-controllable and the block can be both evaded (rotate fake IPs)
and weaponised (spoof a victim's IP to lock them out). Keying on the TCP
peer (`ORIGINAL_REMOTE_ADDR`) is NOT the fix — behind a proxy that's the
proxy's IP for every request, which would collapse the whole cohort onto
one counter. See `docs/architecture.md` "Watch out" (proxy hardening)
and `docs/oauth.md`.
"""

import logging

from django.core.cache import cache

logger = logging.getLogger(__name__)


def _ip_key(scope: str, ip: str) -> str:
    return f"mcp_sql:{scope}:ip:{ip}"


def is_ip_blocked(ip: str, *, scope: str, threshold: int) -> bool:
    """Return True when this IP's per-IP counter for `scope` is at/over threshold.

    One Redis GET, no DB I/O. Fail-open on Redis trouble: a cache outage
    returns False so a blip cannot accidentally lock everyone out (the
    downstream path runs normally). Catch is narrowed to
    `ConnectionError, ValueError` (Redis outage / TTL-evicted-key race);
    a misconfigured threshold surfaces as a normal comparison error, not a
    silent fail-open.
    """
    try:
        count = cache.get(_ip_key(scope, ip)) or 0
    except (ConnectionError, ValueError):
        return False
    return count >= threshold


def record_attempt(ip: str, *, scope: str, window: int, threshold: int) -> int:
    """Increment this IP's per-`scope` fixed-window counter; return the new count.

    Returns the new per-IP count (0 on cache failure). Emits exactly one
    operator `WARNING` at the threshold-crossing transition so the silent
    block is at least visible in log aggregation when it engages — and not
    on every subsequent blocked request (callers short-circuit via
    `is_ip_blocked` before recording, so the window is fixed from the first
    attempt and not extended by later ones).

    `cache.add(key, 0, timeout=window)` is the race-safe SETNX seed that
    fixes the TTL once; `cache.incr` is an atomic INCRBY. Failure is logged
    at WARNING (sub-Sentry) so a cache outage doesn't become an event flood.

    No global cross-IP counter is kept: the per-user volume tripwire
    (`mcp_sql.observability`, reading `MCPQueryLog`) is the intended
    aggregate-alert channel, and the botnet-probe alert that an earlier
    design would have fed from a global per-minute bucket was deliberately
    dropped — the silent per-IP block plus this threshold-crossing WARNING
    are the whole response to bearer-probe noise.
    """
    ip_key = _ip_key(scope, ip)
    try:
        cache.add(ip_key, 0, timeout=window)
        ip_count = cache.incr(ip_key)
    except (ConnectionError, ValueError):
        logger.warning("MCP %s counter increment failed (ip=%s)", scope, ip)
        return 0
    if ip_count == threshold:
        logger.warning(
            "MCP %s silent IP block engaged: ip=%s count=%d threshold=%d "
            "window_seconds=%d. Clear via `cache.delete('%s')` or wait the window.",
            scope,
            ip,
            ip_count,
            threshold,
            window,
            ip_key,
        )
    return ip_count
