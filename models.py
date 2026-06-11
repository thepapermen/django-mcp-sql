from django.conf import settings
from django.db import models
from mcp_sql.schemas import AuthRejectionReason


class MCPQueryLog(models.Model):
    """Append-only audit row for every MCP SQL query attempt.

    Append-only is convention, not a DB trigger; admin write paths are
    deliberately absent and migration 0002 REVOKEs `mcp_readonly_role`'s
    SELECT on this table. See `docs/architecture.md` for the
    full design (audit invariant, retention notes, the curated-view
    pattern that bounds cast-error leak surface).

    Inherits from `django.db.models.Model` directly, NOT from any
    consumer base model (e.g. one adding django-simple-history tracking
    or created/updated timestamps) — a deliberate choice. Two reasons:
    (1) auditing an audit table via django-simple-history would double the
    storage cost on an already write-heavy table with no operational value
    (the audit row IS the history); (2) `created_at` / `updated_at` on an
    append-only table are misleading — `started_at` is the authoritative
    timestamp. The deviation is intentional; do not "fix" it without a
    review.
    """

    DECISION_ALLOWED = "allowed"
    DECISION_REJECTED = "rejected"
    DECISION_CHOICES = (
        (DECISION_ALLOWED, "allowed"),
        (DECISION_REJECTED, "rejected"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="+",
    )
    # Stringified DOT `AccessToken.pk` (a `BigAutoField`). CharField, not
    # FK, so purging the live token table cannot cascade or null out the
    # audit trail. Opaque correlation handle — it links an audit row to
    # an issuance event, not to a live token. NOT a `help_text` because
    # `help_text` changes ship a Django migration for pure metadata.
    token_id = models.CharField(max_length=64, blank=True, default="")
    decision = models.CharField(max_length=16, choices=DECISION_CHOICES)
    # MCP tool that produced this row (`schemas.ToolName`): `run_query` rows
    # carry the full SQL fields; `list_tables` / `describe_table` rows are
    # metadata-only (empty `raw_sql`/SQL fields, no `duration_ms`/`row_count`)
    # and are written by `executor.audit_tool_call`. The `run_query` default
    # keeps every pre-existing row correct without a data migration — before
    # this field, the executor's `run_query` path was the only writer.
    tool = models.CharField(max_length=32, default="run_query")
    # Name of the MCP profile (access tier) this request was bound to
    # (`MCP_SQL["PROFILES"]` key, e.g. "default"). Blank default keeps every
    # pre-existing row valid without a data migration — same precedent as
    # `tool`. Per-profile attribution lets the usage-summary / volume signal
    # slice by tier.
    profile = models.CharField(max_length=64, blank=True, default="")
    rejection_reason = models.CharField(max_length=64, blank=True, default="")
    raw_sql = models.TextField()
    normalized_sql = models.TextField(blank=True, default="")
    wrapped_sql = models.TextField(blank=True, default="")
    started_at = models.DateTimeField()
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    row_count = models.PositiveIntegerField(null=True, blank=True)
    truncated = models.BooleanField(default=False)
    result_bytes = models.PositiveIntegerField(null=True, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        ordering = ("-started_at",)
        indexes = (
            models.Index(fields=("user", "started_at")),
            models.Index(fields=("decision", "started_at")),
        )
        # No static `permissions` here. Each MCP profile carries its own
        # cohort-level permission (`MCP_SQL["PROFILES"][...]["PERMISSION_CODENAME"]`)
        # that gates whether a user may obtain an MCP OAuth token for that
        # tier — but the package cannot know a consumer's profile names at
        # model-definition time, so they are created idempotently from
        # PROFILES by the `post_migrate` receiver in signals.py
        # (`provision_mcp_profiles`), each hung off THIS model's content type.
        # `MCPQueryLog` is still the subsystem's only tracked state, so it
        # remains the anchor — there is just no compile-time codename list.
        verbose_name = "MCP query log"
        verbose_name_plural = "MCP query logs"

    def __str__(self) -> str:
        return f"#{self.pk} {self.decision} {self.started_at:%Y-%m-%d %H:%M:%S}"


class MCPAuthRejectionLog(models.Model):
    """Append-only audit row for resolved-user access-ending events.

    Two event classes, both keyed to a real user (see
    `schemas.AuthRejectionReason`): per-request gate denials written by
    `MCPOAuth2Authentication.authenticate`, and logout-driven token
    revocations written by `signals.revoke_mcp_tokens_on_logout`
    (`reason=SESSION_LOGOUT`). The table answers "when/why did this user
    lose MCP access?".

    Separate from `MCPQueryLog` by design. These events happen BEFORE (or
    instead of) a query being evaluated; conflating them in MCPQueryLog
    would pollute Phase 4's daily-volume "queries per user" aggregation
    with auth-rejection counts and leave ~10 SQL-shaped fields empty per
    row. Phase 4's planned revoked-credential / removed-MFA / dead-session
    probing alert reads THIS table.

    REVOKE on `mcp_readonly_role` lives in the migration that creates the
    table (same posture as `MCPQueryLog`'s migration 0002): the agent
    must not read its own rejection log.

    Every row carries a resolved `user`. Post-pivot, the anonymous /
    bad-token rejection path goes through Redis counters
    (`throttle.record_attempt` + silent IP block via `throttle.is_ip_blocked`),
    not through this table — so `user` is non-nullable. `token_pk`
    stringifies `AccessToken.pk` for the same decoupling reason as
    `MCPQueryLog.token_id`. `application_name` is a string rather than
    a FK so a future cleanup of stale dynamically-registered
    Applications (Phase 4) does not cascade or null-out audit history.
    """

    # Reason vocabulary lives in `schemas.AuthRejectionReason` (StrEnum,
    # mirrors `OutcomeReason`). Imported here only for the `choices=` kwarg
    # so admin and migration state record the closed set. Two writers
    # reference the enum directly: `auth.py` for per-request gate denials,
    # and `signals.py` for the `SESSION_LOGOUT` revocation row. Note: the
    # high-volume "bad / expired / unknown bearer" path is deliberately
    # absent from the enum and from this table — see `AuthRejectionReason`'s
    # docstring for the django-axes-on-Redis deferral rationale.
    REASON_CHOICES = tuple(
        (r.value, label)
        for r, label in (
            (
                AuthRejectionReason.BAD_APPLICATION,
                "Token not issued by an mcp-sql Application",
            ),
            (AuthRejectionReason.BAD_SCOPE, "Token does not carry mcp:sql scope"),
            (
                AuthRejectionReason.INACTIVE_OR_NON_STAFF,
                "User is not an active staff member",
            ),
            (AuthRejectionReason.NO_MFA, "User does not have a verified TOTP device"),
            (
                AuthRejectionReason.NO_PERM,
                "User holds no MCP profile permission",
            ),
            (
                AuthRejectionReason.AMBIGUOUS_PROFILE,
                "User is assigned to more than one MCP profile",
            ),
            (AuthRejectionReason.NO_SESSION, "User has no live Django session"),
            (
                AuthRejectionReason.SESSION_LOGOUT,
                "MCP tokens revoked on user logout",
            ),
        )
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="+",
    )
    token_pk = models.CharField(max_length=64, blank=True, default="")
    application_name = models.CharField(max_length=255, blank=True, default="")
    reason = models.CharField(max_length=64, choices=REASON_CHOICES)
    error = models.TextField(blank=True, default="")
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    started_at = models.DateTimeField()

    class Meta:
        ordering = ("-started_at",)
        indexes = (
            models.Index(fields=("user", "started_at")),
            models.Index(fields=("reason", "started_at")),
        )
        verbose_name = "MCP auth rejection log"
        verbose_name_plural = "MCP auth rejection logs"

    def __str__(self) -> str:
        who = self.user_id or "anon"
        return (
            f"#{self.pk} {self.reason} user={who} {self.started_at:%Y-%m-%d %H:%M:%S}"
        )
