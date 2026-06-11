"""Unregister django-oauth-toolkit ModelAdmin classes.

DOT auto-registers ModelAdmin for `Application`, `AccessToken`, `Grant`,
`RefreshToken`, and `IDToken` when `oauth2_provider` is in
`INSTALLED_APPS`. Those admins are write-enabled to superusers, which
would bypass two design invariants of the MCP SQL surface:

1. The single-Application contract. A superuser could create a new
   Application, attach a redirect URI under their control, and mint
   tokens with `mcp:sql` scope. `MCPOAuth2Authentication` rejects tokens
   not bound to an `mcp-sql` Application, but keeping a parallel write
   path open invites confusion and a future regression.
2. The locked-down redirect URI. Migration 0005 sets the canonical
   `mcp-sql` Application's `redirect_uris` to the single loopback entry
   `http://127.0.0.1` (RFC 8252 §7.3). Editing it via the admin would
   reroute the OAuth flow to an attacker-controlled URI in a single edit.

Unregistering does not remove the underlying tables (DOT still uses them
at runtime). It only removes the operator-facing admin surface. Token
lifecycle operations (revoke a user's tokens, audit usage) are documented
in `docs/oauth.md` and use the Django shell.

This module also registers READ-ONLY admins for the two audit tables
(`MCPQueryLog`, `MCPAuthRejectionLog`) plus a per-user usage-summary view
(allowed/rejected query counts + auth-rejection counts per rolling window) —
the instrument for tuning `MCP_SQL["VOLUME_ALERT_THRESHOLDS"]`.
"""

import contextlib
from datetime import timedelta
from typing import Any

from django.contrib import admin

# `NotRegistered` lives in `admin.sites` across all supported Django lines
# (it only moved to `admin.exceptions` in 5.0, still re-exported here); the
# import path is kept on `sites` for 4.2 compat. django-stubs omits it from
# the `sites` stub, hence the targeted ignore.
from django.contrib.admin.sites import NotRegistered  # type: ignore[attr-defined]
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db.models import Count
from django.template.response import TemplateResponse
from django.urls import path
from django.utils import timezone
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.models import MCPQueryLog
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Application
from oauth2_provider.models import Grant
from oauth2_provider.models import IDToken
from oauth2_provider.models import RefreshToken

for model_cls in (Application, AccessToken, Grant, RefreshToken, IDToken):
    with contextlib.suppress(NotRegistered):
        admin.site.unregister(model_cls)


# Rolling windows for the usage summary: label → seconds.
_USAGE_WINDOWS = (("1h", 3600), ("24h", 86400), ("7d", 604800))

# Search / ordering / summary labels traverse the consumer user model's
# USERNAME_FIELD — the same model-agnostic contract as `get_username()`.
_USER_LOOKUP = f"user__{get_user_model().USERNAME_FIELD}"


class _ProfileListFilter(admin.SimpleListFilter):
    """Filter by configured tier names from `MCP_SQL["PROFILES"]`.

    NOT the stock `AllValuesFieldListFilter` a bare `"profile"` entry would
    give: `profile` is an unindexed, choice-less CharField, so the stock
    filter runs `SELECT DISTINCT profile` over the unbounded append-only
    audit table on every changelist render. Configured tiers are also the
    more correct lookup set — operators filter by live tiers, not by
    whatever historical strings accumulated.
    """

    title = "profile"
    parameter_name = "profile"

    def lookups(self, request, model_admin):
        return [(name, name) for name in sorted(mcp_sql_settings.profiles())]

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(profile=self.value())
        return queryset


# django-stubs types `ModelAdmin` as generic, but Django does not make it
# runtime-subscriptable (`ModelAdmin[Model]` raises `TypeError` on import unless
# the consumer runs `django_stubs_ext.monkeypatch()`, which a published package
# must not require). So the base stays bare and the `type-arg` warning is
# silenced here rather than parameterized.
class _ReadOnlyModelAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    """View-only admin: browse rows, never add/change/delete.

    The audit tables are append-only — the executor, signal receivers, and
    auth class are the only writers — so the admin must not open a write
    path. A LOCAL mixin (not some consumer-provided read-only mixin) keeps
    the package free of project imports.
    """

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(MCPQueryLog)
class MCPQueryLogAdmin(_ReadOnlyModelAdmin):
    """Read-only browser for query audit rows + the per-user usage summary.

    Search / ordering / the `user_email` display all key on the consumer
    user model's `USERNAME_FIELD` (via `_USER_LOOKUP` / `get_username()`),
    so the admin works against any user model.
    """

    date_hierarchy = "started_at"
    list_display = (
        "id",
        "started_at",
        "user_email",
        "profile",
        "decision",
        "tool",
        "rejection_reason",
        "row_count",
        "truncated",
        "duration_ms",
        "client_ip",
    )
    list_filter = ("decision", "tool", "truncated", _ProfileListFilter)
    search_fields = (_USER_LOOKUP, "rejection_reason", "client_ip")
    list_select_related = ("user",)
    change_list_template = "admin/mcp_sql/mcpquerylog_change_list.html"

    @admin.display(description="user", ordering=_USER_LOOKUP)
    def user_email(self, obj):
        return obj.user.get_username()

    def get_urls(self):
        return [
            path(
                "usage-summary/",
                self.admin_site.admin_view(self.usage_summary_view),
                name="mcp_sql_usage_summary",
            ),
            *super().get_urls(),
        ]

    def usage_summary_view(self, request):
        # `admin_view` enforces staff login but NOT the model view
        # permission — re-add it so only operators allowed to read the audit
        # log see the per-user volume breakdown.
        if not self.has_view_permission(request):
            raise PermissionDenied
        return TemplateResponse(
            request,
            "admin/mcp_sql/usage_summary.html",
            {
                **self.admin_site.each_context(request),
                "title": "MCP usage summary",
                "opts": self.model._meta,
                "window_labels": [label for label, _ in _USAGE_WINDOWS],
                "col_count": len(_USAGE_WINDOWS) * 3 + 1,
                "rows": _usage_rows(),
            },
        )


@admin.register(MCPAuthRejectionLog)
class MCPAuthRejectionLogAdmin(_ReadOnlyModelAdmin):
    """Read-only browser for resolved-user access-ending events."""

    date_hierarchy = "started_at"
    list_display = (
        "id",
        "started_at",
        "user_email",
        "reason",
        "application_name",
        "client_ip",
    )
    list_filter = ("reason",)
    search_fields = (_USER_LOOKUP, "application_name", "client_ip")
    list_select_related = ("user",)

    @admin.display(description="user", ordering=_USER_LOOKUP)
    def user_email(self, obj):
        return obj.user.get_username()


def _usage_rows():
    """Per-user counts of allowed/rejected queries + auth-rejections per window.

    Six grouped queries (3 windows x {query log, auth-rejection log}), each
    backed by the models' `(decision|reason, started_at)` / `(user,
    started_at)` indexes. Each row is pre-shaped into a `cells` list aligned
    to `_USAGE_WINDOWS` because Django templates cannot index a dict by a
    computed key. Row labels traverse the consumer user model's
    `USERNAME_FIELD` so the summary stays model-agnostic (mirrors
    `get_username()` without a per-row instance fetch).
    """
    now = timezone.now()
    table: dict[object, dict[str, Any]] = {}

    def _row(user_id, user_label):
        return table.setdefault(
            user_id,
            {
                "label": user_label,
                "cells": {
                    label: {"allowed": 0, "rejected": 0, "auth": 0}
                    for label, _ in _USAGE_WINDOWS
                },
            },
        )

    for label, seconds in _USAGE_WINDOWS:
        since = now - timedelta(seconds=seconds)
        for r in (
            MCPQueryLog.objects.filter(started_at__gte=since)
            .values("user_id", _USER_LOOKUP, "decision")
            .annotate(n=Count("id"))
        ):
            cell = _row(r["user_id"], r[_USER_LOOKUP])["cells"][label]
            if r["decision"] in cell:  # "allowed" / "rejected"
                cell[r["decision"]] += r["n"]
        for r in (
            MCPAuthRejectionLog.objects.filter(started_at__gte=since)
            .values("user_id", _USER_LOOKUP)
            .annotate(n=Count("id"))
        ):
            _row(r["user_id"], r[_USER_LOOKUP])["cells"][label]["auth"] += r["n"]

    rows = [
        {
            "label": row["label"],
            "cells": [row["cells"][label] for label, _ in _USAGE_WINDOWS],
        }
        for row in table.values()
    ]
    rows.sort(key=lambda r: r["label"] or "")  # label is nullable on exotic user models
    return rows
