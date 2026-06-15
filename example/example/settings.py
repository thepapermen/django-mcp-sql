"""Django settings for the django-mcp-sql example project.

Stock Django — no allauth, no vendored sessions, no project-specific user
model. Demonstrates that the package works against a vanilla consumer.

Two database aliases — `default` for the example's own writes,
`mcp_readonly` for the package's read-only path. Both point at the same
PG database; connection details come from environment variables (see
the package README for the recommended values).
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "example-not-for-production"  # noqa: S105
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "oauth2_provider",
    "mcp_sql",
    "notes",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "example.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "example.wsgi.application"


_PG_HOST = os.environ.get("EXAMPLE_PG_HOST", "127.0.0.1")
_PG_PORT = int(os.environ.get("EXAMPLE_PG_PORT", "5432"))
_PG_DB = os.environ.get("EXAMPLE_PG_DB", "mcp_sql_example_local")
_PG_USER = os.environ.get("EXAMPLE_PG_USER", "mcp_sql_example")
_PG_PASSWORD = os.environ.get("EXAMPLE_PG_PASSWORD", "mcp_sql_example")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _PG_DB,
        "USER": _PG_USER,
        "PASSWORD": _PG_PASSWORD,
        "HOST": _PG_HOST,
        "PORT": _PG_PORT,
        "ATOMIC_REQUESTS": True,
        "OPTIONS": {"application_name": "mcp-sql-example"},
    },
    # MCP read-only alias. Same database, same role — Postgres role-based
    # boundary kicks in at runtime via `SET LOCAL ROLE mcp_readonly_role`.
    # ATOMIC_REQUESTS False so the executor's own transaction does not join
    # the default alias's request-scoped one.
    "mcp_readonly": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _PG_DB,
        "USER": _PG_USER,
        "PASSWORD": _PG_PASSWORD,
        "HOST": _PG_HOST,
        "PORT": _PG_PORT,
        "ATOMIC_REQUESTS": False,
        "CONN_MAX_AGE": 0,
        "OPTIONS": {"application_name": "mcp-sql-example-readonly"},
    },
}

DATABASE_ROUTERS = ["mcp_sql.db_router.McpSqlRouter"]

AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/admin/login/"

# === MCP SQL config ===
#
# Two profiles, to demonstrate multi-role access tiers:
#
#   default     — the original flat demo surface: one Django-internal model
#                 (auth.Permission) so `list_tables` returns something
#                 inspectable, plus `notes.Note` so `run_query` reads
#                 user-created rows. Role `mcp_readonly_role` (the package
#                 default), group `mcp_sql_users`, perm `use_mcp_session`.
#   second_profile — a SECOND tier with its own role (`mcp_ro_second_profile`),
#                 group, and permission, whose only readable object is a
#                 curated VIEW (`notes.MCPNoteSecondProfileView`) that row- AND
#                 column-limits notes: only titles starting with "S", and
#                 without `body`/`author_id`. The view's static WHERE is the
#                 row boundary; the role gets SELECT on the view, never on
#                 `notes_note`. This is the per-role row-limiting pattern.
#
# Per-profile groups/permissions are created idempotently by the package's
# `provision_mcp_profiles` post_migrate signal (just run `make migrate`); the
# roles are created by `make roles`. `SESSION_CONTEXT` (per-user scoping) is
# left dormant — the per-user recipe lives in the docs, not this demo.
MCP_SQL = {
    "PROFILES": {
        "default": {
            "ROLE": "mcp_readonly_role",
            "PERMISSION_CODENAME": "use_mcp_session",
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": [
                "auth.Permission",
                "notes.Note",
            ],
        },
        "second_profile": {
            "ROLE": "mcp_ro_second_profile",
            "PERMISSION_CODENAME": "use_mcp_session_second_profile",
            "GROUP_NAME": "mcp_sql_second_profiles",
            "ALLOWED_MODELS": [
                "notes.MCPNoteSecondProfileView",
            ],
        },
    },
    "BAN_SELECT_STAR": True,
    "LIMITS": {
        "DEFAULT_LIMIT": 10,
        "HARD_LIMIT": 100,
        "BYTES_LIMIT": 256 * 1024,
    },
    "VOLUME_ALERT_THRESHOLDS": {
        "allowed": {3600: 50, 86400: 150},
        "rejected": {3600: 50, 86400: 150},
    },
    "BAD_TOKEN_IP_THRESHOLD": 100,
    "BAD_TOKEN_IP_WINDOW_SECONDS": 21600,
    "RESOURCE_NAME": "MCP SQL Example",
    # Stock Django has no MFA. The package default (`deny_unconfigured_mfa`)
    # is fail-closed and would reject every user at the OAuth issuance gate,
    # so the demo wires a permissive checker. Production consumers point this
    # at a real check (e.g. "allauth.mfa.utils.is_mfa_enabled") — see
    # `example/mfa.py`.
    "MFA_CHECKER": "example.mfa.allow_all",
}

# === OAuth2 (django-oauth-toolkit) ===
OAUTH2_PROVIDER = {
    "OAUTH2_VALIDATOR_CLASS": "mcp_sql.oauth.MCPOAuth2Validator",
    "SCOPES": {"mcp:sql": "Read-only SQL surface for MCP agents"},
    "DEFAULT_SCOPES": ["mcp:sql"],
    "ACCESS_TOKEN_EXPIRE_SECONDS": 6 * 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 0,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "PKCE_REQUIRED": True,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],
}

# Cache backend — Redis if reachable, fall back to LocMem otherwise. The
# bad-token IP-block counter (`mcp_sql.auth._is_ip_blocked`) uses
# `django.core.cache`, so SOME backend must be configured.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "mcp_sql": {"level": "DEBUG", "propagate": True},
    },
}
