"""Standalone Django settings for the package's own test suite.

Self-contained: stock Django + DRF + django-oauth-toolkit + the package and
its in-package test app, against a plain PostgreSQL reachable via the
`MCP_SQL_TEST_PG_*` environment variables (defaults match the GitHub Actions
`postgres:14` service container). This is what `pytest` runs against in the
extracted repo; an in-tree consumer instead runs the suite under its own
settings (this project: `--ds=config.settings.test`).

Deliberate omissions:

- NO `mcp_readonly` database alias. `test_executor.py::
  test_alias_missing_writes_audit_and_raises` depends on its absence, the
  executor tests that do execute SQL mock `connections`, and the role-
  isolation tests enter the role on the default connection. Adding the alias
  here would flip that executor test's premise.
- NO MFA-enforcement middleware, hence no `MCP_SQL_TEST_MFA_PATCH_TARGETS`
  (the conftest seam for consumers whose middleware would preempt the
  package gate).
- NO `REST_FRAMEWORK` override. Stock DRF defaults (AllowAny + session/basic
  auth) are exactly what the package's isolation tests pin — the package
  must self-declare its auth/permission contract on `/mcp/sql/` without
  leaning on consumer DRF configuration.
- `MFA_CHECKER` stays at the package's fail-closed default
  (`deny_unconfigured_mfa`); the `mcp_mfa_on` / `mcp_mfa_off` fixtures
  override it per-test.
"""

import os

SECRET_KEY = "mcp-sql-test-suite-not-a-secret"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]

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
    "mcp_sql.tests.testapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "mcp_sql.tests.urls"

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

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("MCP_SQL_TEST_PG_DB", "mcp_sql"),
        "USER": os.environ.get("MCP_SQL_TEST_PG_USER", "postgres"),
        "PASSWORD": os.environ.get("MCP_SQL_TEST_PG_PASSWORD", "postgres"),
        "HOST": os.environ.get("MCP_SQL_TEST_PG_HOST", "127.0.0.1"),
        "PORT": int(os.environ.get("MCP_SQL_TEST_PG_PORT", "5432")),
        "OPTIONS": {"application_name": "mcp-sql-tests"},
    },
}

DATABASE_ROUTERS = ["mcp_sql.db_router.McpSqlRouter"]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/admin/login/"

# Fast + deterministic test plumbing.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
# Annotated because the django-stubs mypy plugin loads this settings module
# into the type-check build (the `[tool.mypy]` `/tests/` exclude does not drop
# the configured settings module), so a bare `[]` trips `var-annotated`.
AUTH_PASSWORD_VALIDATORS: list[dict[str, object]] = []
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
}

# Mirrors the shape an in-tree consumer's test settings expose to the suite:
# a single `default` profile whose `ALLOWED_MODELS` is empty — parser /
# executor tests pass their own `allowed_tables`, integration tests stub the
# whitelist per-case, and the cross-profile tests build a two-profile config
# from this base via the `two_profiles` fixture.
MCP_SQL = {
    "PROFILES": {
        "default": {
            "ROLE": "mcp_readonly_role",
            "PERMISSION_CODENAME": "use_mcp_session",
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": [],
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
    # The runtime session-existence gate needs a session model with a `user`
    # FK; the in-package test app ships a minimal stand-in.
    "SESSION_MODEL": "mcp_sql_testapp.TestSession",
}

OAUTH2_PROVIDER = {
    "OAUTH2_VALIDATOR_CLASS": "mcp_sql.oauth.MCPOAuth2Validator",
    "SCOPES": {"mcp:sql": "Read-only SQL surface for MCP agents"},
    "DEFAULT_SCOPES": ["mcp:sql"],
    "ACCESS_TOKEN_EXPIRE_SECONDS": 6 * 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 0,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "PKCE_REQUIRED": True,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],
}
