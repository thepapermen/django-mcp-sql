"""Shared fixtures for Phase 3 OAuth + MCP transport tests.

Most tests need the same trio: the canonical `mcp-sql` OAuth Application
(created by migration 0005), a staff user holding `mcp_sql.use_mcp_session`
(provisioned by the `provision_mcp_profiles` post_migrate receiver), and a
freshly-minted access token bound to both. These fixtures wrap that setup.

MFA is mocked rather than driven through a real authenticator model. Both
MCP gate sites (`auth.py` and `views/oauth_authorize.py`) read the checker
through `mcp_sql_settings.MFA_CHECKER`, so the fixtures override
`MCP_SQL["MFA_CHECKER"]` to a module-level helper here. A consumer whose
settings install their own MFA-enforcement middleware (which would
intercept test-client requests before the package gate) declares the
middleware's checker symbol(s) in `MCP_SQL_TEST_MFA_PATCH_TARGETS`; the
fixtures patch each listed dotted path to a truthy checker. Under the
package's standalone settings (`mcp_sql.tests.settings`) the list is
absent and no consumer patching happens.
"""

import secrets
from datetime import timedelta

import pytest
from django.conf import settings as django_settings
from django.contrib.auth.models import Permission
from django.core.cache import cache
from django.utils import timezone


def _mfa_checker_truthy(_user, types=None):
    """Module-level callable so the conftest can be referenced by dotted path."""
    return True


def _mfa_checker_falsy(_user, types=None):
    return False


def _patch_consumer_mfa(monkeypatch):
    """Patch each consumer-declared MFA symbol to a truthy checker.

    A consumer's staff-MFA-enforcement middleware would otherwise redirect
    authenticated staff without MFA to its TOTP setup page and preempt the
    package's own gate in integration tests. The consumer's test settings
    declare the symbol(s) via `MCP_SQL_TEST_MFA_PATCH_TARGETS`; absent (the
    package's standalone settings), this is a no-op.
    """
    for target in getattr(django_settings, "MCP_SQL_TEST_MFA_PATCH_TARGETS", []):
        monkeypatch.setattr(target, _mfa_checker_truthy)


@pytest.fixture
def _isolated_mcp_cache():
    """Wipe the cache so the throttle counters / block keys start clean.

    Used by the silent-IP-block tests across both throttle scopes —
    `TestBadTokenIpBlock` / `TestAnonymousProbeCounter` (`mcp_sql:bad_token:*`)
    and `TestRegistrationSilentBlock` / `test_throttle.py` (`mcp_sql:register:*`).
    Those tests read the per-IP counter from the cache; leftover keys from a
    previous test would shift the threshold off by N.

    `cache.clear()` is a **global** wipe — django-redis calls FLUSHDB by
    default and LocMemCache (the Django default when settings/test.py
    doesn't override `CACHES`) drops every key in the local dict. If
    another test in the same process depends on cache state (e.g. axes
    failure counters — note `feedback_pytest_db_interference` flags that
    concurrent `make test` runs share state), this fixture would race
    with it. Today the project's tests don't share cache state across
    files; if that ever changes, narrow this to `cache.delete_pattern`
    over BOTH `mcp_sql:bad_token:*` AND `mcp_sql:register:*` (or just
    `mcp_sql:*`) — don't scope it to one namespace, or the other scope's
    keys leak across tests.
    """
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def mcp_app(db):
    """The single canonical OAuth Application row.

    `make test` runs with `--nomigrations`, so the Phase 3 data migration
    (0005) doesn't execute against the test DB. This fixture mirrors the
    migration's values exactly so test setup matches production state.
    """
    from oauth2_provider.models import Application

    app, _ = Application.objects.get_or_create(
        name="mcp-sql",
        defaults={
            "client_id": "mcp-sql",
            "client_secret": "",
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "skip_authorization": True,
            "redirect_uris": "http://127.0.0.1",
            "algorithm": "",
        },
    )
    # Sanity-check the public-client invariant. The `TestOAuthTokenEndpointHappyPath`
    # test exercises the actual contract (POST /o/token/ with no client_secret
    # works); this guard is here just so a future fixture edit that silently
    # downgrades to a confidential client fails fast at fixture setup.
    assert app.client_type == Application.CLIENT_PUBLIC
    return app


@pytest.fixture
def use_mcp_perm(db):
    """The `mcp_sql.use_mcp_session` Permission for the default profile.

    Provisioned by the `provision_mcp_profiles` post_migrate receiver (one
    Permission per `MCP_SQL["PROFILES"]` entry, content_type `mcpquerylog`).
    `MCPQueryLog.Meta.permissions` is empty since TIC-585 — codenames are
    config-derived, so Django's `create_permissions` no longer makes this one.
    """
    return Permission.objects.get(
        codename="use_mcp_session",
        content_type__app_label="mcp_sql",
        content_type__model="mcpquerylog",
    )


@pytest.fixture
def mcp_group(db, use_mcp_perm):
    """The `mcp_sql_users` group holding `use_mcp_session` (the default profile).

    Provisioned by the `provision_mcp_profiles` post_migrate receiver, which
    runs at test-DB setup (even under `--nomigrations`); this fixture fetches
    it (`get_or_create` is just defensive) so the group-grant signal has a
    real group to recognise.
    """
    from django.contrib.auth.models import Group
    from mcp_sql.conf import mcp_sql_settings

    group_name = mcp_sql_settings.profiles()["default"].group_name
    group, _ = Group.objects.get_or_create(name=group_name)
    group.permissions.add(use_mcp_perm)
    return group


@pytest.fixture
def mcp_user_factory():
    """Override-seam: callable producing a fresh test user (R5 reusability).

    Returns a `callable(**kwargs) -> User`. The package's default uses
    only stock Django: `get_user_model().objects.create_user(...)` keyed
    on `UserModel.USERNAME_FIELD` so it works with any consumer's user
    model (email-as-username, plain `username`, custom field) — without
    importing any consumer-specific factory. **Deliberately** does NOT
    import a consumer-specific factory (e.g. `myapp.users.tests.factories
    .UserFactory`); that would be decoupling theatre — the whole point of
    the override-seam is that
    an extracted `django-mcp-sql` ships this conftest and runs against
    the consumer's user model unchanged.

    A consumer who wants their own factory (factory_boy random fields,
    realistic test fixtures, etc.) overrides this fixture in their own
    conftest **at or below** the package's test directory (pytest's
    more-local-wins resolution).
    """

    from mcp_sql.tests.factories import UserFactory

    return UserFactory


@pytest.fixture
def mcp_session_factory():
    """Override-seam: callable producing a Session row for the gate test (R5).

    The session-existence runtime gate in `MCPOAuth2Authentication` queries
    `apps.get_model(mcp_sql_settings.SESSION_MODEL)` — for this project,
    that resolves to the vendored `user_sessions.Session` (with the `user`
    FK + `expire_date` columns the gate needs). The default factory creates
    a row in that model. Consumers using a different session model
    (anything that exposes `session_key`, `session_data`, `expire_date`,
    `user`) override by redefining this fixture.
    """
    from django.apps import apps
    from mcp_sql.conf import mcp_sql_settings

    def _make(*, user, expire_date=None):
        session_model = apps.get_model(mcp_sql_settings.SESSION_MODEL)
        return session_model.objects.create(
            session_key=secrets.token_urlsafe(20),
            session_data="",
            expire_date=expire_date or (timezone.now() + timedelta(hours=1)),
            user=user,
        )

    return _make


@pytest.fixture
def mcp_user(db, use_mcp_perm, mcp_user_factory):
    """Active staff user holding `mcp_sql.use_mcp_session`. MFA mocked separately."""
    user = mcp_user_factory(is_active=True, is_staff=True)
    user.user_permissions.add(use_mcp_perm)
    return user


@pytest.fixture
def mcp_mfa_on(monkeypatch, settings):
    """Force the MCP MFA gate to pass by overriding `MCP_SQL["MFA_CHECKER"]`.

    Both MCP gate sites read the checker through `mcp_sql_settings.MFA_CHECKER`
    (R2 of the reusability lift), so a single settings override covers both
    `auth.py` and `views/oauth_authorize.py`. The accessor's
    `setting_changed` receiver flushes its cache on enter and exit so the
    dotted-path resolution sees the fresh value each side of the test.

    A consumer's MFA-enforcement middleware reads its own checker symbol,
    which must also be patched — otherwise it would redirect authenticated
    staff without MFA to the TOTP setup page and mask the `/o/authorize/`
    gate in integration tests. See `_patch_consumer_mfa`.
    """
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "MFA_CHECKER": "mcp_sql.tests.conftest._mfa_checker_truthy",
    }
    _patch_consumer_mfa(monkeypatch)


@pytest.fixture
def mcp_mfa_off(monkeypatch, settings):
    """Inverse of `mcp_mfa_on` for the MCP gate's MFA check.

    Overrides `MCP_SQL["MFA_CHECKER"]` to a False-returning callable so
    both gate sites reject; keeps any consumer middleware checker truthy so
    integration tests reach the gate without being preempted by the
    middleware's MFA-setup redirect (the gate itself is what these tests
    assert on).
    """
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "MFA_CHECKER": "mcp_sql.tests.conftest._mfa_checker_falsy",
    }
    _patch_consumer_mfa(monkeypatch)


@pytest.fixture
def mcp_access_token(db, mcp_user, mcp_app):
    """A valid `mcp:sql` AccessToken bound to `mcp_user` + the `mcp-sql` Application."""
    from oauth2_provider.models import AccessToken

    return AccessToken.objects.create(
        user=mcp_user,
        token="test_" + secrets.token_urlsafe(24),
        application=mcp_app,
        expires=timezone.now() + timedelta(hours=1),
        scope="mcp:sql",
    )


@pytest.fixture
def mcp_active_session(db, mcp_user, mcp_session_factory):
    """An active Session row for `mcp_user`.

    The auth class verifies on every request that the user still holds at
    least one live session (`Session.expire_date > now()`) — the runtime
    half of the design's "Option D session-trust" gate (the issuance half
    is the MFA + perm check at `/o/authorize/`). Happy-path tests that
    need to reach the *final* check or pass authentication outright must
    request this fixture; tests asserting an earlier rejection don't need
    it because the session check is intentionally last in the chain.

    The session model is `MCP_SQL["SESSION_MODEL"]` (R1 of the reusability
    lift) and the construction call goes through `mcp_session_factory`
    (R5 override-seam).
    """
    return mcp_session_factory(user=mcp_user)


# --- Multi-profile (TIC-585) scaffolding ------------------------------------
# The cross-profile tests configure a `default` + `second_profile` MCP_SQL
# against the in-package stock test app (mcp_sql.tests.testapp). The model refs
# are package-owned, so no consumer model leaks into the package suite.

MCP_TESTAPP_WIDGET = "mcp_sql_testapp.Widget"
MCP_TESTAPP_SECOND_VIEW = "mcp_sql_testapp.MCPWidgetSecondProfileView"

# Second-profile binding identifiers — the single source for the tests that
# assert on them, so renaming the demonstrator tier touches exactly one place.
SECOND_PROFILE_ROLE = "mcp_ro_second_profile"
SECOND_PROFILE_CODENAME = "use_mcp_session_second_profile"
SECOND_PROFILE_GROUP = "mcp_sql_second_profiles"


def _two_profile_config(base_cfg: dict) -> dict:
    """A 2-profile MCP_SQL off the base test config: `default` (the Widget
    table) + `second_profile` (the row-limited Widget view)."""
    return {
        **base_cfg,
        "PROFILES": {
            "default": {
                "ROLE": "mcp_readonly_role",
                "PERMISSION_CODENAME": "use_mcp_session",
                "GROUP_NAME": "mcp_sql_users",
                "ALLOWED_MODELS": [MCP_TESTAPP_WIDGET],
            },
            "second_profile": {
                "ROLE": SECOND_PROFILE_ROLE,
                "PERMISSION_CODENAME": SECOND_PROFILE_CODENAME,
                "GROUP_NAME": SECOND_PROFILE_GROUP,
                "ALLOWED_MODELS": [MCP_TESTAPP_SECOND_VIEW],
            },
        },
    }


@pytest.fixture
def two_profiles(db, settings):
    """Configure a `default` + `second_profile` MCP_SQL and provision both
    profiles' groups + permissions via the real `provision_mcp_profiles`
    receiver. Returns the `{name: Profile}` mapping."""
    from django.apps import apps as django_apps
    from mcp_sql.conf import mcp_sql_settings
    from mcp_sql.signals import provision_mcp_profiles

    settings.MCP_SQL = _two_profile_config(settings.MCP_SQL)
    provision_mcp_profiles(sender=django_apps.get_app_config("mcp_sql"))
    return mcp_sql_settings.profiles()
