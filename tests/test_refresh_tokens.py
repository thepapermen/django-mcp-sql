"""Opt-in refresh tokens (`MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"]`).

Off by default (the refresh tests in `test_oauth.py` / `test_oauth_server.py`
pin that). When on: the authorization-code exchange returns a refresh
token, every refresh rotates it, the chain is refused once the cap —
measured from the consent, across rotations — has passed, and logout or a
password change revokes refresh tokens along with access tokens.
"""

import base64
import hashlib
import secrets
from datetime import timedelta
from http import HTTPStatus
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.hashers import make_password
from django.contrib.auth.signals import user_logged_out
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError
from django.db import transaction
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.models import MCPRefreshTokenFamily
from mcp_sql.oauth_server import MCPServer
from mcp_sql.schemas import AuthRejectionReason
from mcp_sql.tests.settings import MCP_SQL as BASE_MCP_SQL
from mcp_sql.validation import validate_mcp_sql_settings
from mcp_sql.views.oauth_token import MCPTokenView
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Grant
from oauth2_provider.models import RefreshToken
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant

_LOOPBACK = "http://127.0.0.1:9999"
_CAP = 3600


@pytest.fixture
def refresh_on(settings):
    settings.MCP_SQL = {**settings.MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": _CAP}


def _s256_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _consent_and_exchange(client, user) -> dict:
    """Authorize the canonical (skip-consent) client and exchange the code."""
    client.force_login(user)
    verifier, challenge = _s256_pair()
    params = {
        "client_id": "mcp-sql",
        "response_type": "code",
        "redirect_uri": _LOOPBACK,
        "scope": "mcp:sql",
        "state": "st4te",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    location = client.get(reverse("authorize") + "?" + urlencode(params))["Location"]
    code = parse_qs(urlparse(location).query)["code"][0]
    response = client.post(
        reverse("token"),
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _LOOPBACK,
            "client_id": "mcp-sql",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == HTTPStatus.OK, response.content
    return response.json()


def _refresh(client, refresh_token: str):
    return client.post(
        reverse("token"),
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "mcp-sql",
        },
    )


def _family(refresh_token: str) -> MCPRefreshTokenFamily:
    checksum = hashlib.sha256(refresh_token.encode()).hexdigest()
    rt = RefreshToken.objects.get(token_checksum=checksum)
    return MCPRefreshTokenFamily.objects.get(token_family=rt.token_family)


class TestSetting:
    def test_off_by_default(self):
        from mcp_sql.conf import DEFAULTS

        assert DEFAULTS["REFRESH_TOKEN_MAX_AGE_SECONDS"] == 0

    @pytest.mark.parametrize(
        "value",
        [-1, True, False, "3600", 3600.0, None, 10 * 365 * 24 * 3600 + 1, 10**30],
        ids=["negative", "true", "false", "str", "float", "none", "over-10y", "huge"],
    )
    def test_invalid_values_refuse_to_boot(self, value):
        cfg = {**BASE_MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": value}
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(cfg)

    @pytest.mark.parametrize("value", [0, 86400, 10 * 365 * 24 * 3600])
    def test_valid_values(self, value):
        validate_mcp_sql_settings(
            {**BASE_MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": value}
        )


@pytest.mark.django_db
@pytest.mark.usefixtures("refresh_on", "mcp_mfa_on")
class TestRefreshEnabled:
    def test_server_registers_the_refresh_grant(self):
        server = MCPTokenView.get_oauthlib_core().server
        assert type(server) is MCPServer
        assert set(server.grant_types) == {"authorization_code", "refresh_token"}
        assert isinstance(server.grant_types["refresh_token"], RefreshTokenGrant)
        assert server.grant_types["authorization_code"].refresh_token is True

    def test_discovery_and_registration_advertise_it(self, client):
        metadata = client.get(reverse("oauth_authorization_server_metadata")).json()
        assert metadata["grant_types_supported"] == [
            "authorization_code",
            "refresh_token",
        ]
        for requested, echoed in (
            (
                ["authorization_code", "refresh_token"],
                ["authorization_code", "refresh_token"],
            ),
            (["authorization_code"], ["authorization_code"]),
        ):
            response = client.post(
                reverse("oauth_dynamic_client_registration"),
                data={"redirect_uris": [_LOOPBACK], "grant_types": requested},
                content_type="application/json",
            )
            assert response.json()["grant_types"] == echoed

    def test_exchange_issues_a_refresh_token_and_records_the_consent(
        self, client, mcp_app, mcp_user
    ):
        before = timezone.now()
        body = _consent_and_exchange(client, mcp_user)
        assert body["refresh_token"]
        family = _family(body["refresh_token"])
        assert before <= family.consented_at <= timezone.now()

    def test_refresh_rotates(self, client, mcp_app, mcp_user, settings):
        # Rotation on whatever DOT's own setting says.
        settings.OAUTH2_PROVIDER = {
            **settings.OAUTH2_PROVIDER,
            "ROTATE_REFRESH_TOKEN": False,
        }
        first = _consent_and_exchange(client, mcp_user)
        response = _refresh(client, first["refresh_token"])
        assert response.status_code == HTTPStatus.OK, response.content
        second = response.json()
        assert second["refresh_token"] != first["refresh_token"]
        assert second["access_token"] != first["access_token"]
        assert _family(second["refresh_token"]) == _family(first["refresh_token"])
        # The presented token is spent.
        assert _refresh(client, first["refresh_token"]).json()["error"] == (
            "invalid_grant"
        )

    def test_cap_is_measured_from_consent_across_rotations(
        self, client, mcp_app, mcp_user
    ):
        first = _consent_and_exchange(client, mcp_user)
        second = _refresh(client, first["refresh_token"]).json()
        family = _family(second["refresh_token"])
        # Each rotation minted a fresh token, but the chain started at the
        # consent: once the cap has passed since then, refresh is refused.
        family.consented_at = timezone.now() - timedelta(seconds=_CAP + 1)
        family.save()
        response = _refresh(client, second["refresh_token"])
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_grant"

    def test_within_the_cap_refresh_succeeds(self, client, mcp_app, mcp_user):
        first = _consent_and_exchange(client, mcp_user)
        family = _family(first["refresh_token"])
        family.consented_at = timezone.now() - timedelta(seconds=_CAP - 60)
        family.save()
        assert _refresh(client, first["refresh_token"]).status_code == HTTPStatus.OK

    def test_a_refresh_token_without_a_consent_record_is_refused(
        self, client, mcp_app, mcp_user, mcp_access_token
    ):
        # As 0.1.0b5 or earlier stored it (or any path that bypassed
        # `save_bearer_token`): DOT would accept it, the package has no
        # consent time.
        legacy = RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=mcp_app,
            access_token=mcp_access_token,
        )
        response = _refresh(client, legacy.token)
        assert response.json()["error"] == "invalid_grant"

    def test_logout_revokes_refresh_tokens(
        self, client, mcp_app, mcp_user, django_capture_on_commit_callbacks
    ):
        body = _consent_and_exchange(client, mcp_user)
        with django_capture_on_commit_callbacks(execute=True):
            user_logged_out.send(
                sender=type(mcp_user),
                request=RequestFactory().get("/logout/"),
                user=mcp_user,
            )
        assert not RefreshToken.objects.filter(user=mcp_user).exists()
        assert not AccessToken.objects.filter(user=mcp_user).exists()
        assert _refresh(client, body["refresh_token"]).json()["error"] == (
            "invalid_grant"
        )


@pytest.mark.django_db
class TestPasswordChangeRevokes:
    """Ledger F15: a password change revokes the user's MCP access and
    refresh tokens, with no dependency on a session table."""

    @pytest.fixture(autouse=True)
    def _no_session_gate(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}

    def test_password_change_revokes_and_audits(
        self, mcp_user, mcp_app, mcp_access_token, django_capture_on_commit_callbacks
    ):
        RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=mcp_app,
            access_token=mcp_access_token,
        )
        with django_capture_on_commit_callbacks(execute=True):
            mcp_user.set_password("a-new-password-123")
            mcp_user.save()
        assert not AccessToken.objects.filter(user=mcp_user).exists()
        assert not RefreshToken.objects.filter(user=mcp_user).exists()
        row = MCPAuthRejectionLog.objects.get(user=mcp_user)
        assert row.reason == AuthRejectionReason.PASSWORD_CHANGE
        assert "on password change" in row.error

    def test_password_change_with_nothing_to_revoke_writes_no_row(
        self, mcp_user, django_capture_on_commit_callbacks
    ):
        # As for logout: the table records access that ended (review round
        # 16 corrected the docs, which said the row was unconditional).
        with django_capture_on_commit_callbacks(execute=True):
            mcp_user.set_password("a-new-password-123")
            mcp_user.save()
        assert not MCPAuthRejectionLog.objects.exists()

    @pytest.mark.parametrize(
        "save",
        [
            lambda user: user.save(update_fields=["last_login"]),
            lambda user: user.save(),
        ],
        ids=["last-login-update", "unchanged-password"],
    )
    def test_other_saves_revoke_nothing(
        self, mcp_user, mcp_access_token, django_capture_on_commit_callbacks, save
    ):
        mcp_user.last_login = timezone.now()
        with django_capture_on_commit_callbacks(execute=True):
            save(mcp_user)
        assert AccessToken.objects.filter(pk=mcp_access_token.pk).exists()
        assert not MCPAuthRejectionLog.objects.exists()


class _StaffUserProxy(get_user_model()):  # type: ignore[misc]
    """A proxy of the user model, as an admin may be registered on one."""

    class Meta:
        proxy = True
        app_label = "mcp_sql_testapp"


@pytest.mark.django_db
class TestPasswordChangeEdgeCases:
    """Review round 2: proxies, the login-time hash upgrade, failed saves,
    unusable passwords, and pending authorization codes."""

    @pytest.fixture(autouse=True)
    def _no_session_gate(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}

    def test_proxy_model_save_revokes(
        self, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        proxy = _StaffUserProxy.objects.get(pk=mcp_user.pk)
        with django_capture_on_commit_callbacks(execute=True):
            proxy.set_password("a-new-password-123")
            proxy.save()
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()

    def test_login_time_hash_upgrade_revokes_nothing(
        self, settings, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        # Stored with an older hasher: `check_password` re-hashes it with the
        # preferred one and saves `update_fields=["password"]`.
        mcp_user.password = make_password("same-password", hasher="md5")
        mcp_user.save()
        settings.PASSWORD_HASHERS = [
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
        old_hash = mcp_user.password
        with django_capture_on_commit_callbacks(execute=True):
            assert mcp_user.check_password("same-password")
        assert type(mcp_user)._default_manager.get(pk=mcp_user.pk).password != (
            old_hash
        )  # the upgrade happened ...
        # ... and is not a password change.
        assert AccessToken.objects.filter(pk=mcp_access_token.pk).exists()
        assert not MCPAuthRejectionLog.objects.exists()

    @pytest.mark.parametrize(
        "write",
        ["fresh-instance", "after-set-password-save", "outdated-old-hash"],
    )
    def test_direct_hash_write_with_update_fields_revokes(
        self,
        settings,
        mcp_user,
        mcp_access_token,
        django_capture_on_commit_callbacks,
        write,
    ):
        """`user.password = make_password(new); save(update_fields=
        ["password"])` (SSO / LDAP sync, imports, scripted resets) is a real
        change, though shaped like the hash upgrade (review round 3)."""
        user_model = type(mcp_user)
        if write == "after-set-password-save":
            # `_password` now sits on the instance (as None: `save()`
            # clears what `set_password` put there) from an earlier,
            # ordinary password change.
            mcp_user.set_password("first-change")
            mcp_user.save()
            AccessToken.objects.filter(pk=mcp_access_token.pk).update(user=mcp_user)
            target = mcp_user
        elif write == "outdated-old-hash":
            # The stored hash even needs an upgrade; the write does not go
            # through `check_password`'s setter, so it is still a change.
            mcp_user.password = make_password("old", hasher="md5")
            mcp_user.save()
            settings.PASSWORD_HASHERS = [
                "django.contrib.auth.hashers.PBKDF2PasswordHasher",
                "django.contrib.auth.hashers.MD5PasswordHasher",
            ]
            target = user_model._default_manager.get(pk=mcp_user.pk)
        else:
            target = user_model._default_manager.get(pk=mcp_user.pk)
        token = AccessToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(24),
            application=mcp_access_token.application,
            expires=timezone.now() + timedelta(hours=1),
            scope="mcp:sql",
        )
        with django_capture_on_commit_callbacks(execute=True):
            target.password = make_password("a-brand-new-password")
            target.save(update_fields=["password"])
        assert not AccessToken.objects.filter(pk=token.pk).exists()
        assert MCPAuthRejectionLog.objects.filter(
            user=mcp_user, reason=AuthRejectionReason.PASSWORD_CHANGE
        ).exists()

    @pytest.mark.parametrize(
        "shape",
        ["setter-shaped", "set-password-then-other-fields", "malformed-old-hash"],
    )
    def test_real_change_shaped_like_the_upgrade_revokes(
        self,
        settings,
        mcp_user,
        mcp_access_token,
        django_capture_on_commit_callbacks,
        shape,
    ):
        """Review round 4: a real change on an instance whose stored hash
        needs upgrading, saved exactly the way `check_password`'s setter
        saves (`set_password`, `_password = None`, `update_fields=
        ["password"]`), or after an earlier `set_password` whose save left
        the password out, is still a change. So is a write over a stored
        hash too malformed to decode (it must not raise either)."""
        mcp_user.password = (
            "pbkdf2_sha256$xyz"
            if shape == "malformed-old-hash"
            else make_password("old", hasher="md5")
        )
        mcp_user.save()
        settings.PASSWORD_HASHERS = [
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
        target = type(mcp_user)._default_manager.get(pk=mcp_user.pk)
        with django_capture_on_commit_callbacks(execute=True):
            if shape == "set-password-then-other-fields":
                target.set_password("temporary")
                target.save(update_fields=[target.USERNAME_FIELD])
                target.password = make_password("a-brand-new-password")
            else:
                target.set_password("a-brand-new-password")
                target._password = None
            target.save(update_fields=["password"])
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()
        assert MCPAuthRejectionLog.objects.filter(
            user=mcp_user, reason=AuthRejectionReason.PASSWORD_CHANGE
        ).exists()

    def test_new_legacy_hash_completed_by_check_password_revokes(
        self, settings, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        """Review round 5: a legacy hash for a NEW password, assigned in
        memory (an import / migration path) and then verified, is stored by
        `check_password`'s own setter. That save is a password change: the
        hash checked is not the one stored."""
        mcp_user.set_password("old-password")
        mcp_user.save()
        settings.PASSWORD_HASHERS = [
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
        target = type(mcp_user)._default_manager.get(pk=mcp_user.pk)
        target.password = make_password("brand-new", hasher="md5")
        with django_capture_on_commit_callbacks(execute=True):
            assert target.check_password("brand-new")
        stored = type(mcp_user)._default_manager.get(pk=mcp_user.pk)
        assert stored.check_password("brand-new")  # the change was saved ...
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()
        assert MCPAuthRejectionLog.objects.filter(
            user=mcp_user, reason=AuthRejectionReason.PASSWORD_CHANGE
        ).exists()

    @pytest.mark.skipif(
        not hasattr(AbstractBaseUser, "acheck_password"),
        reason="acheck_password is Django 5.0+",
    )
    def test_async_login_time_hash_upgrade_revokes_nothing(
        self, settings, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        mcp_user.password = make_password("same-password", hasher="md5")
        mcp_user.save()
        settings.PASSWORD_HASHERS = [
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
        old_hash = mcp_user.password
        with django_capture_on_commit_callbacks(execute=True):
            assert async_to_sync(mcp_user.acheck_password)("same-password")
        assert type(mcp_user)._default_manager.get(pk=mcp_user.pk).password != (
            old_hash
        )
        assert AccessToken.objects.filter(pk=mcp_access_token.pk).exists()
        assert not MCPAuthRejectionLog.objects.exists()

    def test_password_check_marker_is_installed_once(self):
        from mcp_sql import signals

        check = AbstractBaseUser.check_password
        assert getattr(check, signals._MARKED)
        signals.install_password_check_marker()
        assert AbstractBaseUser.check_password is check

    def test_unusable_password_with_update_fields_revokes(
        self, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        with django_capture_on_commit_callbacks(execute=True):
            mcp_user.set_unusable_password()
            mcp_user.save(update_fields=["password"])
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()

    def test_a_failed_save_leaves_no_pending_revocation(
        self, mcp_user, mcp_access_token, django_capture_on_commit_callbacks
    ):
        good_name = mcp_user.get_username()
        old_hash = mcp_user.password
        mcp_user.set_password("never-committed")
        setattr(mcp_user, mcp_user.USERNAME_FIELD, "x" * 400)
        with pytest.raises(DatabaseError), transaction.atomic():
            mcp_user.save()
        setattr(mcp_user, mcp_user.USERNAME_FIELD, good_name)
        mcp_user.password = old_hash
        with django_capture_on_commit_callbacks(execute=True):
            mcp_user.save(update_fields=[mcp_user.USERNAME_FIELD])
        assert AccessToken.objects.filter(pk=mcp_access_token.pk).exists()

    @pytest.mark.parametrize("event", ["password-change", "logout"])
    @pytest.mark.usefixtures("mcp_app", "mcp_mfa_on")
    def test_pending_authorization_codes_are_deleted(
        self, client, mcp_user, event, django_capture_on_commit_callbacks
    ):
        client.force_login(mcp_user)
        verifier, challenge = _s256_pair()
        params = {
            "client_id": "mcp-sql",
            "response_type": "code",
            "redirect_uri": _LOOPBACK,
            "scope": "mcp:sql",
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        location = client.get(reverse("authorize") + "?" + urlencode(params))[
            "Location"
        ]
        code = parse_qs(urlparse(location).query)["code"][0]
        assert Grant.objects.filter(user=mcp_user).exists()
        with django_capture_on_commit_callbacks(execute=True):
            if event == "logout":
                user_logged_out.send(
                    sender=type(mcp_user),
                    request=RequestFactory().get("/logout/"),
                    user=mcp_user,
                )
            else:
                mcp_user.set_password("a-new-password-123")
                mcp_user.save()
        assert not Grant.objects.filter(user=mcp_user).exists()
        response = client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _LOOPBACK,
                "client_id": "mcp-sql",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_grant"
        assert not AccessToken.objects.filter(user=mcp_user).exists()


def _install_filtering_default_manager(monkeypatch, user_model, narrow):
    """Make `user_model`'s default manager filter rows, as a consumer's
    `objects = ActiveUserManager()` (or a soft-delete manager) declared
    first on its user model would: a subclass of the model's own manager
    class whose `get_queryset` narrows, installed as `objects` and as the
    default manager (a lookup through either must not find the row).
    `_base_manager` is untouched, as Django leaves it."""
    base = type(user_model._default_manager)

    class FilteringManager(base):  # type: ignore[misc, valid-type]
        def get_queryset(self):
            return narrow(super().get_queryset())

    manager = FilteringManager()
    manager.model = user_model
    manager.name = user_model._default_manager.name
    monkeypatch.setattr(user_model, "objects", manager, raising=False)
    monkeypatch.setattr(user_model._meta, "default_manager", manager)
    assert user_model._default_manager is manager
    assert user_model.objects is manager


_HIDING_MANAGERS = {
    "active-only": lambda qs: qs.filter(is_active=True),
    "hides-every-row": lambda qs: qs.none(),
}


@pytest.mark.django_db
class TestPasswordChangeSeesTheStoredRow:
    """A14 (Grok, review of cf29249): the stored hash is read through the
    base manager on the alias being written. Through the default manager,
    a consumer manager that filters rows hid the user, the change read as
    "no stored hash", and a user reactivated with a new password kept
    every token."""

    @pytest.fixture(autouse=True)
    def _no_session_gate(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "SESSION_MODEL": None}

    @pytest.fixture
    def credentials(self, mcp_user, mcp_app, mcp_access_token):
        """An access token, a refresh token and a pending authorization
        code for `mcp_user`, who is then deactivated (no password change,
        so nothing is revoked yet)."""
        if not any(f.name == "is_active" for f in type(mcp_user)._meta.concrete_fields):
            pytest.skip("the user model has no is_active column")
        RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=mcp_app,
            access_token=mcp_access_token,
        )
        Grant.objects.create(
            user=mcp_user,
            code=secrets.token_urlsafe(24),
            application=mcp_app,
            expires=timezone.now() + timedelta(minutes=1),
            redirect_uri=_LOOPBACK,
            scope="mcp:sql",
            code_challenge=_s256_pair()[1],
            code_challenge_method="S256",
        )
        mcp_user.is_active = False
        mcp_user.save()
        assert AccessToken.objects.filter(user=mcp_user).exists()
        return mcp_user

    @pytest.mark.parametrize("narrow", _HIDING_MANAGERS.values(), ids=_HIDING_MANAGERS)
    def test_reactivation_with_a_new_password_revokes(
        self, monkeypatch, credentials, django_capture_on_commit_callbacks, narrow
    ):
        user_model = type(credentials)
        _install_filtering_default_manager(monkeypatch, user_model, narrow)
        assert not user_model._default_manager.filter(pk=credentials.pk).exists()
        target = user_model._base_manager.get(pk=credentials.pk)
        with django_capture_on_commit_callbacks(execute=True):
            target.is_active = True
            target.set_password("a-new-password-123")
            target.save()
        assert not AccessToken.objects.filter(user=credentials).exists()
        assert not RefreshToken.objects.filter(user=credentials).exists()
        assert not Grant.objects.filter(user=credentials).exists()
        assert MCPAuthRejectionLog.objects.filter(
            user=credentials, reason=AuthRejectionReason.PASSWORD_CHANGE
        ).exists()

    @pytest.mark.parametrize("narrow", _HIDING_MANAGERS.values(), ids=_HIDING_MANAGERS)
    def test_reactivation_without_a_password_change_revokes_nothing(
        self, monkeypatch, credentials, django_capture_on_commit_callbacks, narrow
    ):
        user_model = type(credentials)
        _install_filtering_default_manager(monkeypatch, user_model, narrow)
        target = user_model._base_manager.get(pk=credentials.pk)
        with django_capture_on_commit_callbacks(execute=True):
            target.is_active = True
            target.save()
        assert AccessToken.objects.filter(user=credentials).exists()
        assert RefreshToken.objects.filter(user=credentials).exists()
        assert Grant.objects.filter(user=credentials).exists()
        assert not MCPAuthRejectionLog.objects.exists()

    @pytest.mark.parametrize("narrow", _HIDING_MANAGERS.values(), ids=_HIDING_MANAGERS)
    def test_login_time_hash_upgrade_of_a_hidden_row_revokes_nothing(
        self,
        settings,
        monkeypatch,
        credentials,
        django_capture_on_commit_callbacks,
        narrow,
    ):
        """The base manager finds a row the default manager hides; the
        login-time hash upgrade exemption must hold for it too."""
        user_model = type(credentials)
        # An older hasher's hash, written without signals (not a change).
        user_model._base_manager.filter(pk=credentials.pk).update(
            password=make_password("same-password", hasher="md5")
        )
        settings.PASSWORD_HASHERS = [
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
        _install_filtering_default_manager(monkeypatch, user_model, narrow)
        target = user_model._base_manager.get(pk=credentials.pk)
        with django_capture_on_commit_callbacks(execute=True):
            assert target.check_password("same-password")
        stored = user_model._base_manager.get(pk=credentials.pk).password
        assert stored.startswith("pbkdf2_sha256$")  # the upgrade happened ...
        # ... and is not a password change.
        assert AccessToken.objects.filter(user=credentials).exists()
        assert RefreshToken.objects.filter(user=credentials).exists()
        assert Grant.objects.filter(user=credentials).exists()
        assert not MCPAuthRejectionLog.objects.exists()

    def test_the_stored_hash_is_read_on_the_alias_being_written(self, mcp_user):
        """`pre_save` passes the alias the save writes to; the lookup must
        go there, not to the default database. An alias that does not exist
        makes that observable with one database."""
        from django.db.utils import ConnectionDoesNotExist
        from mcp_sql.signals import note_password_change

        mcp_user.set_password("a-new-password-123")
        with pytest.raises(ConnectionDoesNotExist):
            note_password_change(
                sender=type(mcp_user),
                instance=mcp_user,
                raw=False,
                using="mcp_sql_tests_no_such_alias",
                update_fields=None,
            )

    def test_the_revocation_waits_for_the_alias_being_written(self, mcp_user):
        """The deferred revocation hangs on the saving alias's transaction
        (a rollback of another alias's transaction must not drop it)."""
        from django.db.utils import ConnectionDoesNotExist
        from mcp_sql import signals

        setattr(mcp_user, signals._PENDING_REVOCATION_ATTR, True)
        with pytest.raises(ConnectionDoesNotExist):
            signals.revoke_mcp_tokens_on_password_change(
                sender=type(mcp_user),
                instance=mcp_user,
                created=False,
                raw=False,
                using="mcp_sql_tests_no_such_alias",
                update_fields=None,
            )

    def test_the_token_deletes_run_in_one_transaction_on_their_database(
        self, monkeypatch, mcp_user, mcp_access_token
    ):
        """The transaction that groups the deletes is opened on the alias
        DOT writes its tokens to (`db_for_write(AccessToken)`), and the
        deletes run there (test_multi_db_revocation covers a router that
        splits the models). With one database that is `default`, so the
        alias is asserted as passed: explicitly the routed one, not left to
        default."""
        from django.db import router
        from mcp_sql import signals

        opened = []
        real_atomic = transaction.atomic

        def atomic(using=None, *args, **kwargs):
            opened.append(using)
            return real_atomic(using, *args, **kwargs)

        monkeypatch.setattr(signals.transaction, "atomic", atomic)
        signals._revoke_and_audit(
            user=mcp_user,
            client_ip=None,
            at=timezone.now(),
            reason=AuthRejectionReason.PASSWORD_CHANGE,
            event="password change",
            committed="default",
        )
        assert opened[0] == router.db_for_write(AccessToken)
        assert not AccessToken.objects.filter(pk=mcp_access_token.pk).exists()


@pytest.mark.django_db
def test_documented_family_prune_deletes_only_orphaned_families(mcp_user, mcp_app):
    """The prune snippet in `MCPRefreshTokenFamily`'s docstring and
    docs/oauth.md: families without a refresh token go, live ones stay —
    also when some refresh token has no family (a NULL in the `NOT IN`)."""
    import uuid

    live, orphan = uuid.uuid4(), uuid.uuid4()
    now = timezone.now()
    MCPRefreshTokenFamily.objects.create(token_family=live, consented_at=now)
    MCPRefreshTokenFamily.objects.create(token_family=orphan, consented_at=now)
    for family in (live, None):
        access = AccessToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(24),
            application=mcp_app,
            expires=now + timedelta(hours=1),
            scope="mcp:sql",
        )
        RefreshToken.objects.create(
            user=mcp_user,
            token=secrets.token_urlsafe(32),
            application=mcp_app,
            access_token=access,
            token_family=family,
        )
    MCPRefreshTokenFamily.objects.exclude(
        token_family__in=RefreshToken.objects.filter(token_family__isnull=False).values(
            "token_family"
        )
    ).delete()
    assert list(
        MCPRefreshTokenFamily.objects.values_list("token_family", flat=True)
    ) == [live]
