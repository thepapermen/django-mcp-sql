"""`conf.resolve_profile` — explicit-assignment binding, fail-closed, and
superuser-blind (TIC-585)."""

import pytest
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission

from mcp_sql.conf import Profile
from mcp_sql.conf import ResolutionOutcome
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.tests.conftest import SECOND_PROFILE_CODENAME
from mcp_sql.tests.conftest import SECOND_PROFILE_GROUP

pytestmark = pytest.mark.django_db


def test_single_group_binds_that_profile(two_profiles, mcp_user_factory):
    user = mcp_user_factory(is_active=True, is_staff=True)
    user.groups.add(Group.objects.get(name="mcp_sql_users"))
    resolved = mcp_sql_settings.resolve_profile(user)
    assert isinstance(resolved, Profile)
    assert resolved.name == "default"
    assert resolved.role == "mcp_readonly_role"


def test_no_assignment_is_no_perm(two_profiles, mcp_user_factory):
    user = mcp_user_factory(is_active=True, is_staff=True)
    assert mcp_sql_settings.resolve_profile(user) is ResolutionOutcome.NO_PERM


def test_superuser_confers_nothing(two_profiles, mcp_user_factory):
    """An active superuser has every permission via `has_perm`, but
    `resolve_profile` queries EXPLICIT assignments — so a superuser with no
    profile group/perm resolves to NO_PERM, not a free bind."""
    user = mcp_user_factory(is_active=True, is_staff=True)
    user.is_superuser = True
    user.save()
    # Sanity: the old has_perm gate WOULD have admitted this superuser.
    assert user.has_perm("mcp_sql.use_mcp_session")
    # The explicit-assignment resolver does not.
    assert mcp_sql_settings.resolve_profile(user) is ResolutionOutcome.NO_PERM


def test_two_profile_groups_is_ambiguous(two_profiles, mcp_user_factory):
    user = mcp_user_factory(is_active=True, is_staff=True)
    user.groups.add(Group.objects.get(name="mcp_sql_users"))
    user.groups.add(Group.objects.get(name=SECOND_PROFILE_GROUP))
    assert mcp_sql_settings.resolve_profile(user) is ResolutionOutcome.AMBIGUOUS_PROFILE


def test_same_codename_via_group_and_direct_is_not_ambiguous(
    two_profiles, mcp_user_factory
):
    """The same profile codename held via BOTH a group and a direct grant
    collapses to one distinct codename — bind, not AMBIGUOUS."""
    user = mcp_user_factory(is_active=True, is_staff=True)
    user.groups.add(Group.objects.get(name="mcp_sql_users"))
    perm = Permission.objects.get(
        codename="use_mcp_session",
        content_type__app_label="mcp_sql",
        content_type__model="mcpquerylog",
    )
    user.user_permissions.add(perm)
    resolved = mcp_sql_settings.resolve_profile(user)
    assert isinstance(resolved, Profile)
    assert resolved.name == "default"


def test_direct_permission_alone_binds(two_profiles, mcp_user_factory):
    """Binding is by explicit assignment — a direct `user_permissions` grant
    (no group) is a valid single assignment."""
    user = mcp_user_factory(is_active=True, is_staff=True)
    perm = Permission.objects.get(
        codename=SECOND_PROFILE_CODENAME,
        content_type__app_label="mcp_sql",
        content_type__model="mcpquerylog",
    )
    user.user_permissions.add(perm)
    resolved = mcp_sql_settings.resolve_profile(user)
    assert isinstance(resolved, Profile)
    assert resolved.name == "second_profile"
