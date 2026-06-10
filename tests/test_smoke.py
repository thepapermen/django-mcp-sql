"""`mcp_sql_smoke` profile-selection contract (`--profile`)."""

import pytest
from django.core.management.base import CommandError

from mcp_sql.management.commands.mcp_sql_smoke import Command


class TestSmokeProfileSelection:
    def test_defaults_to_default_profile(self):
        assert Command._smoke_profile(None).name == "default"

    @pytest.mark.django_db
    def test_explicit_name_selects_that_profile(self, two_profiles):
        assert Command._smoke_profile("second_profile").name == "second_profile"

    def test_unknown_name_raises_with_declared_profiles(self):
        with pytest.raises(CommandError, match="Unknown profile"):
            Command._smoke_profile("no_such_tier")
