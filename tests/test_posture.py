"""The security posture the suite runs under is the one it claims.

CI runs the suite twice: with the package's test settings, and with
`MCP_SQL_TEST_POSTURE=minimal` (allow-all MFA checker, no session gate).
This pins that the variable actually took effect — a typo in the CI job
or in `tests/settings.py` would otherwise run the default posture twice.
"""

import os

from mcp_sql.conf import deny_unconfigured_mfa
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.tests.conftest import TEST_SESSION_MODEL
from mcp_sql.tests.conftest import allow_all_mfa


def test_settings_match_the_requested_posture():
    if os.environ.get("MCP_SQL_TEST_POSTURE") == "minimal":
        assert mcp_sql_settings.SESSION_MODEL is None
        assert mcp_sql_settings.MFA_CHECKER is allow_all_mfa
    else:
        assert mcp_sql_settings.SESSION_MODEL == TEST_SESSION_MODEL
        assert mcp_sql_settings.MFA_CHECKER is deny_unconfigured_mfa
