"""Demo-only MFA checker for the example project.

The package ships a fail-closed default MFA checker
(`mcp_sql.conf.deny_unconfigured_mfa`, returns `False` for every user) so an
extracted consumer that forgets to wire a real check denies MCP access rather
than silently granting it. That default is correct for production — but it also
means a consumer MUST set `MCP_SQL["MFA_CHECKER"]`, or the OAuth issuance gate
rejects everyone and the end-to-end flow can never complete.

This stock-Django example has no allauth (and thus no real TOTP), so it wires
the permissive checker below purely to demonstrate the surface. **Do not copy
this into a real deployment** — production consumers point `MFA_CHECKER` at a
genuine check, e.g. `"allauth.mfa.utils.is_mfa_enabled"`.
"""

from typing import Any


def allow_all(user: Any) -> bool:
    """Demo MFA gate: treat every user as MFA-enabled. Example use only."""
    return True
