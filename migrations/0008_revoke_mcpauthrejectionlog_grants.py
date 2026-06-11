"""REVOKE `mcp_readonly_role`'s SELECT on `mcp_sql_mcpauthrejectionlog`.

Same posture as migration 0002 for `MCPQueryLog`: the agent must not be
able to read its own auth-rejection audit trail. The DO/EXCEPTION wrapper
makes the migration safe on fresh dev DBs where the role does not yet
exist (catches `undefined_object` from REVOKE-against-missing-role).

Hand-written RunSQL — `makemigrations` cannot infer DDL like REVOKE from
model state, so this migration is the conventional path for the same
contract that 0002 enforces on the older audit table.

Although the post-pivot design routes anonymous / bad-token probes
through Redis counters (not into this table), the 6 resolved-user
defense-in-depth gates (`BAD_APPLICATION`, `BAD_SCOPE`,
`INACTIVE_OR_NON_STAFF`, `NO_MFA`, `NO_PERM`, `NO_SESSION` — see
`MCPOAuth2Authentication.authenticate`) DO write rows here. The REVOKE
is defense-in-depth against (a) a future grants-pipeline misconfiguration
adding `mcp_sql.MCPAuthRejectionLog` to `ALLOWED_MODELS` and (b) any
`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO
mcp_readonly_role` ever being issued (would auto-grant SELECT to every
new table including ours).
"""

from django.db import migrations

REVOKE_AUTH_REJECTION_FROM_READONLY = """
DO $$
BEGIN
    REVOKE SELECT ON mcp_sql_mcpauthrejectionlog FROM mcp_readonly_role;
EXCEPTION
    WHEN undefined_object THEN
        NULL;
END
$$;
"""


class Migration(migrations.Migration):
    dependencies = [
        ("mcp_sql", "0007_mcpauthrejectionlog"),
    ]

    operations = [
        migrations.RunSQL(
            REVOKE_AUTH_REJECTION_FROM_READONLY,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
