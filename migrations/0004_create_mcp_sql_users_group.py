# Provisioning of the cohort group + permission moved OUT of this
# data migration and into the idempotent `provision_mcp_profiles` post_migrate
# receiver in `signals.py`, which reads `MCP_SQL["PROFILES"]` at apply time and
# creates one Permission + Group per profile. A migration cannot enumerate
# consumer-defined profile names, and the package can no longer declare a
# single static codename in `MCPQueryLog.Meta.permissions`, so the original
# body (which read the now-removed flat `MCP_SQL["GROUP_NAME"]` /
# `PERMISSION_CODENAME` keys) no longer applies.
#
# Retained as a no-op so the migration graph stays intact for environments
# that already applied it. The `default` profile's `mcp_sql_users` group +
# `use_mcp_session` permission those environments created here are found and
# left untouched by the post_migrate sync, so cohort membership survives with
# zero data migration.

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("mcp_sql", "0003_alter_mcpquerylog_result_sample"),
        ("auth", "0012_alter_user_first_name_max_length"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.RunPython(migrations.RunPython.noop, migrations.RunPython.noop),
    ]
