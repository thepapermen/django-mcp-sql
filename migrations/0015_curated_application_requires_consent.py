# Hand-written data migration: the curated `mcp-sql` Application now shows
# the consent page, like every other client kind (DCR-minted and
# settings-declared rows already carry `skip_authorization=False`).
#
# Why: the curated row's registered redirect is `http://127.0.0.1`, and DOT
# accepts ANY port on a loopback IP at request time. With
# `skip_authorization=True`, a phished `/o/authorize/?client_id=mcp-sql&
# redirect_uri=http://127.0.0.1:<port>&...` link opened by a logged-in,
# gate-passing user was answered with an immediate 302 carrying a code to
# that port, with no page in between, so any local process listening there
# (and holding the PKCE verifier it chose) could exchange it. The consent
# page is a CSRF-protected POST a phished GET cannot complete.
#
# Applied to the row named `MCP_SQL["APPLICATION_NAME"]` at apply time, the
# same lookup migration 0005 used to create it. Reverse restores the old
# posture. Fresh installs get the same from 0005 itself, which now creates
# the row with `skip_authorization=False`.

from django.db import migrations


def require_consent(apps, schema_editor):
    from mcp_sql.conf import mcp_sql_settings

    Application = apps.get_model("oauth2_provider", "Application")
    Application.objects.filter(name=mcp_sql_settings.APPLICATION_NAME).update(
        skip_authorization=False
    )


def skip_consent(apps, schema_editor):
    from mcp_sql.conf import mcp_sql_settings

    Application = apps.get_model("oauth2_provider", "Application")
    Application.objects.filter(name=mcp_sql_settings.APPLICATION_NAME).update(
        skip_authorization=True
    )


class Migration(migrations.Migration):
    dependencies = [
        # The curated row is created by 0005, which already depends on the
        # oauth2_provider migrations it needs.
        ("mcp_sql", "0014_mcpauthrejectionlog_reason_inactive"),
    ]

    operations = [
        migrations.RunPython(require_consent, reverse_code=skip_consent),
    ]
