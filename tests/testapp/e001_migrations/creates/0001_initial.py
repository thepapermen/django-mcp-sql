from django.db import migrations

# Stands in for the migration that creates a whitelisted model's table: the
# relation `mcp_widget_second_profile` in `public`.
CREATE_SQL = (
    "CREATE TABLE public.mcp_widget_second_profile (id bigint, name varchar(100))"
)


class Migration(migrations.Migration):
    operations = [
        migrations.RunSQL(CREATE_SQL, "DROP TABLE public.mcp_widget_second_profile"),
    ]
