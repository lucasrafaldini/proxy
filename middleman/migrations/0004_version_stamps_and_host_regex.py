from django.db import migrations, models

import middleman.version

# Rows that exist when this migration runs predate version tracking. They are
# stamped with the literal legacy marker (not the callable default, which
# would wrongly claim they were created by the current version).
LEGACY_VERSION = "pre-2.0.0"


class Migration(migrations.Migration):

    dependencies = [
        ("middleman", "0003_blacklistrule_host_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessentry",
            name="created_by_version",
            field=models.CharField(default=LEGACY_VERSION, editable=False, max_length=32),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="accessentry",
            name="created_by_version",
            field=models.CharField(
                default=middleman.version.current_version, editable=False, max_length=32
            ),
        ),
        migrations.AddField(
            model_name="blacklistrule",
            name="created_by_version",
            field=models.CharField(default=LEGACY_VERSION, editable=False, max_length=32),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="blacklistrule",
            name="created_by_version",
            field=models.CharField(
                default=middleman.version.current_version, editable=False, max_length=32
            ),
        ),
        migrations.AlterField(
            model_name="blacklistrule",
            name="rule_type",
            field=models.CharField(
                choices=[
                    ("ip", "IP"),
                    ("path", "Path"),
                    ("host", "Host (site)"),
                    ("host_re", "Host (regex)"),
                ],
                max_length=8,
            ),
        ),
    ]
