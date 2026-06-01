from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("middleman", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="BlacklistRule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("rule_type", models.CharField(choices=[("ip", "IP"), ("path", "Path")], max_length=8)),
                ("value", models.CharField(max_length=255)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "middleman_blacklist_rule",
                "ordering": ["rule_type", "value"],
            },
        ),
        migrations.AddConstraint(
            model_name="blacklistrule",
            constraint=models.UniqueConstraint(fields=("rule_type", "value"), name="unique_blacklist_rule"),
        ),
    ]