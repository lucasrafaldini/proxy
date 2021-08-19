# Generated by Django 3.2.6 on 2021-08-18 19:08

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AccessEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=20, unique=True)),
                ('ip', models.CharField(max_length=45)),
                ('path', models.CharField(max_length=255)),
                ('already_requested', models.IntegerField(default=0)),
                ('max_requests', models.IntegerField(default=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'middleman_access_entry',
                'ordering': ['ip'],
            },
        ),
    ]