"""
Delete abuse signals older than N days (they only matter inside the detection
window; older ones are an audit trail). Client policies are never touched.

    python manage.py prune_abuse_signals --older-than-days 30
"""

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from middleman.abuse import get_config
from middleman.models import AbuseSignal


class Command(BaseCommand):
    help = "Delete abuse signals older than N days."

    def add_arguments(self, parser):
        parser.add_argument("--older-than-days", type=int, default=30)

    def handle(self, *args, **options):
        days = options["older_than_days"]
        window_days = get_config()["WINDOW_MINUTES"] / (24 * 60)
        if days < 1 or days < window_days:
            raise CommandError("--older-than-days must be at least 1 and cover the detection window.")
        deleted, _ = AbuseSignal.objects.filter(bucket__lt=timezone.now() - timedelta(days=days)).delete()
        self.stdout.write("Deleted {} abuse signal bucket(s) older than {} days.".format(deleted, days))
