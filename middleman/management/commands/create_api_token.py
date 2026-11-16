"""
Create an API token for a user. The token is printed once and only its hash is
stored. The token acts with the user's permissions (e.g. the proxy-operator or
proxy-auditor group).

    python manage.py create_api_token alice --name ops-script --expires-in-days 90
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from middleman.auth import create_token


class Command(BaseCommand):
    help = "Create an API token for a user; prints it once."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--name", required=True, help="What the token is for.")
        parser.add_argument("--expires-in-days", type=int, default=None,
                            help="Days until the token expires (default: never).")

    def handle(self, *args, **options):
        user = get_user_model().objects.filter(username=options["username"]).first()
        if user is None:
            raise CommandError("User {!r} does not exist.".format(options["username"]))
        if not user.is_active:
            raise CommandError("User {!r} is inactive.".format(options["username"]))
        days = options["expires_in_days"]
        if days is not None and days < 1:
            raise CommandError("--expires-in-days must be at least 1.")
        name = options["name"].strip()
        if not name:
            raise CommandError("--name cannot be empty.")
        api_token, token = create_token(user, name, timedelta(days=days) if days else None)
        self.stdout.write("Token for {} ({}), shown only once:".format(user.get_username(), api_token.name))
        self.stdout.write(token)
        self.stdout.write("Use it as: Authorization: Bearer <token>")
