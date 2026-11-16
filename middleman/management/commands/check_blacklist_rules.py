"""
Report blacklist rules that are invalid in the running proxy version.

Invalid rules are never applied by the proxy (they are skipped and logged
once per process). Rules usually become invalid because they were created by
an older version, before validation existed; ``created_by_version`` says which.
Review the list and choose: fix them in the dashboard/admin, disable them,
delete them, or accept them as part of an old flow.

    python manage.py check_blacklist_rules                 # report; exit 1 if any are invalid
    python manage.py check_blacklist_rules --disable-invalid
    python manage.py check_blacklist_rules --delete-invalid
"""

import logging

from django.core.management.base import BaseCommand, CommandError

from middleman.exceptions import InvalidRuleError
from middleman.models import BlacklistRule
from middleman.rules import validate_ip_rule, validate_path_rule
from middleman.version import __version__
from proxy.settings import BLACKLISTED_IPS, BLACKLISTED_PATHS

logger = logging.getLogger("middleman.commands.check_blacklist_rules")


class Command(BaseCommand):
    help = "List blacklist rules that are invalid in this proxy version; optionally disable or delete them."

    def add_arguments(self, parser):
        action = parser.add_mutually_exclusive_group()
        action.add_argument("--disable-invalid", action="store_true", help="Disable every invalid rule.")
        action.add_argument("--delete-invalid", action="store_true", help="Delete every invalid rule.")

    def handle(self, *args, **options):
        invalid = []
        for rule in BlacklistRule.objects.order_by("id"):
            error = rule.validation_error
            if error is not None:
                invalid.append((rule, error))

        settings_invalid = []
        for name, values, validator in (
            ("BLACKLISTED_IPS", BLACKLISTED_IPS, validate_ip_rule),
            ("BLACKLISTED_PATHS", BLACKLISTED_PATHS, validate_path_rule),
        ):
            for value in values:
                try:
                    validator(value)
                except InvalidRuleError as error:
                    settings_invalid.append((name, value, error))

        self.stdout.write("Proxy version: {}".format(__version__))
        if not invalid and not settings_invalid:
            self.stdout.write(self.style.SUCCESS("All blacklist rules are valid."))
            return

        for rule, error in invalid:
            self.stdout.write(
                "  id={} type={} value={!r} enabled={} created_by_version={} reason={}: {}".format(
                    rule.pk, rule.rule_type, rule.value, rule.enabled,
                    rule.created_by_version, error.reason, error.message,
                )
            )
        for name, value, error in settings_invalid:
            self.stdout.write(
                "  setting={} value={!r} reason={}: {} (edit the environment variable)".format(
                    name, value, error.reason, error.message
                )
            )

        if options["disable_invalid"] or options["delete_invalid"]:
            verb = "Disabled" if options["disable_invalid"] else "Deleted"
            for rule, error in invalid:
                if options["disable_invalid"]:
                    if rule.enabled:
                        rule.enabled = False
                        rule.save(update_fields=["enabled"])
                else:
                    rule.delete()
                logger.info(
                    "[check_blacklist_rules] %s invalid blacklist rule | rule_type=%s value=%r "
                    "created_by_version=%r reason=%s",
                    verb, rule.rule_type, rule.value, rule.created_by_version, error.reason,
                )
            self.stdout.write(self.style.SUCCESS("{} {} invalid rule(s).".format(verb, len(invalid))))
            if settings_invalid:
                raise CommandError(
                    "{} invalid rule(s) come from settings and must be fixed in the environment.".format(
                        len(settings_invalid)
                    ),
                    returncode=1,
                )
            return

        raise CommandError(
            "{} invalid rule(s). They are not applied. Fix or delete them, or rerun with "
            "--disable-invalid / --delete-invalid.".format(len(invalid) + len(settings_invalid)),
            returncode=1,
        )
