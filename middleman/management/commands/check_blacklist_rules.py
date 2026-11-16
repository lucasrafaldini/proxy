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

Rules whose *type* this version does not know (``unknown_rule_type``) almost
always come from a newer version (e.g. after a rollback). They are reported
but never disabled or deleted, unless ``--include-unknown-types`` is given:
upgrading again makes them valid.
"""

import logging

from django.core.management.base import BaseCommand, CommandError

from middleman.exceptions import InvalidRuleError
from middleman.models import BlacklistRule
from middleman.rules import validate_ip_rule, validate_path_rule
from middleman.user_agents import parse_user_agent_regex, parse_user_agent_rule
from middleman.version import __version__
from proxy.settings import (BLACKLISTED_IPS, BLACKLISTED_PATHS,
                            BLACKLISTED_USER_AGENTS,
                            BLACKLISTED_USER_AGENTS_RE)

logger = logging.getLogger("middleman.commands.check_blacklist_rules")


class Command(BaseCommand):
    help = "List blacklist rules that are invalid in this proxy version; optionally disable or delete them."

    def add_arguments(self, parser):
        action = parser.add_mutually_exclusive_group()
        action.add_argument("--disable-invalid", action="store_true", help="Disable every invalid rule.")
        action.add_argument("--delete-invalid", action="store_true", help="Delete every invalid rule.")
        parser.add_argument(
            "--include-unknown-types", action="store_true",
            help="Also disable/delete rules whose type this version does not know "
                 "(by default they are kept: they usually come from a newer version).",
        )

    def handle(self, *args, **options):
        invalid, unknown_types = [], []
        for rule in BlacklistRule.objects.order_by("id"):
            error = rule.validation_error
            if error is None:
                continue
            if error.reason == "unknown_rule_type" and not options["include_unknown_types"]:
                unknown_types.append((rule, error))
            else:
                invalid.append((rule, error))

        settings_invalid = []
        for name, values, validator in (
            ("BLACKLISTED_IPS", BLACKLISTED_IPS, validate_ip_rule),
            ("BLACKLISTED_PATHS", BLACKLISTED_PATHS, validate_path_rule),
            ("BLACKLISTED_USER_AGENTS", BLACKLISTED_USER_AGENTS, parse_user_agent_rule),
            ("BLACKLISTED_USER_AGENTS_RE", BLACKLISTED_USER_AGENTS_RE, parse_user_agent_regex),
        ):
            for value in values:
                try:
                    validator(value)
                except InvalidRuleError as error:
                    settings_invalid.append((name, value, error))

        self.stdout.write("Proxy version: {}".format(__version__))
        if not invalid and not settings_invalid and not unknown_types:
            self.stdout.write(self.style.SUCCESS("All blacklist rules are valid."))
            return

        for rule, error in unknown_types:
            self.stdout.write(
                "  id={} type={} value={!r} enabled={} created_by_version={}: rule type unknown to v{} "
                "(probably from a newer version); not applied, kept".format(
                    rule.pk, rule.rule_type, rule.value, rule.enabled, rule.created_by_version, __version__,
                )
            )

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
            if unknown_types:
                self.stdout.write(
                    "Kept {} rule(s) of unknown types; add --include-unknown-types to {} them too.".format(
                        len(unknown_types), verb.lower()[:-1]
                    )
                )
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
            "--disable-invalid / --delete-invalid.".format(len(invalid) + len(settings_invalid) + len(unknown_types)),
            returncode=1,
        )
