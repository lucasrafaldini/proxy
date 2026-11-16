"""Brute-force protection of the password login (/admin/login/, django-axes)."""

import io
from datetime import timedelta

from axes.models import AccessAttempt
from django.conf import settings
from django.core.management import call_command
from django.test import Client, TestCase, override_settings

from middleman import abuse
from middleman.models import AbuseSignal
from middleman.tests.utils.auth import make_user

ATTACKER = "203.0.113.66"
OTHER = "203.0.113.67"
PASSWORD = "correct horse battery staple"
LIMIT = settings.AXES_FAILURE_LIMIT


class AdminLoginTestCase(TestCase):
    def setUp(self):
        self.admin = make_user("admin", role=None, is_staff=True, is_superuser=True)
        self.admin.set_password(PASSWORD)
        self.admin.save()

    def login(self, username="admin", password=PASSWORD, ip=ATTACKER, client=None, **extra):
        client = client or Client()
        response = client.post(
            "/admin/login/?next=/admin/", {"username": username, "password": password, "next": "/admin/"},
            REMOTE_ADDR=ip, **extra,
        )
        return response

    def fail(self, times, ip=ATTACKER, username="admin", **extra):
        responses = []
        with self.assertLogs("middleman", "WARNING"):
            for i in range(times):
                responses.append(self.login(username=username, password="wrong-{}".format(i), ip=ip, **extra))
        return responses

    def assertLoggedIn(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/admin/")

    def assertLocked(self, response):
        self.assertEqual(response.status_code, 429)


class LockoutTest(AdminLoginTestCase):
    def test_settings_are_wired(self):
        self.assertEqual(settings.AUTHENTICATION_BACKENDS[0], "axes.backends.AxesStandaloneBackend")
        self.assertEqual(settings.MIDDLEWARE[-1], "axes.middleware.AxesMiddleware")
        self.assertEqual(settings.AXES_CLIENT_IP_CALLABLE, "middleman.client_ip.axes_client_ip")
        self.assertFalse(settings.AXES_RESET_ON_SUCCESS)
        self.assertEqual(settings.AXES_LOCKOUT_PARAMETERS, ["ip_address"])
        self.assertEqual(settings.AXES_USERNAME_CALLABLE, "middleman.apps.axes_username")

    def test_mistakes_below_the_limit_still_allow_login(self):
        responses = self.fail(LIMIT - 1)
        self.assertTrue(all(r.status_code == 200 for r in responses))  # form with an error
        self.assertLoggedIn(self.login())

    def test_limit_locks_out_even_the_right_password(self):
        self.fail(LIMIT)
        client = Client()
        self.assertLocked(self.login(client=client))
        self.assertEqual(client.get("/admin/", REMOTE_ADDR=ATTACKER).status_code, 302)  # not logged in

    def test_real_usernames_are_recorded_for_investigation(self):
        self.fail(1)
        self.assertEqual(AccessAttempt.objects.get().username, "admin")

    def test_lockout_response_does_not_reveal_whether_the_user_exists(self):
        self.fail(LIMIT)
        existing = self.login(username="admin", password="x")
        missing = self.login(username="no-such-user", password="x")
        self.assertLocked(existing)
        self.assertEqual(existing.content, missing.content)

    def test_rotating_usernames_does_not_help(self):
        with self.assertLogs("middleman", "WARNING"):
            for i in range(LIMIT):
                self.login(username="user{}".format(i), password="x")
        self.assertLocked(self.login())

    def test_other_clients_are_not_locked_out(self):
        self.fail(LIMIT)
        self.assertLoggedIn(self.login(ip=OTHER))

    def test_spoofed_forwarded_for_does_not_evade_the_lockout(self):
        with self.assertLogs("middleman", "WARNING"):
            for i in range(LIMIT):
                self.login(password="x", HTTP_X_FORWARDED_FOR="198.51.100.{}".format(i))
        self.assertLocked(self.login(HTTP_X_FORWARDED_FOR="198.51.100.200"))
        self.assertEqual(set(AccessAttempt.objects.values_list("ip_address", flat=True)), {ATTACKER})

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_behind_a_load_balancer_only_the_attacker_is_locked(self):
        lb = {"ip": "10.0.0.2"}
        with self.assertLogs("middleman", "WARNING"):
            for _ in range(LIMIT):
                self.login(password="x", HTTP_X_FORWARDED_FOR=ATTACKER, **lb)
        self.assertLocked(self.login(HTTP_X_FORWARDED_FOR=ATTACKER, **lb))
        self.assertLoggedIn(self.login(HTTP_X_FORWARDED_FOR=OTHER, **lb))  # same LB, other client
        # The attacker cannot escape by adding its own X-Forwarded-For entries.
        self.assertLocked(self.login(HTTP_X_FORWARDED_FOR="1.1.1.1, " + ATTACKER, **lb))

    def test_a_successful_login_does_not_reset_the_counter(self):
        # Attacker owns a valid account and logs into it between guesses.
        own = make_user("attacker", role=None, is_staff=True)
        own.set_password("attacker-pass")
        own.save()
        self.fail(LIMIT - 1)
        self.assertLoggedIn(self.login(username="attacker", password="attacker-pass"))
        self.fail(1)
        self.assertLocked(self.login(username="attacker", password="attacker-pass"))

    def test_lockout_expires_after_the_cool_off(self):
        self.fail(LIMIT)
        self.assertLocked(self.login())
        AccessAttempt.objects.update(attempt_time=AccessAttempt.objects.get().attempt_time
                                     - settings.AXES_COOLOFF_TIME - timedelta(seconds=1))
        self.assertLoggedIn(self.login())

    def test_admin_can_unlock_an_ip(self):
        self.fail(LIMIT)
        call_command("axes_reset_ip", ATTACKER, stdout=io.StringIO())
        self.assertLoggedIn(self.login())

    def test_non_staff_with_valid_credentials_cannot_log_in(self):
        user = make_user("staffless", role="proxy-operator")
        user.set_password(PASSWORD)
        user.save()
        response = self.login(username="staffless")
        self.assertEqual(response.status_code, 200)  # form error, no session
        self.assertNotIn("_auth_user_id", Client().session)


class LoginObservabilityTest(AdminLoginTestCase):
    def test_password_is_never_stored_or_logged(self):
        secret = "Sup3r-Secret-Guess"
        with self.assertLogs(level="DEBUG") as logs:
            self.login(password=secret)
        self.assertNotIn(secret, "\n".join(logs.output))
        attempt = AccessAttempt.objects.get()
        self.assertNotIn(secret, attempt.post_data)
        self.assertNotIn(secret, attempt.get_data)

    def test_failures_and_lockout_are_logged_with_context(self):
        with self.assertLogs("middleman.apps", "WARNING") as logs:
            for _ in range(LIMIT + 1):
                self.login(username="admin", password="x")
        self.assertIn("[AdminLogin] Failed login | ip={} username='admin'".format(ATTACKER), logs.output[0])
        self.assertTrue(any("[AdminLogin] Client locked out" in line and "username='admin'" in line
                            for line in logs.output))

    def test_a_password_typed_into_the_username_field_is_never_logged(self):
        mistyped = "MyP4ssw0rd-typed-as-username"
        with self.assertLogs(level="DEBUG") as logs:
            for _ in range(LIMIT + 1):
                self.login(username=mistyped, password="x")
        joined = "\n".join(logs.output)
        self.assertNotIn(mistyped, joined)
        self.assertIn("username='<not an account>'", joined)
        # Not in axes' own table either.
        self.assertEqual(list(AccessAttempt.objects.values_list("username", flat=True)), ["<not an account>"])
        self.assertLocked(self.login())  # the lockout still works (it is per IP)

    def test_failures_feed_abuse_detection(self):
        self.fail(4)  # 4 x 3 points >= threshold 10
        self.assertEqual(AbuseSignal.objects.get(ip=ATTACKER, kind="login_failure").count, 4)
        self.assertTrue(abuse.hides_rate_limit_headers(ATTACKER))
