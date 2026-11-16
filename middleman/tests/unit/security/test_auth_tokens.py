"""API token authentication: format, storage, and every way a token can be wrong."""

import hashlib
import re
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from middleman.auth import (GENERIC_FAILURE, LAST_USED_RESOLUTION, create_token,
                            generate_token, hash_token, parse_token)
from middleman.models import ApiToken
from middleman.tests.utils.auth import make_user

TOKEN_RE = re.compile(r"mm_[0-9a-f]{8}_[A-Za-z0-9_-]{43}")


class TokenFormatTest(TestCase):
    def test_generated_tokens_are_well_formed_and_unique(self):
        tokens = {generate_token()[0] for _ in range(200)}
        self.assertEqual(len(tokens), 200)
        for token in tokens:
            self.assertRegex(token, TOKEN_RE)

    def test_only_the_hash_is_stored(self):
        user = make_user()
        api_token, token = create_token(user, "ci")
        stored = ApiToken.objects.get(pk=api_token.pk)
        self.assertEqual(stored.key_hash, hashlib.sha256(token.encode()).hexdigest())
        secret = token.split("_", 2)[2]
        for field in ApiToken._meta.concrete_fields:
            self.assertNotIn(secret, str(getattr(stored, field.attname)))

    def test_parse_token(self):
        token, prefix, _ = generate_token()
        self.assertEqual(parse_token(token), prefix)
        for bad in ["", "mm_", "mm_zzzzzzzz_" + "a" * 43, "xx_" + token[3:], token + "a", token[:-1],
                    token.upper(), " " + token, token.replace("_", "-", 1)]:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_token(bad))


class TokenAuthenticationTest(TestCase):
    """Every failure is a 401 with the same body, a WWW-Authenticate header and a logged reason."""

    url = "/registry/"

    def setUp(self):
        self.user = make_user()
        self.api_token, self.token = create_token(self.user, "tests")

    def call(self, authorization=None, **extra):
        client = APIClient()
        if authorization is not None:
            extra["HTTP_AUTHORIZATION"] = authorization
        return client.get(self.url, **extra)

    def assertRejected(self, authorization, reason=None, **extra):
        with self.assertLogs("middleman", "WARNING") as logs:
            response = self.call(authorization, **extra)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": GENERIC_FAILURE})
        self.assertEqual(response["WWW-Authenticate"], 'Bearer realm="middleman"')
        if reason:
            self.assertTrue(any("reason={}".format(reason) in line for line in logs.output), logs.output)
        return logs

    def test_valid_token(self):
        response = self.call("Bearer " + self.token)
        self.assertEqual(response.status_code, 200)

    def test_scheme_is_case_insensitive_and_extra_spaces_are_tolerated(self):
        for header in ["bearer " + self.token, "BEARER " + self.token, "Bearer   " + self.token, " Bearer " + self.token]:
            with self.subTest(header=header):
                self.assertEqual(self.call(header).status_code, 200)

    def test_missing_credentials_is_401_not_authenticated(self):
        response = self.call()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], 'Bearer realm="middleman"')

    def test_other_schemes_are_not_accepted(self):
        for header in ["Token " + self.token, "Basic b3BlcmF0b3I6cHctb3BlcmF0b3I=", self.token]:
            with self.subTest(header=header):
                self.assertEqual(self.call(header).status_code, 401)

    def test_malformed_headers(self):
        self.assertRejected("Bearer", "malformed_header")
        self.assertRejected("Bearer " + self.token + " extra", "malformed_header")

    def test_malformed_tokens(self):
        for token in ["x", "mm_1234", self.token[:-1], self.token + "x", self.token.upper(), "mm_" + "g" * 8 + "_" + "a" * 43]:
            with self.subTest(token=token):
                self.assertRejected("Bearer " + token, "malformed_token")

    def test_unknown_prefix(self):
        self.assertRejected("Bearer " + generate_token()[0], "unknown_token")

    def test_known_prefix_with_wrong_secret(self):
        forged = "mm_{}_{}".format(self.api_token.prefix, "A" * 43)
        self.assertRejected("Bearer " + forged, "unknown_token")

    def test_hashes_are_compared_in_constant_time(self):
        with patch("middleman.auth.hmac.compare_digest", return_value=True) as compare:
            self.call("Bearer " + self.token)
        compare.assert_called_once_with(hash_token(self.token), self.api_token.key_hash)

    def test_revoked_token(self):
        ApiToken.objects.filter(pk=self.api_token.pk).update(revoked_at=timezone.now())
        self.assertRejected("Bearer " + self.token, "revoked")

    def test_expired_token_including_the_exact_expiry_instant(self):
        now = timezone.now()
        ApiToken.objects.filter(pk=self.api_token.pk).update(expires_at=now)
        with patch("middleman.auth.timezone.now", return_value=now):
            self.assertRejected("Bearer " + self.token, "expired")

    def test_token_before_expiry(self):
        ApiToken.objects.filter(pk=self.api_token.pk).update(expires_at=timezone.now() + timedelta(minutes=1))
        self.assertEqual(self.call("Bearer " + self.token).status_code, 200)

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        self.assertRejected("Bearer " + self.token, "inactive_user")

    def test_non_ascii_and_oversized_headers_are_rejected_not_crashing(self):
        self.assertRejected("Bearer tökén", "non_ascii_header")
        self.assertRejected("Bearer " + "a" * 10000, "malformed_token")

    def test_token_in_query_string_is_ignored(self):
        response = APIClient().get(self.url, {"token": self.token, "access_token": self.token})
        self.assertEqual(response.status_code, 401)

    def test_failure_responses_do_not_reveal_the_reason(self):
        bodies = set()
        ApiToken.objects.filter(pk=self.api_token.pk).update(revoked_at=timezone.now())
        for header in ["Bearer " + self.token, "Bearer " + generate_token()[0], "Bearer junk"]:
            with self.assertLogs("middleman", "WARNING"):
                bodies.add(self.call(header).content)
        self.assertEqual(len(bodies), 1)

    def test_token_never_appears_in_logs(self):
        secret = self.token.split("_", 2)[2]
        forged = "mm_{}_{}".format(self.api_token.prefix, "B" * 43)
        with self.assertLogs("middleman", "DEBUG") as logs:
            self.call("Bearer " + forged)
            ApiToken.objects.filter(pk=self.api_token.pk).update(revoked_at=timezone.now())
            self.call("Bearer " + self.token)
            create_token(self.user, "another")
        joined = "\n".join(logs.output)
        self.assertNotIn(secret, joined)
        self.assertNotIn("B" * 43, joined)
        self.assertIn("prefix={}".format(self.api_token.prefix), joined)  # identifiable without the secret

    def test_last_used_is_recorded_but_throttled(self):
        self.call("Bearer " + self.token)
        first = ApiToken.objects.get(pk=self.api_token.pk).last_used_at
        self.assertIsNotNone(first)
        self.call("Bearer " + self.token)
        self.assertEqual(ApiToken.objects.get(pk=self.api_token.pk).last_used_at, first)
        later = first + LAST_USED_RESOLUTION
        with patch("middleman.auth.timezone.now", return_value=later):
            self.call("Bearer " + self.token)
        self.assertEqual(ApiToken.objects.get(pk=self.api_token.pk).last_used_at, later)

    def test_token_acts_with_its_users_permissions(self):
        nobody = make_user("nobody", role=None)
        _, token = create_token(nobody, "no-perms")
        response = self.call("Bearer " + token)
        self.assertEqual(response.status_code, 403)  # authenticated, not authorised

    def test_anonymous_endpoints_ignore_authorization_headers(self):
        # /insights/ and the proxy never authenticate, so a stray header is harmless.
        response = APIClient().get(reverse("insights"), HTTP_AUTHORIZATION="Bearer junk")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_reports_a_bad_token_instead_of_downgrading_to_anonymous(self):
        # The dashboard authenticates (to show operator sections), so a broken
        # token is an error the caller should see.
        with self.assertLogs("middleman", "WARNING"):
            response = APIClient().get(reverse("dashboard"), HTTP_AUTHORIZATION="Bearer junk")
        self.assertEqual(response.status_code, 401)
