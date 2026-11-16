"""Who may do what: a permission matrix over every management action."""

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman.auth import ROLE_PERMISSIONS, create_token
from middleman.models import AccessEntry, ApiToken, BlacklistRule, ClientPolicy
from middleman.tests.utils.auth import make_user

ANON, NO_ROLE, AUDITOR, OPERATOR, SUPERUSER = "anonymous", "no-role", "auditor", "operator", "superuser"


class PermissionMatrixTest(TestCase):
    """Each (identity, action) pair has exactly one expected status."""

    def setUp(self):
        self.entry = AccessEntry.objects.create(key="k1", ip="203.0.113.1", path="a/", already_requested=3)
        self.rule = BlacklistRule.objects.create(rule_type="path", value="admin/")
        self.users = {
            NO_ROLE: make_user("nobody", role=None),
            AUDITOR: make_user("auditor", role="proxy-auditor"),
            OPERATOR: make_user("operator", role="proxy-operator"),
            SUPERUSER: make_user("root", role=None, is_superuser=True, is_staff=True),
        }

    def client_for(self, identity, via="token"):
        client = APIClient()
        if identity == ANON:
            return client
        user = self.users[identity]
        if via == "token":
            _, token = create_token(user, "matrix")
            client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        else:
            client.force_login(user)
        return client

    def check(self, action, expected):
        for identity, status in expected.items():
            for via in ("token", "session"):
                if identity == ANON and via == "session":
                    continue
                with self.subTest(identity=identity, via=via):
                    response = action(self.client_for(identity, via))
                    self.assertEqual(response.status_code, status, getattr(response, "content", b"")[:200])

    def test_registry_read(self):
        self.check(lambda c: c.get("/registry/"),
                   {ANON: 401, NO_ROLE: 403, AUDITOR: 200, OPERATOR: 200, SUPERUSER: 200})

    def test_registry_reset(self):
        def reset(c):
            AccessEntry.objects.filter(pk=self.entry.pk).update(already_requested=3)
            return c.patch("/registry/", {"key": "k1", "action": "reset_already_requested"}, format="json")
        self.check(reset, {ANON: 401, NO_ROLE: 403, AUDITOR: 403, OPERATOR: 200, SUPERUSER: 200})

    def test_registry_change_limit(self):
        self.check(lambda c: c.patch("/registry/", {"key": "k1", "action": "update_max_requests", "max_requests": 7}, format="json"),
                   {ANON: 401, NO_ROLE: 403, AUDITOR: 403, OPERATOR: 200, SUPERUSER: 200})

    def test_client_policies_read(self):
        self.check(lambda c: c.get("/clients/"),
                   {ANON: 401, NO_ROLE: 403, AUDITOR: 200, OPERATOR: 200, SUPERUSER: 200})

    def test_client_policies_change(self):
        def change(c):
            ClientPolicy.objects.all().delete()
            return c.patch("/clients/", {"ip": "203.0.113.1", "hide_rate_limit_headers": True}, format="json")
        self.check(change, {ANON: 401, NO_ROLE: 403, AUDITOR: 403, OPERATOR: 201, SUPERUSER: 201})

    def test_dashboard_rule_actions(self):
        def create(c):
            BlacklistRule.objects.filter(value="other/").delete()
            return c.post("/", {"action": "create", "rule_type": "path", "value": "other/"})
        expected = {ANON: 401, NO_ROLE: 403, AUDITOR: 403, OPERATOR: 200, SUPERUSER: 200}
        self.check(create, expected)
        self.check(lambda c: c.post("/", {"action": "toggle", "rule_id": self.rule.pk}), expected)

        def delete(c):
            rule, _ = BlacklistRule.objects.get_or_create(rule_type="path", value="gone/")
            return c.post("/", {"action": "delete", "rule_id": rule.pk})
        self.check(delete, expected)

    def test_unknown_dashboard_action_is_denied(self):
        self.check(lambda c: c.post("/", {"action": "drop_tables"}),
                   {ANON: 401, NO_ROLE: 403, AUDITOR: 403, OPERATOR: 403, SUPERUSER: 403})

    def test_unsupported_methods_answer_405_to_authorised_users(self):
        for method in ("delete", "put", "post"):
            with self.subTest(method=method):
                response = getattr(self.client_for(OPERATOR), method)("/registry/", {}, format="json")
                self.assertEqual(response.status_code, 405)
        self.assertEqual(APIClient().delete("/registry/").status_code, 401)

    def test_denied_actions_change_nothing(self):
        for identity in (ANON, NO_ROLE, AUDITOR):
            client = self.client_for(identity)
            client.patch("/registry/", {"key": "k1", "action": "reset_already_requested"}, format="json")
            client.post("/", {"action": "delete", "rule_id": self.rule.pk})
            client.patch("/clients/", {"ip": "203.0.113.1", "hide_rate_limit_headers": True}, format="json")
        self.assertEqual(AccessEntry.objects.get(pk=self.entry.pk).already_requested, 3)
        self.assertTrue(BlacklistRule.objects.filter(pk=self.rule.pk).exists())
        self.assertFalse(ClientPolicy.objects.exists())

    def test_rejections_are_logged_with_requester_and_reason(self):
        with self.assertLogs("middleman.views", "WARNING") as logs:
            self.client_for(AUDITOR).patch("/registry/", {"key": "k1", "action": "reset_already_requested"}, format="json")
            APIClient().get("/registry/", REMOTE_ADDR="198.51.100.4")
        self.assertIn("[RegistryView] Rejected PATCH request | reason=access_denied requester=auditor@127.0.0.1", logs.output[0])
        self.assertIn("[RegistryView] Rejected GET request | reason=access_denied requester=anonymous@198.51.100.4", logs.output[1])


class SessionCsrfTest(TestCase):
    """Browser sessions are CSRF-protected; tokens are not cookies, so they need no CSRF token."""

    def test_session_post_without_csrf_token_is_rejected(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(make_user())
        response = client.post("/", {"action": "create", "rule_type": "path", "value": "x/"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("CSRF", response.json()["detail"])
        self.assertFalse(BlacklistRule.objects.exists())

    def test_session_post_with_csrf_token_is_accepted(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(make_user())
        page = client.get("/")
        csrf = page.cookies["csrftoken"].value
        response = client.post("/", {"action": "create", "rule_type": "path", "value": "x/"}, HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(response.status_code, 200)

    def test_token_post_needs_no_csrf_token(self):
        client = APIClient(enforce_csrf_checks=True)
        _, token = create_token(make_user(), "script")
        response = client.post("/", {"action": "create", "rule_type": "path", "value": "x/"},
                               HTTP_AUTHORIZATION="Bearer " + token)
        self.assertEqual(response.status_code, 200)


class DashboardVisibilityTest(TestCase):
    """Per-client data (IPs, usage) and rules are only rendered for users allowed to see them."""

    def setUp(self):
        AccessEntry.objects.create(key="k1", ip="203.0.113.77", path="secret-path/", already_requested=4, max_requests=5)
        BlacklistRule.objects.create(rule_type="ip", value="198.51.100.66")

    def page(self, client):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode(), response.context

    def test_anonymous_sees_aggregates_only(self):
        content, context = self.page(APIClient())
        self.assertNotIn("203.0.113.77", content)
        self.assertNotIn("4/5", content)
        self.assertNotIn("198.51.100.66", content)
        self.assertIn("Log in", content)
        # Not just hidden by the template: the data is never handed to it.
        self.assertEqual((context["recent_entries"], context["incident_feed"], context["rules"]), ([], [], []))

    def test_auditor_sees_clients_and_rules_but_no_edit_controls(self):
        client = APIClient()
        client.force_login(make_user("auditor", role="proxy-auditor"))
        content, _ = self.page(client)
        self.assertIn("203.0.113.77", content)
        self.assertIn("198.51.100.66", content)
        self.assertNotIn("Add rule", content)
        self.assertNotIn('value="toggle"', content)
        self.assertNotIn('value="delete"', content)

    def test_operator_sees_edit_controls(self):
        client = APIClient()
        client.force_login(make_user())
        content, _ = self.page(client)
        for marker in ["Add rule", 'value="toggle"', 'value="delete"']:
            self.assertIn(marker, content)

    def test_insights_stays_aggregate(self):
        data = APIClient().get(reverse("insights")).json()
        self.assertNotIn("203.0.113.77", str(data))


class DefaultRolesTest(TestCase):
    def test_roles_have_exactly_their_permissions(self):
        make_user()  # ensures roles
        for role, codenames in ROLE_PERMISSIONS.items():
            with self.subTest(role=role):
                perms = set(Group.objects.get(name=role).permissions.values_list("codename", flat=True))
                self.assertEqual(perms, set(codenames))

    def test_no_role_can_manage_tokens(self):
        for codenames in ROLE_PERMISSIONS.values():
            self.assertFalse([c for c in codenames if "apitoken" in c])

    def test_roles_are_idempotent_and_keep_manual_additions(self):
        from django.contrib.auth.models import Permission

        from middleman.apps import ensure_default_roles

        make_user()
        group = Group.objects.get(name="proxy-auditor")
        extra = Permission.objects.get(codename="change_accessentry")
        group.permissions.add(extra)
        ensure_default_roles(sender=None)
        ensure_default_roles(sender=None)
        self.assertEqual(Group.objects.filter(name="proxy-auditor").count(), 1)
        self.assertTrue(group.permissions.filter(pk=extra.pk).exists())


class AdminAuthorisationTest(TestCase):
    def test_non_staff_cannot_use_the_admin(self):
        client = APIClient()
        client.force_login(make_user())  # operator, not staff
        response = client.get("/admin/middleman/blacklistrule/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login/", response["Location"])

    def test_staff_auditor_can_view_but_not_change(self):
        client = APIClient()
        client.force_login(make_user("auditor", role="proxy-auditor", is_staff=True))
        self.assertEqual(client.get("/admin/middleman/blacklistrule/").status_code, 200)
        self.assertEqual(client.get("/admin/middleman/blacklistrule/add/").status_code, 403)

    def test_staff_operator_cannot_see_tokens(self):
        client = APIClient()
        client.force_login(make_user(is_staff=True))
        self.assertEqual(client.get("/admin/middleman/apitoken/").status_code, 403)

    def test_tokens_cannot_be_added_in_admin_even_by_superusers(self):
        client = APIClient()
        client.force_login(make_user("root", role=None, is_staff=True, is_superuser=True))
        self.assertEqual(client.get("/admin/middleman/apitoken/add/").status_code, 403)

    def test_superuser_can_revoke_tokens_from_admin(self):
        root = make_user("root", role=None, is_staff=True, is_superuser=True)
        api_token, token = create_token(make_user(), "to-revoke")
        client = APIClient()
        client.force_login(root)
        client.post("/admin/middleman/apitoken/", {"action": "revoke", "_selected_action": [api_token.pk]})
        self.assertIsNotNone(ApiToken.objects.get(pk=api_token.pk).revoked_at)
        with self.assertLogs("middleman", "WARNING"):
            response = APIClient().get("/registry/", HTTP_AUTHORIZATION="Bearer " + token)
        self.assertEqual(response.status_code, 401)

    def test_admin_policy_change_is_manual_and_attributed(self):
        root = make_user("root", role=None, is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_login(root)
        client.post("/admin/middleman/clientpolicy/add/", {"ip": "::ffff:203.0.113.9", "hide_rate_limit_headers": "on", "reason": "abuse report"})
        policy = ClientPolicy.objects.get()
        self.assertEqual((policy.ip, policy.source, policy.updated_by), ("203.0.113.9", "manual", root))
