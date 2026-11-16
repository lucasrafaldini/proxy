from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APIClient

from middleman.apps import ensure_default_roles
from middleman.auth import create_token


def make_user(username="operator", role="proxy-operator", **extra):
    """A user in one of the default roles (None for no role)."""
    ensure_default_roles(sender=None)
    user = get_user_model().objects.create_user(username=username, password="pw-" + username, **extra)
    if role:
        user.groups.add(Group.objects.get(name=role))
    return user


def logged_in_client(username="operator", role="proxy-operator", **extra):
    """APIClient with a session login (like the dashboard in a browser)."""
    client = APIClient()
    client.force_login(make_user(username, role, **extra))
    return client


def token_client(username="operator", role="proxy-operator", **extra):
    """APIClient sending a real API token; returns (client, token)."""
    user = make_user(username, role, **extra)
    _, token = create_token(user, "tests")
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
    return client, token
