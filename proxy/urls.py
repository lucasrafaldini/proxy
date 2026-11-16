from django.contrib import admin
from django.urls import path, re_path

from middleman.views import (AllowedHostsView, ClientPolicyView, DashboardView,
                             InsightsView, ProxyView, RegistryView)

urlpatterns = [
    path("", DashboardView.as_view(), name="dashboard"),
    path("insights/", InsightsView.as_view(), name="insights"),
    re_path(r"^proxy/(?P<path>\w+)/$", ProxyView.as_view(), name="proxy"),
    path("registry/", RegistryView.as_view(), name="registry"),
    path("clients/", ClientPolicyView.as_view(), name="clients"),
    path("settings/allowed-hosts/", AllowedHostsView.as_view(), name="allowed-hosts"),
    # Staff-only management of rules and entries (python manage.py createsuperuser).
    path("admin/", admin.site.urls),
]
