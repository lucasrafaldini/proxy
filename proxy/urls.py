from django.contrib import admin
from django.urls import path, re_path

from middleman.views import DashboardView, InsightsView, ProxyView, RegistryView

urlpatterns = [
    path("", DashboardView.as_view(), name="dashboard"),
    path("insights/", InsightsView.as_view(), name="insights"),
    re_path(r"^proxy/(?P<path>\w+)/$", ProxyView.as_view(), name="proxy"),
    path("registry/", RegistryView.as_view(), name="registry"),
]
