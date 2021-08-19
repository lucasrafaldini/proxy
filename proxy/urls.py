from django.contrib import admin
from django.urls import path, re_path

from middleman.views import ProxyView, RegistryView

urlpatterns = [
    re_path(r"^proxy/(?P<path>\w+)/$", ProxyView.as_view(), name="proxy"),
    path("registry/", RegistryView.as_view(), name="registry"),
]
