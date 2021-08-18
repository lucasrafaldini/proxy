
from django.contrib import admin
from django.urls import re_path
from middleman.views import ProxyView

urlpatterns = [
    re_path(r'^(?P<path>\w+)/$', ProxyView.as_view(), name='proxy')
]
