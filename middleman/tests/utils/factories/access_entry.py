import random
from typing import List

from django.utils import timezone

import factory

from middleman.models import AccessEntry


class AccessEntryModelFactory(factory.Factory):
    class Meta:
        model = AccessEntry


    key= hash("{}@{}".format("111.111.111.111", "/index/") % 10**8)
    ip = "111.111.111.111"
    path = "/index/"
    request = ""
    already_requested = 52
    max_requests = 100
    created_at = timezone.now()
