import random
from typing import List

import factory
from django.utils import timezone

from middleman.models import AccessEntry


def random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


class AccessEntryModelFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = AccessEntry

    _ip_and_path = [random_ip(), "index/"]
    key = "{}".format(
        hash("{}@{}".format("{}".format(_ip_and_path[0]), _ip_and_path[1])) % 10 ** 20
    )
    ip = _ip_and_path[0]
    path = _ip_and_path[1]
    already_requested = 52
    max_requests = 100
    created_at = timezone.now()
