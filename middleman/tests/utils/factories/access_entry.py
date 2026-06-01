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

    ip = factory.LazyFunction(random_ip)
    path = "index/"
    key = factory.Sequence(lambda n: "{}".format(10 ** 19 + n))
    already_requested = 52
    max_requests = 100
    created_at = timezone.now()
