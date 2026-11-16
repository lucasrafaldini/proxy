from .settings import *  # noqa: F401,F403

# Use sqlite for tests so unit/CI runs do not require an external Postgres service.
# In memory: commands run with these settings (make migrations-check...) never
# leave a database file behind (pytest's test database was in memory already).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# Django's test client sends Host: testserver.
ALLOWED_HOSTS_BASELINE = [*ALLOWED_HOSTS_BASELINE, "testserver"]  # noqa: F405
