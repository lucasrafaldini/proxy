import os
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from middleman.exceptions import InvalidRuleError
from middleman.hosts import parse_baseline
from middleman.version import __version__ as PROXY_VERSION


def _env_flag(name):
    """Strict boolean environment flag: unset/empty is False; anything unrecognised stops startup."""
    raw = os.getenv(name, "").strip().lower()
    if raw in ("", "0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    raise ImproperlyConfigured(
        "{}={!r} is not a boolean; use true/false (or 1/0, yes/no, on/off).".format(name, os.getenv(name))
    )

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv(
    "SECRET_KEY", "django-insecure-development-test-key"
)

# SECURITY WARNING: don't run with debug turned on in production!
# Off unless explicitly requested at startup: DEBUG=true in the environment,
# or `python manage.py <command> --debug`. (It used to be always on.)
DEBUG = _env_flag("DEBUG")

LOGLEVEL = os.environ.get("LOGLEVEL", "warning").upper()
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
if LOGLEVEL not in _LOG_LEVELS:
    raise ImproperlyConfigured(
        "LOGLEVEL={!r} is not valid; use one of {}.".format(LOGLEVEL, ", ".join(_LOG_LEVELS))
    )

# Every line says which proxy version produced it (see CHANGELOG.md).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s %(levelname)-8s %(name)s [proxy v{}] %(message)s".format(
                PROXY_VERSION
            ),
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "middleman": {"level": LOGLEVEL},
        # Django's request/server warnings (4xx/5xx) in the same format.
        "django": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}

# Host header validation is done by middleman.hosts.AllowedHostsMiddleware
# (first middleware; startup fails otherwise) against:
#  * this baseline, from ALLOWED_HOSTS (comma-separated; default localhost,
#    127.0.0.1, [::1]); it cannot be changed at runtime, so admins can never
#    lock themselves out;
#  * hosts added at runtime through /settings/allowed-hosts/ (dedicated
#    permissions, staff only).
try:
    ALLOWED_HOSTS_BASELINE = parse_baseline(os.getenv("ALLOWED_HOSTS"))
except InvalidRuleError as exc:
    raise ImproperlyConfigured("ALLOWED_HOSTS: {}".format(exc))
ALLOWED_HOSTS = ["*"]  # delegated to AllowedHostsMiddleware; do not change

BASE_TARGET_URL = os.environ.get("BASE_TARGET_URL", "http://localhost:8000/")

BLACKLISTED_IPS = [
    item.strip()
    for item in os.getenv("BLACKLISTED_IPS", "").split(",")
    if item.strip()
]

BLACKLISTED_PATHS = [
    item.strip()
    for item in os.getenv("BLACKLISTED_PATHS", "").split(",")
    if item.strip()
]

# Reverse proxies / load balancers allowed to set X-Forwarded-For (IPs or
# CIDRs, comma-separated). Empty = trust nobody: the TCP peer is the client.
# See middleman/client_ip.py. Invalid entries stop the app at startup.
TRUSTED_PROXIES = [
    item.strip()
    for item in os.getenv("TRUSTED_PROXIES", "").split(",")
    if item.strip()
]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "axes",
    "middleman",
]

MIDDLEWARE = [
    # Must stay first: the only Host header check (see ALLOWED_HOSTS above).
    "middleman.hosts.AllowedHostsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Must stay last (django-axes): answers locked-out login attempts.
    "axes.middleware.AxesMiddleware",
]

# Brute-force protection for password logins (/admin/login/), by django-axes.
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",  # must be first
    "django.contrib.auth.backends.ModelBackend",
]
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
# Lock the client IP: rotating usernames does not help. Not the username
# alone, which would let anyone lock an admin out (denial of service).
AXES_LOCKOUT_PARAMETERS = ["ip_address"]
# Same spoofing-resistant client IP as the rest of the app (TRUSTED_PROXIES);
# never trust X-Forwarded-For by default, or rotating it would evade lockouts.
AXES_CLIENT_IP_CALLABLE = "middleman.client_ip.axes_client_ip"
# A successful login must not wipe the IP's failures: an attacker with any
# valid account could otherwise reset the counter between guesses.
AXES_RESET_ON_SUCCESS = False
# Store only usernames of real accounts (a password typed into the username
# field must not end up in the database or the logs). Lockouts are per IP.
AXES_USERNAME_CALLABLE = "middleman.apps.axes_username"
AXES_HTTP_RESPONSE_CODE = 429

ROOT_URLCONF = "proxy.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "proxy.wsgi.application"


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.getenv("POSTGRES_HOST", "localhost"),
        "NAME": os.getenv("POSTGRES_DB", "db-test"),
        "USER": os.getenv("POSTGRES_USER", "proxy-test"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
        "PORT": 5432,
    }
}


REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    # API tokens for scripts (Authorization: Bearer mm_...), sessions for the
    # dashboard (log in at /admin/). Basic auth is deliberately not enabled.
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "middleman.auth.ApiTokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    # Secure by default: public views opt out explicitly.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

# Automatic hiding of rate limit headers for abusive clients; see
# middleman/abuse.py for the signals, weights and defaults.
ABUSE_DETECTION = {}

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = "/static/"

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
