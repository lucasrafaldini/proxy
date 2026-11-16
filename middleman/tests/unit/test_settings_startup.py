import os
import subprocess
import sys

from django.conf import settings
from django.test import SimpleTestCase

PROJECT_ROOT = settings.BASE_DIR


def start_django(**env_overrides):
    """Import settings and run app.ready() in a fresh interpreter."""
    env = dict(os.environ, DJANGO_SETTINGS_MODULE="proxy.test_settings", **env_overrides)
    return subprocess.run(
        [sys.executable, "-c", "import django; django.setup(); print('started')"],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True,
    )


class StartupConfigurationTest(SimpleTestCase):
    """Security/logging misconfiguration stops the app instead of being ignored."""

    def test_valid_configuration_starts(self):
        result = start_django(TRUSTED_PROXIES="10.0.0.1, 172.16.0.0/12", LOGLEVEL="info")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_trusted_proxies_stop_startup(self):
        result = start_django(TRUSTED_PROXIES="10.0.0.1,10.0.0.0/33")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TRUSTED_PROXIES contains '10.0.0.0/33'", result.stderr)

    def test_invalid_loglevel_stops_startup(self):
        result = start_django(LOGLEVEL="verbose")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LOGLEVEL='VERBOSE' is not valid", result.stderr)


def run_python(code, settings_module="proxy.settings", argv=None, **env_overrides):
    """Run code in a fresh interpreter with a clean DEBUG/ALLOWED_HOSTS environment."""
    env = {k: v for k, v in os.environ.items() if k not in ("DEBUG", "ALLOWED_HOSTS", "LOGLEVEL")}
    env.update(DJANGO_SETTINGS_MODULE=settings_module, **env_overrides)
    command = argv or [sys.executable, "-c", code]
    return subprocess.run(command, cwd=PROJECT_ROOT, env=env, capture_output=True, text=True)


SHOW_DEBUG = "import django; django.setup(); from django.conf import settings; print('DEBUG=%s' % settings.DEBUG)"


class DebugFlagTest(SimpleTestCase):
    """DEBUG is off unless explicitly requested at startup."""

    def debug_with(self, **env):
        result = run_python(SHOW_DEBUG, **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().splitlines()[-1], result.stderr

    def test_off_by_default(self):
        self.assertEqual(self.debug_with()[0], "DEBUG=False")

    def test_explicit_true_values(self):
        for value in ["true", "TRUE", "1", "yes", "on", " True "]:
            with self.subTest(value=value):
                shown, stderr = self.debug_with(DEBUG=value)
                self.assertEqual(shown, "DEBUG=True")
                self.assertIn("DEBUG mode is ON", stderr)  # loud startup warning

    def test_explicit_false_values(self):
        for value in ["false", "0", "no", "off", ""]:
            with self.subTest(value=value):
                self.assertEqual(self.debug_with(DEBUG=value)[0], "DEBUG=False")

    def test_unrecognised_values_stop_startup(self):
        # The old code treated any non-empty string (even "False") as on.
        for value in ["maybe", "enabled", "2", "False!"]:
            with self.subTest(value=value):
                result = run_python(SHOW_DEBUG, DEBUG=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is not a boolean", result.stderr)

    def test_loglevel_debug_no_longer_enables_debug(self):
        self.assertEqual(self.debug_with(LOGLEVEL="DEBUG")[0], "DEBUG=False")

    def test_manage_py_debug_flag(self):
        code = "from django.conf import settings; print('DEBUG=%s' % settings.DEBUG)"
        with_flag = run_python(None, argv=[sys.executable, "manage.py", "shell", "--debug", "-c", code])
        without = run_python(None, argv=[sys.executable, "manage.py", "shell", "-c", code])
        self.assertEqual(with_flag.returncode, 0, with_flag.stderr)
        self.assertEqual(with_flag.stdout.strip(), "DEBUG=True")  # --debug was consumed, not passed on
        self.assertEqual(without.stdout.strip(), "DEBUG=False")


SHOW_HOSTS = ("import django; django.setup(); from django.conf import settings; "
              "print(settings.ALLOWED_HOSTS, settings.ALLOWED_HOSTS_BASELINE)")


class AllowedHostsStartupTest(SimpleTestCase):
    def test_default_baseline(self):
        result = run_python(SHOW_HOSTS)
        self.assertEqual(result.stdout.strip(), "['*'] ['localhost', '127.0.0.1', '[::1]']")

    def test_environment_baseline_is_parsed(self):
        result = run_python(SHOW_HOSTS, ALLOWED_HOSTS="Proxy.Example.com, .internal.example, 10.0.0.5")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "['*'] ['proxy.example.com', '.internal.example', '10.0.0.5']")

    def test_invalid_environment_values_stop_startup(self):
        # '["*"]' is the value that used to crash Django with a confusing error.
        for value in ['["*"]', "*", "example.com:8000", ".com", "http://example.com", "a.com,,*"]:
            with self.subTest(value=value):
                result = run_python(SHOW_HOSTS, ALLOWED_HOSTS=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ImproperlyConfigured: ALLOWED_HOSTS:", result.stderr)

    def test_startup_fails_if_the_host_gate_is_not_first(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "gate_moved_settings.py"), "w") as fh:
                fh.write(
                    "from proxy.settings import *  # noqa\n"
                    "MIDDLEWARE = [m for m in MIDDLEWARE if m != 'middleman.hosts.AllowedHostsMiddleware']\n"
                    "MIDDLEWARE.append('middleman.hosts.AllowedHostsMiddleware')\n"
                )
            result = run_python("import django; django.setup()", settings_module="gate_moved_settings",
                                PYTHONPATH=tmp + os.pathsep + str(PROJECT_ROOT))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be the first entry of MIDDLEWARE", result.stderr)
