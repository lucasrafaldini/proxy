#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proxy.settings")
    # Debug mode only when explicitly requested at startup, e.g.
    # `python manage.py runserver --debug` (or DEBUG=true in the environment).
    if "--debug" in sys.argv[1:]:
        sys.argv = [arg for arg in sys.argv if arg != "--debug"]
        os.environ["DEBUG"] = "true"
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment? (make targets use .venv "
            "automatically; or run .venv/bin/python manage.py ...)"
        ) from exc
    try:
        execute_from_command_line(sys.argv)
    except Exception as exc:
        # Database and configuration failures get a semantic explanation (what
        # is wrong, which settings were used, what to do) instead of a bare
        # stack trace. --traceback still shows the full trace.
        from middleman.diagnostics import handle_command_failure

        if handle_command_failure(exc, sys.argv):
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
