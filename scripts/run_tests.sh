#!/usr/bin/env bash
#
# Single entry point for the test suite.
#
# 1. Checks that this machine can run the tests (Python version, virtualenv,
#    installed dependencies) and fixes what it can: it creates/repairs a
#    project virtualenv and (re)installs test_requirements.txt whenever the
#    requirement files change or a dependency is missing.
# 2. Runs pytest in an isolated environment, so variables exported in your
#    shell (BLACKLISTED_IPS, ALLOWED_HOSTS, DJANGO_SETTINGS_MODULE, ...) can't
#    change the results.
#
# Usage:
#   scripts/run_tests.sh                    # prepare env if needed + full suite
#   scripts/run_tests.sh -k cidr --no-cov   # extra args are passed to pytest
#   scripts/run_tests.sh --setup-only       # only check/prepare the environment
#   scripts/run_tests.sh --recreate         # rebuild the virtualenv from scratch
#
# Environment overrides:
#   PYTHON=/path/to/python3   interpreter used to create the virtualenv
#   VENV_DIR=/path/to/venv    virtualenv location (default: <project>/.venv)

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
case "$SCRIPT_PATH" in */*) SCRIPT_DIR="${SCRIPT_PATH%/*}" ;; *) SCRIPT_DIR="." ;; esac
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="${VENV_DIR:-$PROJECT_ROOT/.venv}"
VENV_PY="$VENV_DIR/bin/python"
STAMP_FILE="$VENV_DIR/.test-requirements.sha256"
REQUIREMENT_FILES=("requirements.txt" "test_requirements.txt")
TEST_SETTINGS="proxy.test_settings"

# Django 4.2 (pinned in requirements.txt) supports Python 3.8 - 3.12.
MIN_PY_MAJOR=3; MIN_PY_MINOR=8
MAX_TESTED_PY_MINOR=12

# Modules the suite needs; a failed import means the env must be (re)installed.
REQUIRED_MODULES="django, rest_framework, axes, requests, re2, pytest, pytest_django, pytest_cov, factory, faker"

# Variables read by proxy/settings.py at import time that would leak into the tests.
ISOLATED_VARS=(ALLOWED_HOSTS BLACKLISTED_IPS BLACKLISTED_PATHS TRUSTED_PROXIES BASE_TARGET_URL DEBUG LOGLEVEL)

if [ -t 2 ]; then
    C_INFO=$'\033[1;34m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OFF=$'\033[0m'
else
    C_INFO=""; C_WARN=""; C_ERR=""; C_OFF=""
fi
log()  { printf '%s[run_tests]%s %s\n' "$C_INFO" "$C_OFF" "$*" >&2; }
warn() { printf '%s[run_tests] WARNING:%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '%s[run_tests] ERROR:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

usage() { sed -n '3,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

RECREATE=0
SETUP_ONLY=0
PYTEST_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --recreate)   RECREATE=1 ;;
        --setup-only) SETUP_ONLY=1 ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; PYTEST_ARGS+=("$@"); break ;;
        *)            PYTEST_ARGS+=("$1") ;;
    esac
    shift
done

cd "$PROJECT_ROOT"

# --- 1. Python interpreter ----------------------------------------------------

python_version_ok() {
    "$1" -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($MIN_PY_MAJOR, $MIN_PY_MINOR) else 1)" 2>/dev/null
}

find_python() {
    if [ -n "${PYTHON:-}" ]; then
        command -v "$PYTHON" >/dev/null 2>&1 || die "PYTHON='$PYTHON' was not found."
        python_version_ok "$PYTHON" || die "PYTHON='$PYTHON' is older than $MIN_PY_MAJOR.$MIN_PY_MINOR."
        echo "$PYTHON"; return
    fi
    # Prefer versions Django 4.2 supports, newest first.
    for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && python_version_ok "$candidate"; then
            echo "$candidate"; return
        fi
    done
    die "Python >= $MIN_PY_MAJOR.$MIN_PY_MINOR is required but was not found. Install it or set PYTHON=/path/to/python3."
}

# --- 2. Virtualenv --------------------------------------------------------------

venv_is_healthy() {
    [ -x "$VENV_PY" ] && "$VENV_PY" -c "import sys, pip" >/dev/null 2>&1
}

# Must be called in the main shell (not via $(...)) so that `die` aborts the script.
resolve_base_python() {
    BASE_PYTHON="$(find_python)" || exit 1
}

create_venv() {
    local base_python="$1"
    [ -n "$base_python" ] || die "No Python interpreter to create the virtualenv with."
    log "Creating virtualenv at $VENV_DIR using $("$base_python" --version 2>&1)"
    rm -rf "$VENV_DIR"
    if "$base_python" -m venv "$VENV_DIR" >/dev/null 2>&1; then
        return
    fi
    rm -rf "$VENV_DIR"
    # Debian/Ubuntu ship python3 without ensurepip unless python3-venv is installed.
    if "$base_python" -m virtualenv --version >/dev/null 2>&1; then
        "$base_python" -m virtualenv -q "$VENV_DIR" && return
    elif command -v virtualenv >/dev/null 2>&1; then
        virtualenv -q -p "$base_python" "$VENV_DIR" && return
    fi
    die "Could not create a virtualenv with '$base_python'. On Debian/Ubuntu install it with:
    sudo apt-get install python3-venv
or install virtualenv (pip install --user virtualenv) and run this script again."
}

ensure_venv() {
    # Resolve the interpreter *before* touching an existing virtualenv, so a bad
    # PYTHON value can never leave you without a working environment.
    if [ "$RECREATE" -eq 1 ]; then
        resolve_base_python
        log "--recreate given: rebuilding virtualenv."
        create_venv "$BASE_PYTHON"
    elif ! venv_is_healthy; then
        resolve_base_python
        if [ -e "$VENV_DIR" ]; then
            warn "Virtualenv at $VENV_DIR is broken or incomplete; recreating it."
        fi
        create_venv "$BASE_PYTHON"
    fi
    venv_is_healthy || die "Virtualenv at $VENV_DIR is not usable after creation."
    python_version_ok "$VENV_PY" \
        || die "Virtualenv Python is older than $MIN_PY_MAJOR.$MIN_PY_MINOR. Run with --recreate (and PYTHON=...)."
    if ! "$VENV_PY" -c "import sys; sys.exit(0 if sys.version_info[:2] <= (3, $MAX_TESTED_PY_MINOR) else 1)"; then
        warn "$("$VENV_PY" --version 2>&1) is newer than what Django 4.2 supports (<= 3.$MAX_TESTED_PY_MINOR)." \
             "If installs or tests fail, rerun with PYTHON=python3.12 --recreate."
    fi
}

# --- 3. Dependencies --------------------------------------------------------------

requirements_fingerprint() {
    # Hash of the requirement files + interpreter version, computed with Python
    # so the script does not depend on sha256sum/shasum being installed.
    "$VENV_PY" - "${REQUIREMENT_FILES[@]}" <<'PY'
import hashlib, sys
digest = hashlib.sha256(sys.version.encode())
for name in sys.argv[1:]:
    with open(name, "rb") as fh:
        digest.update(fh.read())
print(digest.hexdigest())
PY
}

dependencies_importable() {
    "$VENV_PY" -c "import $REQUIRED_MODULES" >/dev/null 2>&1
}

ensure_dependencies() {
    local file
    for file in "${REQUIREMENT_FILES[@]}"; do
        [ -f "$file" ] || die "Missing $PROJECT_ROOT/$file"
    done

    local expected current=""
    expected="$(requirements_fingerprint)"
    [ -f "$STAMP_FILE" ] && current="$(cat "$STAMP_FILE")"

    if [ "$expected" = "$current" ] && dependencies_importable; then
        log "Dependencies are up to date."
        return
    fi

    if [ -n "$current" ] && [ "$expected" != "$current" ]; then
        log "Requirement files changed since the last install; updating dependencies."
    else
        log "Installing test dependencies (test_requirements.txt)."
    fi
    "$VENV_PY" -m pip install --disable-pip-version-check --quiet -r test_requirements.txt \
        || die "pip install failed. Check your network/proxy settings (or PIP_INDEX_URL) and try again."

    dependencies_importable \
        || die "Dependencies were installed but these imports still fail: $REQUIRED_MODULES"
    echo "$expected" > "$STAMP_FILE"
}

ensure_venv
ensure_dependencies

if [ "$SETUP_ONLY" -eq 1 ]; then
    log "Environment is ready ($("$VENV_PY" --version 2>&1) at $VENV_DIR)."
    exit 0
fi

# --- 4. Run the suite in an isolated environment ---------------------------------

for var in "${ISOLATED_VARS[@]}"; do
    if [ -n "${!var+x}" ]; then
        warn "Ignoring $var from your shell so it can't affect the tests."
        unset "$var"
    fi
done
if [ -n "${DJANGO_SETTINGS_MODULE:-}" ] && [ "$DJANGO_SETTINGS_MODULE" != "$TEST_SETTINGS" ]; then
    warn "Overriding DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE with $TEST_SETTINGS (sqlite test database)."
fi
export DJANGO_SETTINGS_MODULE="$TEST_SETTINGS"
export PYTHONDONTWRITEBYTECODE=1

log "Running: pytest --ds=$TEST_SETTINGS ${PYTEST_ARGS[*]-}"
exec "$VENV_PY" -m pytest --ds="$TEST_SETTINGS" ${PYTEST_ARGS[@]+"${PYTEST_ARGS[@]}"}
