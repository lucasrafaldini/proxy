#!/usr/bin/env bash
#
# Verify that make targets leave nothing behind (make check-hygiene).
#
# Runs each target twice (ROUNDS) and fails if any run:
#   * creates files or directories in the project tree other than the
#     target's declared output (htmlcov/ for coverage-html, .benchmarks/ for
#     bench-save, pruned to BENCH_KEEP);
#   * leaves anything in its temporary directory (every run gets a private
#     TMPDIR, so anything left there was left by us);
#   * leaves processes running (runserver, the upstream stub, live servers);
#   * grows ~/.cache (pip, black, pip-audit...);
#   * keeps growing the virtualenv (it may change on the first round, not after).
#
# Usage: scripts/check_hygiene.sh [target ...]   (default: a representative set)

set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
case "$SCRIPT_PATH" in */*) SCRIPT_DIR="${SCRIPT_PATH%/*}" ;; *) SCRIPT_DIR="." ;; esac
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

VENV="${VENV:-.venv}"
ROUNDS="${ROUNDS:-2}"
BENCH_KEEP_CHECK=2
DEFAULT_TARGETS=(
    venv
    migrations-check
    test-quick
    test
    test-failed
    test-functional
    coverage-html
    # Specs are split on spaces: ARGS values must be single words (-kEXPR).
    "bench-save ARGS=-kvalidate BENCH_KEEP=$BENCH_KEEP_CHECK"
    "bench-save ARGS=-kvalidate BENCH_KEEP=$BENCH_KEEP_CHECK"
    "bench-save ARGS=-kvalidate BENCH_KEEP=$BENCH_KEEP_CHECK"
    "bench-throughput ARGS=-ksingle-threaded"
    doctor
    check-rules
)
if [ $# -gt 0 ]; then TARGETS=("$@"); else TARGETS=("${DEFAULT_TARGETS[@]}"); fi

FAILURES=0
fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

tree_snapshot() {
    find . -path ./.git -prune -o -path "./$VENV" -prune -o -print | LC_ALL=C sort
}
dir_size_kb() { [ -d "$1" ] && du -sk "$1" 2>/dev/null | cut -f1 || echo 0; }
our_processes() {
    # Anything started from this project that outlives a make run.
    pgrep -u "$(id -u)" -af "$PROJECT_ROOT|_upstream_stub.py|manage.py runserver" 2>/dev/null \
        | grep -v -e "check_hygiene.sh" -e "pgrep" || true
}
allowed_outputs() {
    case "$1" in
        coverage-html*) echo "^\./htmlcov(/|$)" ;;
        bench-save*)    echo "^\./\.benchmarks(/|$)" ;;
        ci*)            echo "^\./coverage\.xml$" ;;
        *)              echo "^$" ;;
    esac
}

cache_before="$(dir_size_kb "$HOME/.cache")"
processes_before="$(our_processes)"
venv_after_round=()

for round in $(seq 1 "$ROUNDS"); do
    echo "== Round $round/$ROUNDS"
    for spec in "${TARGETS[@]}"; do
        before="$(tree_snapshot)"
        run_tmp="$(mktemp -d)"
        # shellcheck disable=SC2086
        read -r -a words <<< "$spec"
        printf '  make %-60s' "$spec"
        TMPDIR="$run_tmp" make -s "${words[@]}" > "$run_tmp.log" 2>&1
        status=$?
        # A failing command is fine here (e.g. doctor without a database);
        # only what it leaves behind is judged. Usage errors are not.
        if [ "$status" -ne 0 ] && grep -q "No rule to make target" "$run_tmp.log"; then
            fail "not a make target: $spec"
        fi
        echo " (exit $status)"
        after="$(tree_snapshot)"
        new="$(LC_ALL=C comm -13 <(echo "$before") <(echo "$after") | grep -Ev "$(allowed_outputs "$spec")" || true)"
        [ -z "$new" ] || fail "left files in the project tree:"$'\n'"$(echo "$new" | head -10 | sed 's/^/        /')"
        leftovers="$(find "$run_tmp" -mindepth 1 2>/dev/null | head -5)"
        [ -z "$leftovers" ] || fail "left temporary files:"$'\n'"$(echo "$leftovers" | sed 's/^/        /')"
        rm -rf "$run_tmp" "$run_tmp.log"
        sleep 0.5
        procs="$(LC_ALL=C comm -13 <(echo "$processes_before" | LC_ALL=C sort) <(our_processes | LC_ALL=C sort))"
        [ -z "$procs" ] || fail "left processes running:"$'\n'"$(echo "$procs" | cut -c1-150 | sed 's/^/        /')"
        case "$spec" in
            bench-save*)
                saved="$(find .benchmarks -name '*.json' 2>/dev/null | wc -l)"
                # At least one (the run really saved), at most BENCH_KEEP (pruned).
                [ "$saved" -ge 1 ] && [ "$saved" -le "$BENCH_KEEP_CHECK" ] \
                    || fail "$saved saved benchmark runs, expected 1 to $BENCH_KEEP_CHECK"
                ;;
        esac
    done
    venv_after_round+=("$(dir_size_kb "$VENV")")
    echo "   virtualenv after round $round: ${venv_after_round[-1]} KB"
done

cache_after="$(dir_size_kb "$HOME/.cache")"
[ "$cache_after" -le "$cache_before" ] || fail "~/.cache grew from ${cache_before} KB to ${cache_after} KB"
if [ "${#venv_after_round[@]}" -ge 2 ]; then
    growth=$(( venv_after_round[-1] - venv_after_round[0] ))
    # pytest's cache and coverage's data file are rewritten, not appended: allow a little jitter.
    [ "$growth" -le 512 ] || fail "the virtualenv keeps growing: +${growth} KB between rounds"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "Hygiene OK: ${#TARGETS[@]} target(s) x $ROUNDS round(s) left no files, caches, temp files or processes behind."
    exit 0
fi
echo "Hygiene FAILED: $FAILURES problem(s)."
exit 1
