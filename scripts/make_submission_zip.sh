#!/usr/bin/env bash
set -euo pipefail

# Creates a zip of the repository for submission, without local/generated files
# (.git, virtualenv, caches, databases, coverage reports).
# Usage: ./scripts/make_submission_zip.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/../proxy-finishup-submission.zip"

cd "$REPO_ROOT"
rm -f "$OUT"

zip -r "$OUT" . -x "./.git/*" "./.venv/*" "./.pytest_cache/*" "*/__pycache__/*" "*.pyc" \
    "*.sqlite3" "./.coverage" "./coverage.xml" "./.env" "./htmlcov/*" "./.benchmarks/*"

echo "Created $OUT"
