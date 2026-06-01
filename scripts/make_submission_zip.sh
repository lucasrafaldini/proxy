#!/usr/bin/env bash
set -euo pipefail

# Creates a zip of the repository for submission while excluding the local devto post
# Usage: ./scripts/make_submission_zip.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/../proxy-finishup-submission.zip"

cd "$REPO_ROOT"
rm -f "$OUT"

# Include everything except the devto submission draft and the .git folder
zip -r "$OUT" . -x "./devto-submission.md" "./.git/*" "*/__pycache__/*" "*.pyc" "*.sqlite3"

echo "Created $OUT"
