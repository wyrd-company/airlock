#!/bin/sh
# Rebuild the action's dist/ and fail when it differs from the committed
# copy, so the bundle and the module the action runs are the ones the source
# builds. Run it on a clean checkout: it compares with what Git holds.
set -eu

cd "$(dirname "$0")/.."

scripts/build-action.sh
if [ -n "$(git status --porcelain --untracked-files=all -- dist)" ]; then
  echo "dist/ differs from the source. Run \`task action:build\` and commit dist/:" >&2
  git status --short --untracked-files=all -- dist >&2
  git --no-pager diff --stat -- dist >&2
  exit 1
fi
echo "dist/ matches the source."
