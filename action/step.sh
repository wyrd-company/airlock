#!/bin/sh
# The Airlock action's audit step: run the engine on the pinned Node, with an
# allowlisted environment and nothing else.
#
# action.yml runs this from a `shell: sh` step whose own env sets every value
# below from the github and runner contexts. sh here is dash, which imports
# no functions from the environment and reads $ENV only when interactive, so
# no variable the caller set runs code before this script. This script then
# starts Node through /usr/bin/env -i with only the names listed here. The
# caller's NODE_*, *_PROXY, SSL_CERT_*, LD_* and TLS variables never reach it.
# The three credentials are written to Node's standard input, so they appear
# in no process's arguments or environment.
#
# See docs/action.md, "What the action proves".
set -eu

node="$AIRLOCK_NODE_DIR/node"
if [ ! -x "$node" ]; then
  echo "::error::The action's pinned Node is not at $AIRLOCK_NODE_DIR, where setup-node installs Node $AIRLOCK_NODE_VERSION."
  exit 1
fi
version=$(/usr/bin/env -i "$node" --version)
if [ "$version" != "v$AIRLOCK_NODE_VERSION" ]; then
  echo "::error::The Node at $AIRLOCK_NODE_DIR is $version, not the pinned v$AIRLOCK_NODE_VERSION."
  exit 1
fi

# NUL-separated: the token input, AIRLOCK_TOKEN, and the run's own token.
printf '%s\0%s\0%s\0' "${INPUT_TOKEN:-}" "${AIRLOCK_TOKEN:-}" "${AIRLOCK_RUN_TOKEN:-}" |
  exec /usr/bin/env -i \
    PATH="$AIRLOCK_NODE_DIR:/usr/bin:/bin" \
    HOME="${HOME:-}" \
    RUNNER_TEMP="$RUNNER_TEMP" \
    GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" \
    GITHUB_OUTPUT="${GITHUB_OUTPUT:-}" \
    GITHUB_ENV="${GITHUB_ENV:-}" \
    GITHUB_ACTION="${GITHUB_ACTION:-}" \
    GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
    GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
    GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
    GITHUB_REPOSITORY_ID="${GITHUB_REPOSITORY_ID:-}" \
    GITHUB_WORKFLOW_REF="${GITHUB_WORKFLOW_REF:-}" \
    GITHUB_WORKFLOW_SHA="${GITHUB_WORKFLOW_SHA:-}" \
    GITHUB_JOB="${GITHUB_JOB:-}" \
    GITHUB_API_URL="${GITHUB_API_URL:-}" \
    INPUT_MODE="${INPUT_MODE:-}" \
    INPUT_REPOSITORY="${INPUT_REPOSITORY:-}" \
    INPUT_POLICY="${INPUT_POLICY:-}" \
    INPUT_REF="${INPUT_REF:-}" \
    INPUT_FORMAT="${INPUT_FORMAT:-}" \
    INPUT_FAIL_ON_INCOMPLETE="${INPUT_FAIL_ON_INCOMPLETE:-}" \
    AIRLOCK_JOB_CHECK_RUN_ID="${AIRLOCK_JOB_CHECK_RUN_ID:-}" \
    AIRLOCK_CREDENTIALS_ON_STDIN=1 \
    "$node" "$AIRLOCK_ACTION_PATH/dist/index.mjs"
