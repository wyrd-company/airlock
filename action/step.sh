#!/bin/sh
# The Airlock action's audit step: run the engine on the pinned Node, with an
# allowlisted environment and nothing else.
#
# action.yml runs this from a `shell: sh` step whose own env sets every value
# below from the github and runner contexts, and blanks BASH_ENV, ENV and the
# dynamic loader's variables, which act on this shell and on env before
# env -i can. sh must be dash, which imports no functions from the
# environment and reads $ENV only when interactive; an earlier step of
# action.yml refuses any other shell with a message, and the first lines
# here refuse it again, silently, before any command a function could
# shadow. This script then checks the pinned Node's SHA-256 and starts it
# through /usr/bin/env -i with only the names listed here: the caller's
# NODE_*, *_PROXY, SSL_CERT_*, LD_* and TLS variables never reach it. The
# three credentials go to Node on standard input, so Node's environment holds
# none of them and no process's arguments do; this shell and env, before
# -i, hold them in their environment.
#
# See docs/action.md, "What the action proves".
# Only reserved words, parameter expansion and the special builtin exit until
# the shell is known to be dash on Linux: in bash, a function imported from
# a BASH_FUNC_* variable would shadow any regular builtin, echo included.
case ${BASH_VERSION+bash}${ZSH_VERSION+zsh}${KSH_VERSION+ksh} in
  ?*) exit 70 ;;
esac
case ${AIRLOCK_RUNNER_OS-} in
  Linux) ;;
  *) exit 70 ;;
esac

set -eu

# The SHA-256 of bin/node in Node's official v24.22.3 Linux tarballs,
# node-v24.22.3-linux-x64.tar.xz and node-v24.22.3-linux-arm64.tar.xz from
# https://nodejs.org/dist/v24.22.3/. Each tarball matched SHASUMS256.txt,
# whose signature, SHASUMS256.txt.asc, is good from release key
# 5BE8A3F6C8A5C01D106C0AD820B1A390B168D356 (docs/action.md). Change these with
# the version, and both version lines in action.yml.
case ${AIRLOCK_NODE_ARCH-} in
  x64) expected=a7ec1b37e6ff9d187e4198c5b6df9a4eb1c74dd31804fb3bac55cc4ceca1ac01 ;;
  arm64) expected=8f9c2a55879e9705cb285b6cdd649d95df642c6720f052cb30f300d2677da99f ;;
  *)
    echo "::error::The action runs on x64 or arm64 Linux runners only."
    exit 1
    ;;
esac

node="$AIRLOCK_NODE_DIR/node"
if [ ! -x "$node" ]; then
  echo "::error::The action's pinned Node is not at $AIRLOCK_NODE_DIR, where setup-node installs Node $AIRLOCK_NODE_VERSION."
  exit 1
fi
digest=$(/usr/bin/env -i /usr/bin/sha256sum "$node")
case $digest in
  "$expected "*) ;;
  *)
    echo "::error::The Node at $AIRLOCK_NODE_DIR is not Node's official v$AIRLOCK_NODE_VERSION build: its SHA-256 is not $expected."
    exit 1
    ;;
esac
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
