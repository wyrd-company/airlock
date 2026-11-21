#!/bin/sh
# The forge legs of CI's "Action: a forged run token is refused" job. Each
# leg tries one way a caller's job environment could replace the run's token
# or GitHub's answers, and this script arms it, checks the action resisted
# it, and shows it works on an ordinary step.
#
#   ci-forge.sh arm     before the action
#   ci-forge.sh assert  after the action: it refused, or reached GitHub
#   ci-forge.sh live    after the action: the forge works outside it
#
# LEG is pair, node-options, bash-env or proxy. FORGED is the synthetic
# token. MARKER is the file the node-options forge writes when its code runs.
set -eu

leg=${LEG:?}
marker=${MARKER:?}

case "${1:?}" in
  arm)
    mkdir -p /tmp/airlock-forge
    # Every node step before this one, checkout's included, ran the
    # node-options forge and wrote the marker; the action must not.
    rm -f "$marker"
    case "$leg" in
      bash-env)
        # The script expands $FORGED when bash sources it, not here.
        # shellcheck disable=SC2016
        printf 'export AIRLOCK_RUN_TOKEN="$FORGED"\n' >/tmp/airlock-forge/rewrite.sh
        echo "BASH_ENV=/tmp/airlock-forge/rewrite.sh" >>"$GITHUB_ENV"
        ;;
      proxy)
        # A dead proxy, Node told to use it, and TLS checks off. Set after
        # checkout, which a dead proxy would stop.
        {
          echo "NODE_USE_ENV_PROXY=1"
          echo "HTTPS_PROXY=http://127.0.0.1:9"
          echo "HTTP_PROXY=http://127.0.0.1:9"
          echo "https_proxy=http://127.0.0.1:9"
          echo "http_proxy=http://127.0.0.1:9"
          echo "NODE_TLS_REJECT_UNAUTHORIZED=0"
        } >>"$GITHUB_ENV"
        ;;
    esac
    ;;
  assert)
    message=$(cat "${FINDINGS:?}")
    echo "$ARTIFACT" | grep -Eq '^airlock-findings-[0-9]+$'
    case "$leg" in
      proxy)
        # The run's real token: the audit must have reached GitHub itself.
        # It is placed and then stops at the policy, or completes; a proxy
        # would have made the first request fail as run_token_unconfirmed.
        if echo "$message" | grep -q run_token_unconfirmed; then
          echo "the audit did not reach GitHub: $message" >&2
          exit 1
        fi
        if [ "${OUTCOME:?}" = incomplete ]; then
          echo "$message" | grep -q "cannot resolve the policy"
        fi
        echo "reached GitHub directly ($OUTCOME); uploaded as $ARTIFACT"
        ;;
      *)
        test "${OUTCOME:?}" = incomplete
        echo "$message" | grep -q foreign_installation_token
        echo "refused as foreign_installation_token; uploaded as $ARTIFACT"
        ;;
    esac
    if [ -e "$marker" ]; then
      echo "the caller's NODE_OPTIONS ran inside the action" >&2
      exit 1
    fi
    echo "no step of the action ran the caller's NODE_OPTIONS"
    ;;
  live)
    case "$leg" in
      pair) test "$AIRLOCK_RUN_TOKEN" = "$FORGED" ;;
      bash-env) bash -c 'test "$AIRLOCK_RUN_TOKEN" = "$FORGED"' ;;
      node-options)
        node -e 'process.exit(process.env.AIRLOCK_RUN_TOKEN === process.env.FORGED ? 0 : 1)'
        test -e "$marker"
        ;;
      proxy)
        # The action's Node is first on PATH now; through the dead proxy its
        # fetch fails.
        if node -e 'fetch(process.env.GITHUB_API_URL).then(() => process.exit(1), () => process.exit(0))'; then
          :
        else
          echo "fetch reached GitHub despite the proxy" >&2
          exit 1
        fi
        ;;
    esac
    echo "the $leg forge works on an ordinary step"
    ;;
esac
