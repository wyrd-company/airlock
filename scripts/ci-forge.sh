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
# LEG is pair, node-options, bash-env, ld-preload or proxy. FORGED is the
# synthetic token. MARKER is the file the node-options and ld-preload forges
# write when their code runs.
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
      ld-preload)
        # A library the loader runs in every process that starts with
        # LD_PRELOAD or LD_AUDIT pointing at it. It marks only processes of
        # the action's steps, which it knows by a variable each holds
        # (AIRLOCK_FORGE_PROBE marks the ordinary step that shows it live).
        cat >/tmp/airlock-forge/hook.c <<'C'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static const char *held(void) {
  static const char *names[] = {"AIRLOCK_RUN_TOKEN", "AIRLOCK_CREDENTIALS_ON_STDIN",
                                "INPUT_NODE-VERSION", "INPUT_IF-NO-FILES-FOUND",
                                "AIRLOCK_RUNNER_OS", "AIRLOCK_FORGE_PROBE"};
  for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
    const char *value = getenv(names[i]);
    if (value != NULL && *value != '\0') return names[i];
  }
  return NULL;
}
__attribute__((constructor)) static void mark(void) {
  const char *name = held();
  if (name != NULL) {
    char exe[256] = "?";
    ssize_t size = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (size > 0) exe[size] = '\0';
    int fd = open("/tmp/airlock-forge-marker", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
      char line[400];
      int length = snprintf(line, sizeof line, "%d %s %s\n", (int)getpid(), exe, name);
      if (length > 0) (void)write(fd, line, (size_t)length);
      close(fd);
    }
  }
}
unsigned int la_version(unsigned int version) { return version; }
C
        gcc -shared -fPIC -o /tmp/airlock-forge/hook.so /tmp/airlock-forge/hook.c
        {
          echo "LD_PRELOAD=/tmp/airlock-forge/hook.so"
          echo "LD_AUDIT=/tmp/airlock-forge/hook.so"
        } >>"$GITHUB_ENV"
        ;;
      proxy)
        # A dead proxy, Node told to use it, and TLS checks off. Set after
        # checkout, which a dead proxy would stop. Upper case only: Actions
        # reads env names without regard to case when it loads action.yml,
        # so the action can blank HTTPS_PROXY for its Node actions but not
        # https_proxy beside it. The lower-case forms still reach setup-node
        # and upload-artifact; docs/action.md lists that as not covered.
        # The audit step's allowlist drops both (action/tests).
        {
          echo "NODE_USE_ENV_PROXY=1"
          echo "HTTPS_PROXY=http://127.0.0.1:9"
          echo "HTTP_PROXY=http://127.0.0.1:9"
          echo "NODE_TLS_REJECT_UNAUTHORIZED=0"
        } >>"$GITHUB_ENV"
        # No pinned Node in the tool cache, so setup-node must download it,
        # past the dead proxy it blanks, and step.sh then checks the
        # downloaded binary against the official build's SHA-256.
        rm -rf "$RUNNER_TOOL_CACHE/node/24.22.3" 2>/dev/null ||
          sudo rm -rf "$RUNNER_TOOL_CACHE/node/24.22.3"
        test ! -e "$RUNNER_TOOL_CACHE/node/24.22.3"
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
        test -x "$RUNNER_TOOL_CACHE/node/24.22.3/x64/bin/node"
        echo "setup-node downloaded the pinned Node past the proxy, and step.sh accepted its SHA-256"
        echo "reached GitHub directly ($OUTCOME); uploaded as $ARTIFACT"
        ;;
      *)
        test "${OUTCOME:?}" = incomplete
        echo "$message" | grep -q foreign_installation_token
        echo "refused as foreign_installation_token; uploaded as $ARTIFACT"
        ;;
    esac
    if [ -e "$marker" ]; then
      echo "the caller's NODE_OPTIONS or preloaded library ran inside the action:" >&2
      cat "$marker" >&2
      exit 1
    fi
    echo "no step of the action ran the caller's NODE_OPTIONS or preloaded library"
    ;;
  live)
    case "$leg" in
      pair) test "$AIRLOCK_RUN_TOKEN" = "$FORGED" ;;
      bash-env) bash -c 'test "$AIRLOCK_RUN_TOKEN" = "$FORGED"' ;;
      node-options)
        node -e 'process.exit(process.env.AIRLOCK_RUN_TOKEN === process.env.FORGED ? 0 : 1)'
        test -e "$marker"
        ;;
      ld-preload)
        AIRLOCK_FORGE_PROBE=1 /bin/true
        test -e "$marker"
        ;;
      proxy)
        # The action's Node is first on PATH now. Its fetch must fail, and
        # only by the dead proxy refusing the connection.
        node -e 'fetch(process.env.GITHUB_API_URL).then(
          () => { console.error("fetch reached GitHub despite the proxy"); process.exit(1); },
          (error) => { const code = error?.cause?.code; console.log("fetch failed:", code); process.exit(code === "ECONNREFUSED" ? 0 : 1); })'
        ;;
    esac
    echo "the $leg forge works on an ordinary step"
    ;;
esac
