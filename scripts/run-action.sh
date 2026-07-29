#!/usr/bin/env bash
set -euo pipefail

repository=${INPUT_REPOSITORY:-${GITHUB_REPOSITORY:-}}
policy=${INPUT_POLICY:-}
reference=${INPUT_REF:-}
format=${INPUT_FORMAT:-json}
fail_on_incomplete=${INPUT_FAIL_ON_INCOMPLETE:-true}
airlock_bin=${AIRLOCK_BIN:-airlock}

case "$format" in
  json) extension=json ;;
  text) extension=txt ;;
  *)
    echo "::error::format must be 'json' or 'text'."
    exit 2
    ;;
esac

case "$fail_on_incomplete" in
  true | false) ;;
  *)
    echo "::error::fail-on-incomplete must be 'true' or 'false'."
    exit 2
    ;;
esac

invocation=${GITHUB_ACTION:-airlock}
invocation=${invocation//[^[:alnum:]_.-]/_}
findings_location="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/airlock-findings-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${invocation}.${extension}"

finish_incomplete() {
  local message=$1
  printf '%s\n' "$message" >"$findings_location"
  echo "::error::$message"
  {
    echo "outcome=incomplete"
    echo "complete=false"
    echo "findings-location=$findings_location"
  } >>"$GITHUB_OUTPUT"
  [[ "$fail_on_incomplete" == false ]] && exit 0
  exit 2
}

if [[ -z ${AIRLOCK_TOKEN:-} ]]; then
  finish_incomplete "AIRLOCK_TOKEN is required and must be a credential Airlock can prove is read-only."
fi

if [[ -z "$repository" ]]; then
  finish_incomplete "repository is required when GITHUB_REPOSITORY is unavailable."
fi

args=(audit "$repository" --format "$format")
[[ -z "$policy" ]] || args+=(--policy "$policy")
[[ -z "$reference" ]] || args+=(--ref "$reference")

set +e
"$airlock_bin" "${args[@]}" >"$findings_location"
status=$?
set -e

cat "$findings_location"

case "$status" in
  0)
    outcome=conformant
    complete=true
    ;;
  1)
    outcome=nonconformant
    complete=true
    ;;
  2)
    outcome=incomplete
    complete=false
    ;;
  *)
    outcome=incomplete
    complete=false
    ;;
esac

{
  echo "outcome=$outcome"
  echo "complete=$complete"
  echo "findings-location=$findings_location"
} >>"$GITHUB_OUTPUT"

if [[ "$status" -eq 2 && "$fail_on_incomplete" == false ]]; then
  exit 0
fi

exit "$status"
