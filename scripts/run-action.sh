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
    extension=txt
    validation_error="format must be 'json' or 'text'."
    ;;
esac

case "$fail_on_incomplete" in
  true | false) ;;
  *)
    fail_on_incomplete=true
    validation_error="fail-on-incomplete must be 'true' or 'false'."
    ;;
esac

invocation=${GITHUB_ACTION:-airlock}
invocation=${invocation//[^[:alnum:]_.-]/_}
findings_location="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/airlock-findings-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${invocation}.${extension}"

write_environment() {
  if [[ -n ${GITHUB_ENV:-} ]]; then
    {
      echo "AIRLOCK_FINDINGS=$findings_location"
      echo "AIRLOCK_OUTCOME=$1"
      echo "AIRLOCK_COMPLETE=$2"
    } >>"$GITHUB_ENV"
  fi
}

write_outputs() {
  {
    echo "outcome=$1"
    echo "complete=$2"
    echo "findings-location=$findings_location"
  } >>"$GITHUB_OUTPUT"
  write_environment "$1" "$2"
}

finish_incomplete() {
  local message=$1
  if [[ "$extension" == json ]]; then
    local escaped=$message
    escaped=${escaped//\\/\\\\}
    escaped=${escaped//\"/\\\"}
    escaped=${escaped//$'\n'/\\n}
    printf '{"outcome":"incomplete","complete":false,"message":"%s"}\n' \
      "$escaped" >"$findings_location"
  else
    printf 'incomplete — complete: false\n%s\n' "$message" >"$findings_location"
  fi
  echo "::error::$message"
  write_outputs incomplete false
  [[ "$fail_on_incomplete" == false ]] && exit 0
  exit 2
}

if [[ -n ${validation_error:-} ]]; then
  finish_incomplete "$validation_error"
fi

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

write_outputs "$outcome" "$complete"

if [[ "$status" -eq 2 && "$fail_on_incomplete" == false ]]; then
  exit 0
fi

exit "$status"
