#!/usr/bin/env bash
set -euo pipefail

# Binary contract: 0 no blocking gaps, 1 blocking gaps, 2 a run error.
# In repository mode alone, the Action may map exit 2 to success with
# fail-on-incomplete:false; that override includes setup errors such as a
# missing credential. Central mode refuses the override: a central run that
# could not audit always fails.
# Waived, routed, unbuilt, and out-of-scope rules do not alter the binary exit status.
#
# Two modes. Repository mode audits one repository with the token input,
# which is the run's own GITHUB_TOKEN, or with AIRLOCK_TOKEN. Central mode
# audits every repository of the run's owner, signed in as Airlock Safe, and
# accepts no credential at all.

# Strip surrounding whitespace, as every Airlock credential source does
# before the token is classified.
trim() {
  local value=$1
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  printf '%s' "$value"
}

# The run's own token, given only so an installation token can be compared
# with it. Airlock never sends it anywhere: in repository mode it compares an
# installation token with it too, and in central mode it is removed.
run_token=$(trim "${AIRLOCK_RUN_TOKEN:-}")
unset AIRLOCK_RUN_TOKEN

mode=${INPUT_MODE:-repository}
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

# The override is honoured only for a mode known to be repository mode, so a
# central run, or one whose mode is unreadable, can never end as a success
# without its audit.
override=$fail_on_incomplete
fail_on_incomplete=true
case "$mode" in
  repository) fail_on_incomplete=$override ;;
  central)
    if [[ "$override" == false ]]; then
      validation_error="fail-on-incomplete applies only to repository mode; central mode always fails when it cannot audit."
    fi
    ;;
  *) validation_error="mode must be 'repository' or 'central'." ;;
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

# Write the stable incomplete document. It carries only the adapter's own
# message, never anything Airlock or a service printed.
incomplete_document() {
  local message=$1
  if [[ "$extension" == json ]]; then
    local escaped=$message
    escaped=${escaped//\\/\\\\}
    escaped=${escaped//\"/\\\"}
    escaped=${escaped//$'\n'/\\n}
    printf '{"outcome":"incomplete","complete":false,"mode":"%s","message":"%s"}\n' \
      "${mode//[^a-z]/}" "$escaped" >"$findings_location"
  else
    printf 'incomplete — complete: false\nmode: %s\n%s\n' \
      "${mode//[^a-z]/}" "$message" >"$findings_location"
  fi
}

finish_incomplete() {
  local message=$1
  incomplete_document "$message"
  echo "::error::$message"
  write_outputs incomplete false
  [[ "$fail_on_incomplete" == false ]] && exit 0
  exit 2
}

if [[ -n ${validation_error:-} ]]; then
  finish_incomplete "$validation_error"
fi

if [[ "$mode" == central ]]; then
  # Central mode signs for itself. A credential handed to it is refused
  # rather than ignored.
  if [[ -n $(trim "${INPUT_TOKEN:-}") || -n $(trim "${AIRLOCK_TOKEN:-}") ]]; then
    finish_incomplete "central mode accepts no credential; remove the token input and AIRLOCK_TOKEN."
  fi
  unset AIRLOCK_TOKEN
  if [[ -n ${INPUT_REPOSITORY:-} || -n "$reference" ]]; then
    finish_incomplete "central mode audits every repository of the run's owner; repository and ref do not apply."
  fi
  owner=${GITHUB_REPOSITORY_OWNER:-}
  if [[ -z "$owner" ]]; then
    finish_incomplete "central mode needs GITHUB_REPOSITORY_OWNER."
  fi
  args=(
    audit "$owner" --mode central --format "$format"
    --app-id "${INPUT_APP_ID:-}"
    --key-name "${INPUT_KEY_NAME:-}"
    --installation-repositories "${INPUT_INSTALLATION_REPOSITORIES:-}"
    --vault-url "${INPUT_VAULT_URL:-}"
    --azure-tenant-id "${INPUT_AZURE_TENANT_ID:-}"
    --azure-client-id "${INPUT_AZURE_CLIENT_ID:-}"
  )
else
  credential=$(trim "${INPUT_TOKEN:-}")
  [[ -n "$credential" ]] || credential=$(trim "${AIRLOCK_TOKEN:-}")
  if [[ -z "$credential" ]]; then
    finish_incomplete "repository mode needs the token input, the run's own token, or AIRLOCK_TOKEN, a credential Airlock can prove is read-only."
  fi
  # Airlock reads an installation token's grant from the job's declared
  # permissions, which bound only the run's own token. Any other installation
  # token would be judged by permissions that are not its own. Airlock makes
  # the same comparison on the trimmed values; refusing here saves the build.
  if [[ $credential == ghs_* && $credential != "$run_token" ]]; then
    finish_incomplete "the credential is an installation token other than this run's own; repository mode accepts only the run's GITHUB_TOKEN."
  fi
  export AIRLOCK_TOKEN=$credential
  [[ -z "$run_token" ]] || export AIRLOCK_RUN_TOKEN=$run_token
  if [[ -z "$repository" ]]; then
    finish_incomplete "repository is required when GITHUB_REPOSITORY is unavailable."
  fi
  args=(audit "$repository" --mode repository --format "$format")
  [[ -z "$reference" ]] || args+=(--ref "$reference")
fi
[[ -z "$policy" ]] || args+=(--policy "$policy")

set +e
"$airlock_bin" "${args[@]}" >"$findings_location"
status=$?
set -e

# Airlock writes no report when it stops before auditing, such as on a
# refused sign-in. An empty file is not a report, so it becomes the stable
# incomplete document, and an empty report is never a pass.
if [[ ! -s "$findings_location" ]]; then
  incomplete_document "Airlock exited with status $status before writing a report; the step log says why."
  [[ "$status" -ne 0 && "$status" -ne 1 ]] || status=2
  echo "::error::Airlock exited before writing a report."
fi

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
