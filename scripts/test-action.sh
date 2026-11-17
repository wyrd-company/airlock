#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

fake_airlock="$test_root/airlock"
cat >"$fake_airlock" <<'EOF'
#!/usr/bin/env bash
if [[ -n ${FAKE_RECORD:-} ]]; then
  printf '%s\n' "$@" >"$FAKE_RECORD.args"
  printf 'AIRLOCK_TOKEN=%s\nAIRLOCK_RUN_TOKEN=%s\n' \
    "${AIRLOCK_TOKEN-unset}" "${AIRLOCK_RUN_TOKEN-unset}" >"$FAKE_RECORD.env"
fi
printf '{"outcome":"%s","complete":%s}\n' "${FAKE_OUTCOME:-conformant}" "${FAKE_COMPLETE:-true}"
exit "${FAKE_STATUS:-0}"
EOF
chmod +x "$fake_airlock"

run_case() {
  local expected_status=$1
  local fake_status=$2
  local fail_on_incomplete=$3
  local expected_outcome=$4
  local expected_complete=$5
  local output_file="$test_root/output-$fake_status-$fail_on_incomplete"
  local environment_file="$test_root/environment-$fake_status-$fail_on_incomplete"

  set +e
  AIRLOCK_TOKEN=fixture \
    AIRLOCK_BIN="$fake_airlock" \
    FAKE_STATUS="$fake_status" \
    FAKE_OUTCOME="$expected_outcome" \
    FAKE_COMPLETE="$expected_complete" \
    INPUT_REPOSITORY=example/repository \
    INPUT_FORMAT=json \
    INPUT_FAIL_ON_INCOMPLETE="$fail_on_incomplete" \
    RUNNER_TEMP="$test_root" \
    GITHUB_OUTPUT="$output_file" \
    GITHUB_ENV="$environment_file" \
    "$root/scripts/run-action.sh" >/dev/null
  actual_status=$?
  set -e

  [[ "$actual_status" -eq "$expected_status" ]]
  grep -qE "^outcome=$expected_outcome$" "$output_file"
  grep -qE "^complete=$expected_complete$" "$output_file"
  grep -qE '^findings-location=' "$output_file"
  grep -qE "^AIRLOCK_OUTCOME=$expected_outcome$" "$environment_file"
  grep -qE "^AIRLOCK_COMPLETE=$expected_complete$" "$environment_file"
  grep -qE '^AIRLOCK_FINDINGS=' "$environment_file"
}

run_case 0 0 true conformant true
run_case 1 1 true nonconformant true
run_case 2 2 true incomplete false
run_case 0 2 false incomplete false

missing_token_output="$test_root/output-missing-token"
missing_token_environment="$test_root/environment-missing-token"
AIRLOCK_BIN="$fake_airlock" \
  INPUT_REPOSITORY=example/repository \
  INPUT_FORMAT=json \
  INPUT_FAIL_ON_INCOMPLETE=false \
  RUNNER_TEMP="$test_root" \
  GITHUB_OUTPUT="$missing_token_output" \
  GITHUB_ENV="$missing_token_environment" \
  "$root/scripts/run-action.sh" >/dev/null
grep -qE '^outcome=incomplete$' "$missing_token_output"
grep -qE '^complete=false$' "$missing_token_output"
missing_token_findings=$(sed -n 's/^findings-location=//p' "$missing_token_output")
jq -e '.outcome == "incomplete" and .complete == false' "$missing_token_findings" >/dev/null

missing_token_failing_output="$test_root/output-missing-token-failing"
set +e
AIRLOCK_BIN="$fake_airlock" \
  INPUT_REPOSITORY=example/repository \
  INPUT_FORMAT=json \
  INPUT_FAIL_ON_INCOMPLETE=true \
  RUNNER_TEMP="$test_root" \
  GITHUB_OUTPUT="$missing_token_failing_output" \
  GITHUB_ENV="$test_root/environment-missing-token-failing" \
  GITHUB_ACTION=missing-token-failing \
  "$root/scripts/run-action.sh" >/dev/null
missing_token_status=$?
set -e
[[ "$missing_token_status" -eq 2 ]]
grep -qE '^outcome=incomplete$' "$missing_token_failing_output"
grep -qE '^complete=false$' "$missing_token_failing_output"
missing_token_failing_findings=$(sed -n 's/^findings-location=//p' "$missing_token_failing_output")
[[ -f "$missing_token_failing_findings" ]]

invalid_format_output="$test_root/output-invalid-format"
AIRLOCK_TOKEN=fixture \
  AIRLOCK_BIN="$fake_airlock" \
  INPUT_REPOSITORY=example/repository \
  INPUT_FORMAT=xml \
  INPUT_FAIL_ON_INCOMPLETE=false \
  RUNNER_TEMP="$test_root" \
  GITHUB_OUTPUT="$invalid_format_output" \
  GITHUB_ENV="$test_root/environment-invalid-format" \
  GITHUB_ACTION=invalid-format \
  "$root/scripts/run-action.sh" >/dev/null
grep -qE '^outcome=incomplete$' "$invalid_format_output"
invalid_format_findings=$(sed -n 's/^findings-location=//p' "$invalid_format_output")
[[ -f "$invalid_format_findings" ]]

first_output="$test_root/output-first-invocation"
second_output="$test_root/output-second-invocation"
for invocation in first second; do
  AIRLOCK_TOKEN=fixture \
    AIRLOCK_BIN="$fake_airlock" \
    FAKE_STATUS=0 \
    FAKE_OUTCOME=conformant \
    FAKE_COMPLETE=true \
    INPUT_REPOSITORY=example/repository \
    INPUT_FORMAT=json \
    INPUT_FAIL_ON_INCOMPLETE=true \
    RUNNER_TEMP="$test_root" \
    GITHUB_RUN_ID=123 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_ACTION="$invocation" \
    GITHUB_OUTPUT="$test_root/output-$invocation-invocation" \
    GITHUB_ENV="$test_root/environment-$invocation-invocation" \
    "$root/scripts/run-action.sh" >/dev/null
done
first_location=$(sed -n 's/^findings-location=//p' "$first_output")
second_location=$(sed -n 's/^findings-location=//p' "$second_output")
[[ "$first_location" != "$second_location" ]]

# Run the adapter with the fake binary recording what it received.
# Arguments are NAME=VALUE environment entries; the status is returned.
run_recorded() {
  local name=$1
  shift
  set +e
  env -u AIRLOCK_TOKEN -u AIRLOCK_RUN_TOKEN \
    AIRLOCK_BIN="$fake_airlock" \
    FAKE_RECORD="$test_root/$name" \
    INPUT_FORMAT=json \
    INPUT_FAIL_ON_INCOMPLETE=true \
    RUNNER_TEMP="$test_root" \
    GITHUB_ACTION="$name" \
    GITHUB_OUTPUT="$test_root/output-$name" \
    GITHUB_ENV="$test_root/environment-$name" \
    "$@" "$root/scripts/run-action.sh" >/dev/null 2>&1
  local status=$?
  set -e
  return "$status"
}

# Repository mode passes the run's own token to Airlock as AIRLOCK_TOKEN, and
# never the comparison copy.
run_recorded repository-run-token \
  GITHUB_REPOSITORY=example/repository \
  INPUT_TOKEN=ghs_run AIRLOCK_RUN_TOKEN=ghs_run
grep -qx -- '--mode' "$test_root/repository-run-token.args"
grep -qx 'repository' "$test_root/repository-run-token.args"
grep -qx 'example/repository' "$test_root/repository-run-token.args"
grep -qx 'AIRLOCK_TOKEN=ghs_run' "$test_root/repository-run-token.env"
grep -qx 'AIRLOCK_RUN_TOKEN=unset' "$test_root/repository-run-token.env"

# Another installation token is refused before Airlock runs, whether it
# arrives as the token input or as AIRLOCK_TOKEN.
for source in INPUT_TOKEN AIRLOCK_TOKEN; do
  if run_recorded "foreign-$source" \
    GITHUB_REPOSITORY=example/repository \
    "$source=ghs_another_app" AIRLOCK_RUN_TOKEN=ghs_run; then
    echo "a foreign installation token from $source was not refused" >&2
    exit 1
  fi
  [[ ! -e "$test_root/foreign-$source.args" ]]
  grep -qE '^outcome=incomplete$' "$test_root/output-foreign-$source"
done

# A user token supplied as AIRLOCK_TOKEN keeps working in repository mode.
run_recorded repository-user-token \
  GITHUB_REPOSITORY=example/repository \
  AIRLOCK_TOKEN=ghu_fixture AIRLOCK_RUN_TOKEN=ghs_run
grep -qx 'AIRLOCK_TOKEN=ghu_fixture' "$test_root/repository-user-token.env"

# Central mode audits the run's owner with the six inputs and no credential.
run_recorded central \
  INPUT_MODE=central GITHUB_REPOSITORY_OWNER=example AIRLOCK_RUN_TOKEN=ghs_run \
  INPUT_APP_ID=4409712 INPUT_KEY_NAME=airlock-safe \
  INPUT_INSTALLATION_REPOSITORIES='example/*' \
  INPUT_VAULT_URL=https://example.vault.azure.net \
  INPUT_AZURE_TENANT_ID=tenant INPUT_AZURE_CLIENT_ID=client
expected_central_args="audit
example
--mode
central
--format
json
--app-id
4409712
--key-name
airlock-safe
--installation-repositories
example/*
--vault-url
https://example.vault.azure.net
--azure-tenant-id
tenant
--azure-client-id
client"
[[ "$(cat "$test_root/central.args")" == "$expected_central_args" ]]
grep -qx 'AIRLOCK_TOKEN=unset' "$test_root/central.env"
grep -qx 'AIRLOCK_RUN_TOKEN=unset' "$test_root/central.env"

# Central mode refuses any credential, a repository and a ref.
for refused in INPUT_TOKEN=ghs_run AIRLOCK_TOKEN=ghu_fixture \
  INPUT_REPOSITORY=example/repository INPUT_REF=main; do
  name="central-refuses-${refused%%=*}"
  if run_recorded "$name" \
    INPUT_MODE=central GITHUB_REPOSITORY_OWNER=example "$refused"; then
    echo "central mode accepted $refused" >&2
    exit 1
  fi
  [[ ! -e "$test_root/$name.args" ]]
  grep -qE '^outcome=incomplete$' "$test_root/output-$name"
done

# An unknown mode is a validation error.
if run_recorded unknown-mode INPUT_MODE=organization AIRLOCK_TOKEN=ghu_fixture; then
  echo "an unknown mode was accepted" >&2
  exit 1
fi
[[ ! -e "$test_root/unknown-mode.args" ]]
