#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

fake_airlock="$test_root/airlock"
cat >"$fake_airlock" <<'EOF'
#!/usr/bin/env bash
printf '{"outcome":"%s","complete":%s}\n' "$FAKE_OUTCOME" "$FAKE_COMPLETE"
exit "$FAKE_STATUS"
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
  rg -q "^outcome=$expected_outcome$" "$output_file"
  rg -q "^complete=$expected_complete$" "$output_file"
  rg -q '^findings-location=' "$output_file"
  rg -q "^AIRLOCK_OUTCOME=$expected_outcome$" "$environment_file"
  rg -q "^AIRLOCK_COMPLETE=$expected_complete$" "$environment_file"
  rg -q '^AIRLOCK_FINDINGS=' "$environment_file"
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
rg -q '^outcome=incomplete$' "$missing_token_output"
rg -q '^complete=false$' "$missing_token_output"
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
rg -q '^outcome=incomplete$' "$missing_token_failing_output"
rg -q '^complete=false$' "$missing_token_failing_output"
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
rg -q '^outcome=incomplete$' "$invalid_format_output"
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
