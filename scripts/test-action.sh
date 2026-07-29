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
    "$root/scripts/run-action.sh" >/dev/null
  actual_status=$?
  set -e

  [[ "$actual_status" -eq "$expected_status" ]]
  rg -q "^outcome=$expected_outcome$" "$output_file"
  rg -q "^complete=$expected_complete$" "$output_file"
  rg -q '^findings-location=' "$output_file"
}

run_case 0 0 true conformant true
run_case 1 1 true nonconformant true
run_case 2 2 true incomplete false
run_case 0 2 false incomplete false

missing_token_output="$test_root/output-missing-token"
AIRLOCK_BIN="$fake_airlock" \
  INPUT_REPOSITORY=example/repository \
  INPUT_FORMAT=json \
  INPUT_FAIL_ON_INCOMPLETE=false \
  RUNNER_TEMP="$test_root" \
  GITHUB_OUTPUT="$missing_token_output" \
  "$root/scripts/run-action.sh" >/dev/null
rg -q '^outcome=incomplete$' "$missing_token_output"
rg -q '^complete=false$' "$missing_token_output"
