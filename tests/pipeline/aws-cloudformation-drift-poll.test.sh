#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="${repository_root}/scripts/aws-cloudformation-drift.sh"
test -f "${helper}" && test ! -L "${helper}"
# shellcheck source=scripts/aws-cloudformation-drift.sh
source "${helper}"
test_root="$(mktemp -d)";trap 'rm -rf -- "${test_root}"' EXIT
fake_bin="${test_root}/bin";mkdir -p "${fake_bin}"
cat >"${fake_bin}/sleep" <<'SLEEP'
#!/usr/bin/env bash
set -euo pipefail
n="$(<"${SLEEP_COUNTER}")";n="$((n + 1))";printf '%s\n' "${n}" >"${SLEEP_COUNTER}"
SLEEP
cat >"${fake_bin}/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${AWS_CALL_LOG}"
echo 'PRIVATE_AWS_MARKER provider detail' >&2
[[ "${AWS_MAX_ATTEMPTS:-}" == 1 && "${AWS_RETRY_MODE:-}" == standard &&
  "${AWS_CLI_AUTO_PROMPT:-}" == off && "${AWS_PAGER-__unset__}" == "" ]] || exit 97
joined=" $* "
[[ "${joined}" == *' --cli-connect-timeout 5 '* && "${joined}" == *' --cli-read-timeout 15 '* &&
  "${joined}" == *' --no-cli-pager '* && "${joined}" == *" --region ${REGION} "* ]] || exit 97
if [[ "${joined}" == *' cloudformation detect-stack-drift '* ]]; then
  [[ "${joined}" == *" --stack-name ${STACK_NAME} "* && "${joined}" == *' --query StackDriftDetectionId '* &&
    "${joined}" == *' --output text '* ]] || exit 97
  if [[ "${SCENARIO}" == invalid-detection-id ]]; then printf 'None\n'; else printf '%s\n' "${DETECTION_ID}"; fi
  exit 0
fi
if [[ "${joined}" == *' cloudformation describe-stack-drift-detection-status '* ]]; then
  [[ "${joined}" == *" --stack-drift-detection-id ${DETECTION_ID} "* && "${joined}" == *' --output json '* ]] || exit 97
  n="$(<"${STATUS_COUNTER}")";n="$((n + 1))";printf '%s\n' "${n}" >"${STATUS_COUNTER}"
  case "${SCENARIO}" in
    progress-success)
      if ((n == 1)); then printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"NOT_CHECKED","DetectionStatus":"DETECTION_IN_PROGRESS","DriftedStackResourceCount":null}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}";
      else printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}"; fi ;;
    immediate-success|transient-success)
      if [[ "${SCENARIO}" == transient-success && "${n}" == 1 ]]; then exit 1; fi
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    persistent-error) exit 1 ;;
    perpetual-progress) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","DetectionStatus":"DETECTION_IN_PROGRESS"}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    detection-failed) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","DetectionStatus":"DETECTION_FAILED","DetectionStatusReason":"PRIVATE_AWS_MARKER"}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    drifted) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"DRIFTED","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":1}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    missing-count) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE"}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    missing-timestamp) printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    wrong-detection-id) printf '{"StackId":"%s","StackDriftDetectionId":"00000000-0000-0000-0000-000000000000","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_TIMESTAMP}" ;;
    wrong-stack-id) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${OTHER_STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    malformed) printf '{not-json\n' ;;
    unknown-status) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","DetectionStatus":"SURPRISE"}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    deadline-during-status) /bin/sleep 2; printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
    *) exit 98 ;;
  esac
  exit 0
fi
if [[ "${joined}" == *' cloudformation describe-stack-resource-drifts '* ]]; then
  [[ "${joined}" == *" --stack-name ${STACK_ID} "* ]] || exit 97
  if [[ "${SCENARIO}" == deadline-resource ]]; then /bin/sleep 2; fi
  resource_stack="${STACK_ID}";resource_time="${DETECTION_TIMESTAMP}";resource_status='IN_SYNC'
  [[ "${SCENARIO}" == different-incarnation ]] && resource_stack="${OTHER_STACK_ID}"
  [[ "${SCENARIO}" == stale-resource ]] && resource_time="${STALE_TIMESTAMP}"
  [[ "${SCENARIO}" == not-checked-resource ]] && resource_status='NOT_CHECKED'
  printf '{"StackResourceDrifts":[{"StackId":"%s","Timestamp":"%s","StackResourceDriftStatus":"%s"}]}\n' "${resource_stack}" "${resource_time}" "${resource_status}"
  exit 0
fi
if [[ "${joined}" == *' cloudformation describe-stacks '* ]]; then
  [[ "${joined}" == *" --stack-name ${STACK_ID} "* ]] || exit 97
  last_check="${DETECTION_TIMESTAMP}";[[ "${SCENARIO}" == final-timestamp-mismatch ]] && last_check="${NEWER_TIMESTAMP}"
  printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"IN_SYNC","LastCheckTimestamp":"%s"}}]}\n' "${STACK_ID}" "${last_check}"
  exit 0
fi
exit 97
AWS
chmod 0700 "${fake_bin}/aws" "${fake_bin}/sleep";export PATH="${fake_bin}:${PATH}"
export DETECTION_ID='11111111-2222-3333-4444-555555555555' ACCOUNT_ID='123456789012' REGION='eu-west-1' STACK_NAME='Archon-Test-Stack'
export STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${STACK_NAME}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
export OTHER_STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${STACK_NAME}/ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
export DETECTION_TIMESTAMP='2026-07-31T00:00:00.000Z' STALE_TIMESTAMP='2026-07-30T23:59:59.000Z' NEWER_TIMESTAMP='2026-07-31T00:00:01.000Z'
fail(){ echo "::error::$*" >&2;exit 1; }
assert_equals(){ [[ "$2" == "$1" ]]||fail "$3: expected $1, got $2"; }
run_poll_case(){
  local name="$1" expected="$2" expected_status="$3" expected_sleep="$4" deadline_offset="${5:-60}"
  local dir="${test_root}/poll-${name}" output stdout stderr rc=0 detect_calls
  mkdir -p "${dir}";export RUNNER_TEMP="${dir}" SCENARIO="${name}" AWS_CALL_LOG="${dir}/calls.log" STATUS_COUNTER="${dir}/status.count" SLEEP_COUNTER="${dir}/sleep.count"
  : >"${AWS_CALL_LOG}";printf '0\n'>"${STATUS_COUNTER}";printf '0\n'>"${SLEEP_COUNTER}"
  export CFN_DRIFT_MAX_ATTEMPTS=3 CFN_DRIFT_DELAY_SECONDS=0 CFN_DRIFT_MAX_API_FAILURES=3 CFN_DRIFT_PHASE_TIMEOUT_SECONDS=60
  export CFN_DRIFT_DEADLINE_EPOCH="$(( $(date +%s) + deadline_offset ))"
  output="${RUNNER_TEMP}/drift-${REGION}-${STACK_NAME}.json";stdout="${dir}/stdout";stderr="${dir}/stderr"
  if detect_and_wait_for_cloudformation_stack_in_sync "${REGION}" "${STACK_NAME}" "${output}" "${ACCOUNT_ID}" >"${stdout}" 2>"${stderr}";then rc=0;else rc=$?;fi
  if [[ "${expected}" == success ]];then [[ "${rc}" == 0 ]]||fail "${name} failed";test -f "${output}"&&test ! -L "${output}";assert_equals 600 "$(stat -c '%a' "${output}")" "${name} mode";jq -e --arg id "${DETECTION_ID}" --arg stack "${STACK_ID}" --arg ts "${DETECTION_TIMESTAMP}" '.StackDriftDetectionId==$id and .StackId==$stack and .Timestamp==$ts and .DetectionStatus=="DETECTION_COMPLETE" and .StackDriftStatus=="IN_SYNC" and .DriftedStackResourceCount==0' "${output}">/dev/null;else [[ "${rc}" != 0 ]]||fail "${name} unexpectedly passed";[[ ! -e "${output}" ]]||fail "${name} published failure";fi
  detect_calls="$(awk '/cloudformation detect-stack-drift/{n++}END{print n+0}' "${AWS_CALL_LOG}")";assert_equals 1 "${detect_calls}" "${name} detect calls";assert_equals "${expected_status}" "$(<"${STATUS_COUNTER}")" "${name} status calls";assert_equals "${expected_sleep}" "$(<"${SLEEP_COUNTER}")" "${name} sleeps"
  grep -Fq 'PRIVATE_AWS_MARKER' "${stdout}" "${stderr}"&&fail "${name} leaked provider detail"
  find "${dir}" -maxdepth 1 -name 'cloudformation-drift-status.*' -print -quit|grep -q .&&fail "${name} left raw candidate"
}
run_poll_case progress-success success 2 1
run_poll_case immediate-success success 1 0
run_poll_case transient-success success 2 1
run_poll_case persistent-error failure 3 2
run_poll_case perpetual-progress failure 3 2
run_poll_case detection-failed failure 1 0
run_poll_case drifted failure 1 0
run_poll_case missing-count failure 1 0
run_poll_case missing-timestamp failure 1 0
run_poll_case wrong-detection-id failure 1 0
run_poll_case wrong-stack-id failure 1 0
run_poll_case malformed failure 1 0
run_poll_case unknown-status failure 1 0
run_poll_case invalid-detection-id failure 0 0
run_poll_case deadline-during-status failure 1 0 1
run_resource_case(){
  local name="$1" expected="$2" expected_resource="$3" expected_final="$4" deadline_offset="${5:-60}"
  local dir="${test_root}/resource-${name}" stdout stderr rc=0 resources finals
  mkdir -p "${dir}";export RUNNER_TEMP="${dir}" SCENARIO="${name}" AWS_CALL_LOG="${dir}/calls.log" STATUS_COUNTER="${dir}/status.count" SLEEP_COUNTER="${dir}/sleep.count";:>"${AWS_CALL_LOG}";printf '0\n'>"${STATUS_COUNTER}";printf '0\n'>"${SLEEP_COUNTER}"
  deadline="$(( $(date +%s) + deadline_offset ))";stdout="${dir}/stdout";stderr="${dir}/stderr"
  if verify_cloudformation_stack_resource_drifts "${REGION}" "${STACK_NAME}" "${STACK_ID}" "${DETECTION_TIMESTAMP}" "${ACCOUNT_ID}" "${deadline}" >"${stdout}" 2>"${stderr}";then rc=0;else rc=$?;fi
  if [[ "${expected}" == success ]];then assert_equals 0 "${rc}" "${name} result";assert_equals 1 "$(<"${stdout}")" "${name} count";else [[ "${rc}" != 0 ]]||fail "${name} unexpectedly passed";fi
  resources="$(awk '/describe-stack-resource-drifts/{n++}END{print n+0}' "${AWS_CALL_LOG}")";finals="$(awk '/cloudformation describe-stacks/{n++}END{print n+0}' "${AWS_CALL_LOG}")";assert_equals "${expected_resource}" "${resources}" "${name} resource calls";assert_equals "${expected_final}" "${finals}" "${name} final calls"
  grep -Fq 'PRIVATE_AWS_MARKER' "${stdout}" "${stderr}"&&fail "${name} leaked provider detail"
  find "${dir}" -maxdepth 1 \( -name 'cloudformation-resource-drifts.*' -o -name 'cloudformation-final-stack.*' \) -print -quit|grep -q .&&fail "${name} left raw files"
}
run_resource_case resource-success success 1 1
run_resource_case different-incarnation failure 1 0
run_resource_case stale-resource failure 1 0
run_resource_case not-checked-resource failure 1 0
run_resource_case final-timestamp-mismatch failure 1 1
run_resource_case deadline-resource failure 1 0 1
if bash "${helper}" >/dev/null 2>&1;then fail 'source-only helper allowed execution';fi
grep -Fq 'stack-drift-detection-complete' "${helper}"&&fail 'unsupported waiter remains'
echo 'CloudFormation drift polling and stack-incarnation tests passed'