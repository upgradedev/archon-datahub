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
[[ "$#" -eq 1 ]] || exit 97
n="$(<"${SLEEP_COUNTER}")";n="$((n + 1))";printf '%s\n' "${n}" >"${SLEEP_COUNTER}"
printf '%s\n' "$1" >>"${SLEEP_ARGUMENT_LOG}"
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
    wrong-stack-id) printf '{"StackId":"%s","StackDriftDetectionId":"%s","Timestamp":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${WRONG_STACK_ID}" "${DETECTION_ID}" "${DETECTION_TIMESTAMP}" ;;
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
  resource_stack="${STACK_ID}";resource_time="${ACTIVE_DETECTION_TIMESTAMP}";resource_status='IN_SYNC'
  [[ "${SCENARIO}" == different-incarnation ]] && resource_stack="${OTHER_STACK_ID}"
  [[ "${SCENARIO}" == stale-resource ]] && resource_time="${STALE_TIMESTAMP}"
  [[ "${SCENARIO}" == subsecond-stale-resource ]] && resource_time="${SUBSECOND_STALE_TIMESTAMP}"
  [[ "${SCENARIO}" == invalid-resource-calendar ]] && resource_time="${INVALID_RESOURCE_TIMESTAMP}"
  [[ "${SCENARIO}" == not-checked-resource ]] && resource_status='NOT_CHECKED'
  printf '{"StackResourceDrifts":[{"StackId":"%s","Timestamp":"%s","StackResourceDriftStatus":"%s"}]}\n' "${resource_stack}" "${resource_time}" "${resource_status}"
  exit 0
fi
if [[ "${joined}" == *' cloudformation describe-stacks '* ]]; then
  [[ "${joined}" == *" --stack-name ${STACK_ID} "* ]] || exit 97
  n="$(<"${FINAL_COUNTER}")";n="$((n + 1))";printf '%s\n' "${n}" >"${FINAL_COUNTER}"
  case "${SCENARIO}" in
    deadline-final) /bin/sleep 2 ;;
    final-api-transient) ((n == 1)) && exit 1 ;;
    final-api-persistent) exit 1 ;;
    final-malformed) printf '{not-json\n'; exit 0 ;;
    final-oversize) printf '{"Stacks":[],"Padding":"'; printf '%065537d' 0; printf '"}\n'; exit 0 ;;
  esac
  final_stack="${STACK_ID}";final_status='IN_SYNC';last_check="${ACTIVE_DETECTION_TIMESTAMP}"
  case "${SCENARIO}" in
    final-equivalent-utc) last_check="${EQUIVALENT_TIMESTAMP}" ;;
    final-nonzero-equivalent) last_check="${NONZERO_EQUIVALENT_TIMESTAMP}" ;;
    final-stale-then-current) ((n == 1)) && last_check="${STALE_TIMESTAMP}" ;;
    final-stale-persistent|final-stale-default) last_check="${STALE_TIMESTAMP}" ;;
    final-timestamp-mismatch) last_check="${NEWER_TIMESTAMP}" ;;
    final-subsecond-mismatch) last_check="${SUBSECOND_NEWER_TIMESTAMP}" ;;
    final-different-incarnation) final_stack="${OTHER_STACK_ID}" ;;
    final-drifted) final_status='DRIFTED' ;;
    final-invalid-calendar) last_check="${INVALID_FINAL_TIMESTAMP}" ;;
    final-invalid-second) last_check="${INVALID_SECOND_TIMESTAMP}" ;;
    final-invalid-fraction) last_check="${INVALID_FRACTION_TIMESTAMP}" ;;
    final-missing-then-current)
      if ((n == 1)); then
        printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"IN_SYNC"}}]}\n' "${STACK_ID}"
        exit 0
      fi ;;
    final-absent-drift-info-then-current)
      if ((n == 1)); then printf '{"Stacks":[{"StackId":"%s"}]}\n' "${STACK_ID}";exit 0;fi ;;
    final-not-checked-missing-then-current)
      if ((n == 1)); then printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"NOT_CHECKED"}}]}\n' "${STACK_ID}";exit 0;fi ;;
    final-drifted-stale-then-current)
      if ((n == 1)); then printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"DRIFTED","LastCheckTimestamp":"%s"}}]}\n' "${STACK_ID}" "${STALE_TIMESTAMP}";exit 0;fi ;;
    final-multiple-stacks)
      printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"IN_SYNC","LastCheckTimestamp":"%s"}},{"StackId":"%s","DriftInformation":{"StackDriftStatus":"IN_SYNC","LastCheckTimestamp":"%s"}}]}\n' "${STACK_ID}" "${last_check}" "${STACK_ID}" "${last_check}"
      exit 0 ;;
  esac
  printf '{"Stacks":[{"StackId":"%s","DriftInformation":{"StackDriftStatus":"%s","LastCheckTimestamp":"%s"}}]}\n' "${final_stack}" "${final_status}" "${last_check}"
  exit 0
fi
exit 97
AWS
chmod 0700 "${fake_bin}/aws" "${fake_bin}/sleep";export PATH="${fake_bin}:${PATH}"
export DETECTION_ID='11111111-2222-3333-4444-555555555555' ACCOUNT_ID='123456789012' REGION='eu-west-1' STACK_NAME='Archon-Test-Stack'
export STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${STACK_NAME}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
export OTHER_STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${STACK_NAME}/ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
export WRONG_STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/Not-${STACK_NAME}/ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
export DETECTION_TIMESTAMP='2026-07-31T00:00:00.000Z' STALE_TIMESTAMP='2026-07-30T23:59:59.000Z' NEWER_TIMESTAMP='2026-07-31T00:00:01.000Z'
export EQUIVALENT_TIMESTAMP='2026-07-31T00:00:00.000000+00:00'
export SUBSECOND_DETECTION_TIMESTAMP='2026-07-31T00:00:00.500Z'
export SUBSECOND_STALE_TIMESTAMP='2026-07-31T00:00:00.499999+00:00'
export SUBSECOND_NEWER_TIMESTAMP='2026-07-31T00:00:00.001Z'
export NONZERO_DETECTION_TIMESTAMP='2026-07-31T00:00:00.5Z' NONZERO_EQUIVALENT_TIMESTAMP='2026-07-31T00:00:00.500000000+00:00'
export LEAP_TIMESTAMP='2024-02-29T12:34:56.123456789Z' INVALID_DETECTION_TIMESTAMP='2026-02-29T00:00:00Z'
export INVALID_RESOURCE_TIMESTAMP='2026-04-31T00:00:00Z' INVALID_FINAL_TIMESTAMP='2026-07-31T24:00:00Z'
export INVALID_SECOND_TIMESTAMP='2026-07-31T00:00:60Z' INVALID_FRACTION_TIMESTAMP='2026-07-31T00:00:00.1234567890Z'
fail(){ echo "::error::$*" >&2;exit 1; }
assert_equals(){ [[ "$2" == "$1" ]]||fail "$3: expected $1, got $2"; }
assert_category(){
  local expected="$1" file="$2" exact total
  exact="$(awk -v line="::error title=CloudFormation drift verification failed::category=${expected}" '$0 == line {n++} END {print n+0}' "${file}")"
  total="$(awk 'index($0,"::error title=CloudFormation drift verification failed::category=") == 1 {n++} END {print n+0}' "${file}")"
  assert_equals 1 "${exact}" "${expected} exact category";assert_equals 1 "${total}" "${expected} category count"
}
assert_no_category(){ local file="$1" total;total="$(awk 'index($0,"::error title=CloudFormation drift verification failed::category=") == 1 {n++} END {print n+0}' "${file}")";assert_equals 0 "${total}" 'unexpected category count'; }
assert_sleep_arguments(){
  local expected="$1" log="$2" expected_count="$3" actual_count
  actual_count="$(awk 'END {print NR+0}' "${log}")";assert_equals "${expected_count}" "${actual_count}" 'sleep argument count'
  awk -v expected="${expected}" 'NF != 1 || $1 != expected {bad=1} END {exit bad}' "${log}" || fail "unexpected sleep argument; expected ${expected}"
}
run_poll_case(){
  local name="$1" expected="$2" expected_status="$3" expected_sleep="$4" deadline_offset="${5:-60}"
  local dir="${test_root}/poll-${name}" output stdout stderr rc=0 detect_calls
  mkdir -p "${dir}";export RUNNER_TEMP="${dir}" SCENARIO="${name}" AWS_CALL_LOG="${dir}/calls.log" STATUS_COUNTER="${dir}/status.count" SLEEP_COUNTER="${dir}/sleep.count" SLEEP_ARGUMENT_LOG="${dir}/sleep.args"
  : >"${AWS_CALL_LOG}";: >"${SLEEP_ARGUMENT_LOG}";printf '0\n'>"${STATUS_COUNTER}";printf '0\n'>"${SLEEP_COUNTER}"
  export CFN_DRIFT_MAX_ATTEMPTS=3 CFN_DRIFT_DELAY_SECONDS=0 CFN_DRIFT_MAX_API_FAILURES=3 CFN_DRIFT_PHASE_TIMEOUT_SECONDS=60
  export CFN_DRIFT_DEADLINE_EPOCH="$(( $(date +%s) + deadline_offset ))"
  output="${RUNNER_TEMP}/drift-${REGION}-${STACK_NAME}.json";stdout="${dir}/stdout";stderr="${dir}/stderr"
  if detect_and_wait_for_cloudformation_stack_in_sync "${REGION}" "${STACK_NAME}" "${output}" "${ACCOUNT_ID}" >"${stdout}" 2>"${stderr}";then rc=0;else rc=$?;fi
  if [[ "${expected}" == success ]];then [[ "${rc}" == 0 ]]||fail "${name} failed";test -f "${output}"&&test ! -L "${output}";assert_equals 600 "$(stat -c '%a' "${output}")" "${name} mode";jq -e --arg id "${DETECTION_ID}" --arg stack "${STACK_ID}" --arg ts "${DETECTION_TIMESTAMP}" '.StackDriftDetectionId==$id and .StackId==$stack and .Timestamp==$ts and .DetectionStatus=="DETECTION_COMPLETE" and .StackDriftStatus=="IN_SYNC" and .DriftedStackResourceCount==0' "${output}">/dev/null;else [[ "${rc}" != 0 ]]||fail "${name} unexpectedly passed";[[ ! -e "${output}" ]]||fail "${name} published failure";fi
  detect_calls="$(awk '/cloudformation detect-stack-drift/{n++}END{print n+0}' "${AWS_CALL_LOG}")";assert_equals 1 "${detect_calls}" "${name} detect calls";assert_equals "${expected_status}" "$(<"${STATUS_COUNTER}")" "${name} status calls";assert_equals "${expected_sleep}" "$(<"${SLEEP_COUNTER}")" "${name} sleeps";assert_sleep_arguments 0 "${SLEEP_ARGUMENT_LOG}" "${expected_sleep}"
  grep -Fq 'PRIVATE_AWS_MARKER' "${stdout}" "${stderr}"&&fail "${name} leaked provider detail"
  find "${dir}" -maxdepth 1 -name 'cloudformation-drift-status.*' -print -quit|grep -q .&&fail "${name} left raw candidate"
  return 0
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
  local name="$1" expected="$2" expected_resource="$3" expected_final="$4" expected_sleep="$5" expected_category="${6:--}" deadline_offset="${7:-60}" expected_rc="${8:-}"
  local dir="${test_root}/resource-${name}" stdout stderr rc=0 resources finals sleeps active_detection_timestamp deadline detect_calls status_calls sleep_argument=0
  mkdir -p "${dir}";export RUNNER_TEMP="${dir}" SCENARIO="${name}" AWS_CALL_LOG="${dir}/calls.log" STATUS_COUNTER="${dir}/status.count" SLEEP_COUNTER="${dir}/sleep.count" SLEEP_ARGUMENT_LOG="${dir}/sleep.args" FINAL_COUNTER="${dir}/final.count"
  :>"${AWS_CALL_LOG}";:>"${SLEEP_ARGUMENT_LOG}";printf '0\n'>"${STATUS_COUNTER}";printf '0\n'>"${SLEEP_COUNTER}";printf '0\n'>"${FINAL_COUNTER}"
  active_detection_timestamp="${DETECTION_TIMESTAMP}"
  case "${name}" in
    subsecond-stale-resource) active_detection_timestamp="${SUBSECOND_DETECTION_TIMESTAMP}" ;;
    final-nonzero-equivalent) active_detection_timestamp="${NONZERO_DETECTION_TIMESTAMP}" ;;
    leap-day-success) active_detection_timestamp="${LEAP_TIMESTAMP}" ;;
    invalid-detection-calendar) active_detection_timestamp="${INVALID_DETECTION_TIMESTAMP}" ;;
  esac
  export ACTIVE_DETECTION_TIMESTAMP="${active_detection_timestamp}"
  export CFN_DRIFT_FINAL_BINDING_MAX_ATTEMPTS=3 CFN_DRIFT_FINAL_BINDING_DELAY_SECONDS=0 CFN_DRIFT_MAX_API_FAILURES=3
  case "${name}" in
    final-stale-default) unset CFN_DRIFT_FINAL_BINDING_MAX_ATTEMPTS CFN_DRIFT_FINAL_BINDING_DELAY_SECONDS;sleep_argument=2 ;;
    invalid-final-max) export CFN_DRIFT_FINAL_BINDING_MAX_ATTEMPTS=6 ;;
    invalid-final-delay) export CFN_DRIFT_FINAL_BINDING_DELAY_SECONDS=3 ;;
  esac
  deadline="$(( $(date +%s) + deadline_offset ))";stdout="${dir}/stdout";stderr="${dir}/stderr"
  if verify_cloudformation_stack_resource_drifts "${REGION}" "${STACK_NAME}" "${STACK_ID}" "${ACTIVE_DETECTION_TIMESTAMP}" "${ACCOUNT_ID}" "${deadline}" >"${stdout}" 2>"${stderr}";then rc=0;else rc=$?;fi
  if [[ "${expected}" == success ]];then
    assert_equals 0 "${rc}" "${name} result";assert_equals 1 "$(<"${stdout}")" "${name} count";assert_no_category "${stderr}"
  else
    [[ "${rc}" != 0 ]]||fail "${name} unexpectedly passed";test ! -s "${stdout}"||fail "${name} emitted failure stdout"
    [[ -z "${expected_rc}" ]]||assert_equals "${expected_rc}" "${rc}" "${name} rc"
    if [[ "${expected_category}" != - ]];then assert_category "${expected_category}" "${stderr}";fi
  fi
  resources="$(awk '/describe-stack-resource-drifts/{n++}END{print n+0}' "${AWS_CALL_LOG}")";finals="$(awk '/cloudformation describe-stacks/{n++}END{print n+0}' "${AWS_CALL_LOG}")";sleeps="$(<"${SLEEP_COUNTER}")"
  detect_calls="$(awk '/cloudformation detect-stack-drift/{n++}END{print n+0}' "${AWS_CALL_LOG}")";status_calls="$(awk '/describe-stack-drift-detection-status/{n++}END{print n+0}' "${AWS_CALL_LOG}")"
  assert_equals 0 "${detect_calls}" "${name} detect calls";assert_equals 0 "${status_calls}" "${name} status calls"
  assert_equals "${expected_resource}" "${resources}" "${name} resource calls";assert_equals "${expected_final}" "${finals}" "${name} final calls";assert_equals "${expected_sleep}" "${sleeps}" "${name} sleeps";assert_sleep_arguments "${sleep_argument}" "${SLEEP_ARGUMENT_LOG}" "${expected_sleep}"
  grep -Fq 'PRIVATE_AWS_MARKER' "${stdout}" "${stderr}"&&fail "${name} leaked provider detail"
  find "${dir}" -maxdepth 1 \( -name 'cloudformation-resource-drifts.*' -o -name 'cloudformation-final-stack.*' \) -print -quit|grep -q .&&fail "${name} left raw files"
  return 0
}
run_resource_case resource-success success 1 1 0
run_resource_case leap-day-success success 1 1 0
run_resource_case final-equivalent-utc success 1 1 0
run_resource_case final-nonzero-equivalent success 1 1 0
run_resource_case final-stale-then-current success 1 2 1
run_resource_case final-missing-then-current success 1 2 1
run_resource_case final-absent-drift-info-then-current success 1 2 1
run_resource_case final-not-checked-missing-then-current success 1 2 1
run_resource_case final-drifted-stale-then-current success 1 2 1
run_resource_case final-api-transient success 1 2 1
run_resource_case different-incarnation failure 1 0 0 resource-drift-stale-or-mismatched
run_resource_case stale-resource failure 1 0 0 resource-drift-stale-or-mismatched
run_resource_case subsecond-stale-resource failure 1 0 0 resource-drift-stale-or-mismatched
run_resource_case invalid-resource-calendar failure 1 0 0 resource-drift-stale-or-mismatched
run_resource_case not-checked-resource failure 1 0 0 resource-drift-stale-or-mismatched
run_resource_case invalid-detection-calendar failure 0 0 0 invalid-resource-input 60 64
run_resource_case invalid-final-max failure 0 0 0 invalid-final-binding-bounds 60 64
run_resource_case invalid-final-delay failure 0 0 0 invalid-final-binding-bounds 60 64
run_resource_case final-stale-default failure 1 5 4 final-stack-binding-stale
run_resource_case final-stale-persistent failure 1 3 2 final-stack-binding-stale
run_resource_case final-api-persistent failure 1 3 2 final-stack-api-error-or-timeout
run_resource_case final-timestamp-mismatch failure 1 1 0 final-stack-binding-mismatch
run_resource_case final-subsecond-mismatch failure 1 1 0 final-stack-binding-mismatch
run_resource_case final-different-incarnation failure 1 1 0 final-stack-binding-mismatch
run_resource_case final-drifted failure 1 1 0 final-stack-binding-mismatch
run_resource_case final-multiple-stacks failure 1 1 0 final-stack-binding-mismatch
run_resource_case final-invalid-calendar failure 1 1 0 final-stack-malformed-response
run_resource_case final-invalid-second failure 1 1 0 final-stack-malformed-response
run_resource_case final-invalid-fraction failure 1 1 0 final-stack-malformed-response
run_resource_case final-malformed failure 1 1 0 final-stack-malformed-response
run_resource_case final-oversize failure 1 1 0 final-stack-malformed-response
run_resource_case deadline-resource failure 1 0 0 resource-api-error-or-timeout 1
run_resource_case deadline-final failure 1 1 0 timeout 1
if bash "${helper}" >/dev/null 2>&1;then fail 'source-only helper allowed execution';fi
grep -Fq 'stack-drift-detection-complete' "${helper}"&&fail 'unsupported waiter remains'
echo 'CloudFormation drift polling and stack-incarnation tests passed'
