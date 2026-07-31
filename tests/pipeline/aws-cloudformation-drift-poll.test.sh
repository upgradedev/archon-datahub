#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="${repository_root}/scripts/aws-cloudformation-drift.sh"
test -f "${helper}" && test ! -L "${helper}"
# shellcheck source=scripts/aws-cloudformation-drift.sh
source "${helper}"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT
readonly DETECTION_ID='11111111-2222-3333-4444-555555555555'
readonly ACCOUNT_ID='123456789012'
readonly REGION='eu-west-1'
readonly STACK_NAME='Archon-Test-Stack'
readonly STACK_ID="arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/${STACK_NAME}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
scenario='';status_calls=0;sleep_calls=0;AWS_CALL_LOG=''
fail(){ echo "::error::$*" >&2; exit 1; }
assert_equals(){ [[ "$2" == "$1" ]] || fail "$3: expected $1, got $2"; }
sleep(){ sleep_calls="$((sleep_calls + 1))"; return 0; }
aws() {
  local joined=" $* "
  printf '%s\n' "$*" >>"${AWS_CALL_LOG}"
  [[ "${joined}" == *' --cli-connect-timeout 5 '* ]] || return 97
  [[ "${joined}" == *' --cli-read-timeout 15 '* ]] || return 97
  [[ "${joined}" == *' --no-cli-pager '* ]] || return 97
  [[ "${joined}" == *" --region ${REGION} "* ]] || return 97
  if [[ "${joined}" == *' cloudformation detect-stack-drift '* ]]; then
    [[ "${joined}" == *" --stack-name ${STACK_NAME} "* ]] || return 97
    [[ "${joined}" == *' --query StackDriftDetectionId '* ]] || return 97
    [[ "${joined}" == *' --output text '* ]] || return 97
    if [[ "${scenario}" == 'invalid-detection-id' ]]; then printf 'None\n'; else printf '%s\n' "${DETECTION_ID}"; fi
    return 0
  fi
  [[ "${joined}" == *' cloudformation describe-stack-drift-detection-status '* ]] || return 97
  [[ "${joined}" == *" --stack-drift-detection-id ${DETECTION_ID} "* ]] || return 97
  [[ "${joined}" == *' --output json '* ]] || return 97
  status_calls="$((status_calls + 1))"
  case "${scenario}" in
    progress-success)
      if ((status_calls == 1)); then
        printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"NOT_CHECKED","DetectionStatus":"DETECTION_IN_PROGRESS","DriftedStackResourceCount":null}\n' "${STACK_ID}" "${DETECTION_ID}"
      else
        printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}"
      fi ;;
    immediate-success)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    transient-success)
      if ((status_calls == 1)); then echo 'PRIVATE_AWS_MARKER transient provider error' >&2; return 1; fi
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    persistent-error) echo 'PRIVATE_AWS_MARKER persistent provider error' >&2; return 1 ;;
    perpetual-progress)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"NOT_CHECKED","DetectionStatus":"DETECTION_IN_PROGRESS","DriftedStackResourceCount":null}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    detection-failed)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"UNKNOWN","DetectionStatus":"DETECTION_FAILED","DetectionStatusReason":"PRIVATE_AWS_MARKER"}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    drifted)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"DRIFTED","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":1}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    missing-count)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE"}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    wrong-detection-id)
      printf '{"StackId":"%s","StackDriftDetectionId":"00000000-0000-0000-0000-000000000000","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${STACK_ID}" ;;
    wrong-stack-id)
      printf '{"StackId":"arn:aws:cloudformation:eu-west-1:123456789012:stack/Other-Stack/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"DETECTION_COMPLETE","DriftedStackResourceCount":0}\n' "${DETECTION_ID}" ;;
    malformed) printf '{not-json\n' ;;
    unknown-status)
      printf '{"StackId":"%s","StackDriftDetectionId":"%s","StackDriftStatus":"IN_SYNC","DetectionStatus":"SURPRISE","DriftedStackResourceCount":0}\n' "${STACK_ID}" "${DETECTION_ID}" ;;
    *) return 98 ;;
  esac
}
run_case() {
  local case_name="$1" expected_result="$2" expected_status_calls="$3" expected_sleeps="$4"
  local case_dir="${test_root}/${case_name}" output_path stdout_path stderr_path rc=0 detect_calls described_calls
  mkdir -p "${case_dir}";export RUNNER_TEMP="${case_dir}"
  export CFN_DRIFT_MAX_ATTEMPTS=3 CFN_DRIFT_DELAY_SECONDS=0 CFN_DRIFT_MAX_API_FAILURES=3 CFN_DRIFT_PHASE_TIMEOUT_SECONDS=60
  export CFN_DRIFT_DEADLINE_EPOCH="$(( $(date +%s) + 60 ))"
  scenario="${case_name}";status_calls=0;sleep_calls=0;AWS_CALL_LOG="${case_dir}/aws-calls.log";: >"${AWS_CALL_LOG}"
  output_path="${RUNNER_TEMP}/drift-${REGION}-${STACK_NAME}.json";stdout_path="${case_dir}/stdout.log";stderr_path="${case_dir}/stderr.log"
  if detect_and_wait_for_cloudformation_stack_in_sync "${REGION}" "${STACK_NAME}" "${output_path}" "${ACCOUNT_ID}" >"${stdout_path}" 2>"${stderr_path}"; then rc=0; else rc="$?"; fi
  if [[ "${expected_result}" == success ]]; then
    assert_equals 0 "${rc}" "${case_name} return code"
    test -f "${output_path}" && test ! -L "${output_path}" || fail "${case_name} missing terminal status"
    assert_equals 600 "$(stat -c '%a' "${output_path}")" "${case_name} status mode"
    jq -e --arg detectionId "${DETECTION_ID}" --arg stackId "${STACK_ID}" '
      .StackDriftDetectionId == $detectionId and .StackId == $stackId and
      .DetectionStatus == "DETECTION_COMPLETE" and .StackDriftStatus == "IN_SYNC" and
      .DriftedStackResourceCount == 0' "${output_path}" >/dev/null
  else
    [[ "${rc}" -ne 0 ]] || fail "${case_name} unexpectedly succeeded"
    [[ ! -e "${output_path}" ]] || fail "${case_name} published failure state"
  fi
  detect_calls="$(awk '/cloudformation detect-stack-drift/{n+=1} END{print n+0}' "${AWS_CALL_LOG}")"
  described_calls="$(awk '/cloudformation describe-stack-drift-detection-status/{n+=1} END{print n+0}' "${AWS_CALL_LOG}")"
  assert_equals 1 "${detect_calls}" "${case_name} detect call count"
  assert_equals "${expected_status_calls}" "${described_calls}" "${case_name} status call count"
  assert_equals "${expected_sleeps}" "${sleep_calls}" "${case_name} sleep count"
  grep -Fq 'PRIVATE_AWS_MARKER' "${stdout_path}" "${stderr_path}" && fail "${case_name} exposed raw provider content"
  grep -Fq "${DETECTION_ID}" "${stdout_path}" "${stderr_path}" && fail "${case_name} exposed detection identifier"
  grep -Fq 'stack-drift-detection-complete' "${AWS_CALL_LOG}" && fail "${case_name} invoked unsupported waiter"
  return 0
}
run_case progress-success success 2 1
run_case immediate-success success 1 0
run_case transient-success success 2 1
run_case persistent-error failure 3 2
run_case perpetual-progress failure 3 2
run_case detection-failed failure 1 0
run_case drifted failure 1 0
run_case missing-count failure 1 0
run_case wrong-detection-id failure 1 0
run_case wrong-stack-id failure 1 0
run_case malformed failure 1 0
run_case unknown-status failure 1 0
run_case invalid-detection-id failure 0 0
input_case_dir="${test_root}/invalid-inputs";mkdir -p "${input_case_dir}";export RUNNER_TEMP="${input_case_dir}"
export CFN_DRIFT_DEADLINE_EPOCH="$(( $(date +%s) + 60 ))";AWS_CALL_LOG="${input_case_dir}/aws-calls.log";: >"${AWS_CALL_LOG}"
if detect_and_wait_for_cloudformation_stack_in_sync ap-south-1 "${STACK_NAME}" "${RUNNER_TEMP}/drift-ap-south-1-${STACK_NAME}.json" "${ACCOUNT_ID}" >/dev/null 2>&1; then fail 'invalid region was accepted'; fi
if detect_and_wait_for_cloudformation_stack_in_sync "${REGION}" '../unsafe' "${RUNNER_TEMP}/drift-${REGION}-../unsafe.json" "${ACCOUNT_ID}" >/dev/null 2>&1; then fail 'unsafe stack name was accepted'; fi
if detect_and_wait_for_cloudformation_stack_in_sync "${REGION}" "${STACK_NAME}" "${test_root}/outside.json" "${ACCOUNT_ID}" >/dev/null 2>&1; then fail 'outside output was accepted'; fi
test ! -s "${AWS_CALL_LOG}" || fail 'invalid inputs reached AWS'
if bash "${helper}" >"${test_root}/direct.out" 2>"${test_root}/direct.err"; then fail 'source-only helper allowed direct execution'; fi
grep -Fq 'stack-drift-detection-complete' "${helper}" && fail 'helper contains unsupported waiter'
echo 'CloudFormation drift polling behavior tests passed'