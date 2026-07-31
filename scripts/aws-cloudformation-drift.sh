#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo '::error title=CloudFormation drift polling misuse::source-only helper' >&2
  exit 64
fi

cloudformation_drift_poll_error() {
  printf '::error title=CloudFormation drift verification failed::%s\n' "$1" >&2
}

detect_and_wait_for_cloudformation_stack_in_sync() {
  if [[ "$#" -ne 4 ]]; then
    cloudformation_drift_poll_error 'category=invalid-input'
    return 64
  fi
  local region="$1" stack_name="$2" status_json="$3" account_id="$4"
  local max_attempts="${CFN_DRIFT_MAX_ATTEMPTS:-120}"
  local delay_seconds="${CFN_DRIFT_DELAY_SECONDS:-2}"
  local max_api_failures="${CFN_DRIFT_MAX_API_FAILURES:-3}"
  local phase_timeout_seconds="${CFN_DRIFT_PHASE_TIMEOUT_SECONDS:-900}"
  local started_epoch deadline_epoch now_epoch response_bytes expected_stack_prefix
  local detection_id detection_status candidate='' attempt consecutive_api_failures=0
  CFN_DRIFT_POLL_ATTEMPTS=0
  CFN_DRIFT_POLL_ELAPSED_SECONDS=0

  if [[ ! "${region}" =~ ^(eu-west-1|us-east-1)$ ]] ||
    [[ ! "${stack_name}" =~ ^[A-Za-z][A-Za-z0-9-]{0,127}$ ]] ||
    [[ ! "${account_id}" =~ ^[0-9]{12}$ ]] ||
    [[ ! "${max_attempts}" =~ ^[1-9][0-9]*$ ]] ||
    [[ ! "${delay_seconds}" =~ ^(0|[1-9][0-9]*)$ ]] ||
    [[ ! "${max_api_failures}" =~ ^[1-9][0-9]*$ ]] ||
    [[ ! "${phase_timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
    cloudformation_drift_poll_error 'category=invalid-input'
    return 64
  fi
  if ((max_attempts > 120 || delay_seconds > 30 || max_api_failures > 3 ||
    max_api_failures > max_attempts || phase_timeout_seconds > 900)); then
    cloudformation_drift_poll_error 'category=invalid-bounds'
    return 64
  fi
  if [[ -z "${RUNNER_TEMP:-}" ]] || [[ ! -d "${RUNNER_TEMP}" ]] ||
    [[ -L "${RUNNER_TEMP}" ]] ||
    [[ "${status_json}" != "${RUNNER_TEMP}/drift-${region}-${stack_name}.json" ]] ||
    [[ -e "${status_json}" ]] || [[ -L "${status_json}" ]]; then
    cloudformation_drift_poll_error 'category=invalid-output-boundary'
    return 64
  fi

  if ! started_epoch="$(date +%s 2>/dev/null)" ||
    [[ ! "${started_epoch}" =~ ^[1-9][0-9]*$ ]]; then
    cloudformation_drift_poll_error 'category=clock-error'
    return 1
  fi
  deadline_epoch="${CFN_DRIFT_DEADLINE_EPOCH:-$((started_epoch + phase_timeout_seconds))}"
  if [[ ! "${deadline_epoch}" =~ ^[1-9][0-9]*$ ]] ||
    ((deadline_epoch <= started_epoch || deadline_epoch - started_epoch > phase_timeout_seconds)); then
    cloudformation_drift_poll_error 'category=invalid-deadline'
    return 64
  fi

  if ! candidate="$(mktemp "${RUNNER_TEMP}/cloudformation-drift-status.XXXXXX.json")" ||
    [[ ! -f "${candidate}" ]] || [[ -L "${candidate}" ]]; then
    cloudformation_drift_poll_error 'category=staging-error'
    return 1
  fi
  chmod 0600 "${candidate}"
  if ! detection_id="$(
    aws --cli-connect-timeout 5 --cli-read-timeout 15 --no-cli-pager \
      cloudformation detect-stack-drift --region "${region}" \
      --stack-name "${stack_name}" --query StackDriftDetectionId \
      --output text 2>/dev/null
  )"; then
    rm -f -- "${candidate}"
    cloudformation_drift_poll_error 'category=detect-api-error'
    return 1
  fi
  if [[ ! "${detection_id}" =~ ^[A-Za-z0-9-]{1,36}$ ]] ||
    [[ "${detection_id}" == 'None' ]] || [[ "${detection_id}" == 'null' ]]; then
    rm -f -- "${candidate}"
    cloudformation_drift_poll_error 'category=malformed-detection-id'
    return 1
  fi
  expected_stack_prefix="arn:aws:cloudformation:${region}:${account_id}:stack/${stack_name}/"

  for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
    CFN_DRIFT_POLL_ATTEMPTS="${attempt}"
    if ! now_epoch="$(date +%s 2>/dev/null)" ||
      [[ ! "${now_epoch}" =~ ^[1-9][0-9]*$ ]]; then
      rm -f -- "${candidate}"
      cloudformation_drift_poll_error 'category=clock-error'
      return 1
    fi
    if ((now_epoch >= deadline_epoch)); then
      rm -f -- "${candidate}"
      CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
      cloudformation_drift_poll_error 'category=timeout'
      return 1
    fi
    : >"${candidate}"
    if ! aws --cli-connect-timeout 5 --cli-read-timeout 15 --no-cli-pager \
      cloudformation describe-stack-drift-detection-status --region "${region}" \
      --stack-drift-detection-id "${detection_id}" --output json \
      >"${candidate}" 2>/dev/null; then
      consecutive_api_failures="$((consecutive_api_failures + 1))"
      if ((consecutive_api_failures >= max_api_failures || attempt == max_attempts)); then
        rm -f -- "${candidate}"
        CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
        cloudformation_drift_poll_error 'category=status-api-error'
        return 1
      fi
      sleep "${delay_seconds}"
      continue
    fi
    consecutive_api_failures=0
    if ! response_bytes="$(wc -c <"${candidate}")" ||
      [[ ! "${response_bytes}" =~ ^[0-9]+$ ]] ||
      ((response_bytes == 0 || response_bytes > 65536)); then
      rm -f -- "${candidate}"
      cloudformation_drift_poll_error 'category=malformed-response'
      return 1
    fi
    if ! jq -e --arg detectionId "${detection_id}" \
      --arg stackPrefix "${expected_stack_prefix}" '
        type == "object" and
        .StackDriftDetectionId == $detectionId and
        (.StackId | (type == "string" and startswith($stackPrefix))) and
        (.DetectionStatus == "DETECTION_IN_PROGRESS" or
         .DetectionStatus == "DETECTION_COMPLETE" or
         .DetectionStatus == "DETECTION_FAILED")
      ' "${candidate}" >/dev/null 2>&1; then
      rm -f -- "${candidate}"
      cloudformation_drift_poll_error 'category=malformed-response'
      return 1
    fi
    if ! detection_status="$(jq -er '.DetectionStatus' "${candidate}" 2>/dev/null)"; then
      rm -f -- "${candidate}"
      cloudformation_drift_poll_error 'category=malformed-response'
      return 1
    fi
    case "${detection_status}" in
      DETECTION_IN_PROGRESS)
        if ((attempt == max_attempts)); then
          rm -f -- "${candidate}"
          CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
          cloudformation_drift_poll_error 'category=timeout'
          return 1
        fi
        sleep "${delay_seconds}"
        ;;
      DETECTION_FAILED)
        rm -f -- "${candidate}"
        CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
        cloudformation_drift_poll_error 'category=detection-failed'
        return 1
        ;;
      DETECTION_COMPLETE)
        if ! jq -e '
          .DetectionStatus == "DETECTION_COMPLETE" and
          .StackDriftStatus == "IN_SYNC" and
          (.DriftedStackResourceCount | (type == "number" and . == 0 and floor == .))
        ' "${candidate}" >/dev/null 2>&1; then
          rm -f -- "${candidate}"
          CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
          cloudformation_drift_poll_error 'category=drifted-or-incomplete'
          return 1
        fi
        if ! now_epoch="$(date +%s 2>/dev/null)" ||
          [[ ! "${now_epoch}" =~ ^[1-9][0-9]*$ ]]; then
          rm -f -- "${candidate}"
          cloudformation_drift_poll_error 'category=clock-error'
          return 1
        fi
        CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
        if ! mv -T -- "${candidate}" "${status_json}" ||
          [[ ! -f "${status_json}" ]] || [[ -L "${status_json}" ]]; then
          rm -f -- "${candidate}" "${status_json}"
          cloudformation_drift_poll_error 'category=publish-error'
          return 1
        fi
        return 0
        ;;
    esac
  done
  rm -f -- "${candidate}"
  cloudformation_drift_poll_error 'category=timeout'
  return 1
}