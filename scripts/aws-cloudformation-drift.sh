#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo '::error title=CloudFormation drift polling misuse::source-only helper' >&2
  exit 64
fi

cloudformation_drift_poll_error() {
  printf '::error title=CloudFormation drift verification failed::%s\n' "$1" >&2
}

cloudformation_drift_remaining_seconds() {
  local deadline_epoch="$1" now_epoch
  [[ "${deadline_epoch}" =~ ^[1-9][0-9]*$ ]] || return 64
  now_epoch="$(date +%s 2>/dev/null)" || return 1
  [[ "${now_epoch}" =~ ^[1-9][0-9]*$ ]] || return 1
  ((now_epoch < deadline_epoch)) || return 124
  printf '%s\n' "$((deadline_epoch - now_epoch))"
}

run_bounded_cloudformation_drift_aws() {
  local deadline_epoch="$1" remaining_seconds
  shift
  remaining_seconds="$(cloudformation_drift_remaining_seconds "${deadline_epoch}")" || return "$?"
  AWS_CLI_AUTO_PROMPT=off AWS_MAX_ATTEMPTS=1 AWS_PAGER='' AWS_RETRY_MODE=standard \
    timeout --foreground --signal=TERM --kill-after=2s "${remaining_seconds}s" \
    aws "$@"
}

cloudformation_drift_bounded_sleep() {
  local deadline_epoch="$1" requested_seconds="$2" remaining_seconds pause_seconds
  remaining_seconds="$(cloudformation_drift_remaining_seconds "${deadline_epoch}")" || return "$?"
  pause_seconds="${requested_seconds}"
  if ((pause_seconds > remaining_seconds)); then pause_seconds="${remaining_seconds}"; fi
  sleep "${pause_seconds}"
}

cloudformation_drift_utc_key() {
  if [[ "$#" -ne 1 ]]; then return 64; fi
  jq -ner --arg timestamp "$1" '
    def digits_number:
      sub("^0+"; "") | if . == "" then 0 else tonumber end;
    def leap_year($year):
      (($year % 4) == 0) and ((($year % 100) != 0) or (($year % 400) == 0));
    def month_days($year; $month):
      if $month == 2 then (if leap_year($year) then 29 else 28 end)
      elif ($month == 4 or $month == 6 or $month == 9 or $month == 11) then 30
      elif ($month >= 1 and $month <= 12) then 31
      else 0 end;
    def utc_key:
      if type != "string" then error("invalid timestamp") else
        sub("[+]00:00$"; "Z") |
        capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T" +
          "(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})" +
          "(?:\\.(?<fraction>[0-9]{1,9}))?Z$") |
        (.year | digits_number) as $year |
        (.month | digits_number) as $month |
        (.day | digits_number) as $day |
        (.hour | digits_number) as $hour |
        (.minute | digits_number) as $minute |
        (.second | digits_number) as $second |
        if ($year < 1 or $month < 1 or $month > 12 or $day < 1 or
          $day > month_days($year; $month) or $hour > 23 or
          $minute > 59 or $second > 59) then
          error("invalid timestamp")
        else
          .year + "-" + .month + "-" + .day + "T" + .hour + ":" +
          .minute + ":" + .second + "." +
          (((.fraction // "") + "000000000")[0:9])
        end
      end;
    $timestamp | utc_key
  ' 2>/dev/null
}

detect_and_wait_for_cloudformation_stack_in_sync() {
  if [[ "$#" -ne 4 ]]; then cloudformation_drift_poll_error 'category=invalid-input'; return 64; fi
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
    cloudformation_drift_poll_error 'category=invalid-input'; return 64
  fi
  if ((max_attempts > 120 || delay_seconds > 30 || max_api_failures > 3 ||
    max_api_failures > max_attempts || phase_timeout_seconds > 900)); then
    cloudformation_drift_poll_error 'category=invalid-bounds'; return 64
  fi
  if [[ -z "${RUNNER_TEMP:-}" ]] || [[ ! -d "${RUNNER_TEMP}" ]] ||
    [[ -L "${RUNNER_TEMP}" ]] ||
    [[ "${status_json}" != "${RUNNER_TEMP}/drift-${region}-${stack_name}.json" ]] ||
    [[ -e "${status_json}" ]] || [[ -L "${status_json}" ]]; then
    cloudformation_drift_poll_error 'category=invalid-output-boundary'; return 64
  fi
  if ! started_epoch="$(date +%s 2>/dev/null)" || [[ ! "${started_epoch}" =~ ^[1-9][0-9]*$ ]]; then
    cloudformation_drift_poll_error 'category=clock-error'; return 1
  fi
  deadline_epoch="${CFN_DRIFT_DEADLINE_EPOCH:-$((started_epoch + phase_timeout_seconds))}"
  if [[ ! "${deadline_epoch}" =~ ^[1-9][0-9]*$ ]] ||
    ((deadline_epoch <= started_epoch || deadline_epoch - started_epoch > phase_timeout_seconds)); then
    cloudformation_drift_poll_error 'category=invalid-deadline'; return 64
  fi
  if ! candidate="$(mktemp "${RUNNER_TEMP}/cloudformation-drift-status.XXXXXX.json")" ||
    [[ ! -f "${candidate}" ]] || [[ -L "${candidate}" ]]; then
    cloudformation_drift_poll_error 'category=staging-error'; return 1
  fi
  if ! chmod 0600 "${candidate}"; then
    rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=staging-error'; return 1
  fi
  if ! detection_id="$(run_bounded_cloudformation_drift_aws "${deadline_epoch}" \
    --cli-connect-timeout 5 --cli-read-timeout 15 --no-cli-pager \
    cloudformation detect-stack-drift --region "${region}" --stack-name "${stack_name}" \
    --query StackDriftDetectionId --output text 2>/dev/null)"; then
    rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=detect-api-error-or-timeout'; return 1
  fi
  if [[ ! "${detection_id}" =~ ^[A-Za-z0-9-]{1,36}$ ]] ||
    [[ "${detection_id}" == 'None' ]] || [[ "${detection_id}" == 'null' ]]; then
    rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=malformed-detection-id'; return 1
  fi
  expected_stack_prefix="arn:aws:cloudformation:${region}:${account_id}:stack/${stack_name}/"
  for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
    CFN_DRIFT_POLL_ATTEMPTS="${attempt}"
    if ! now_epoch="$(date +%s 2>/dev/null)" || [[ ! "${now_epoch}" =~ ^[1-9][0-9]*$ ]]; then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=clock-error'; return 1
    fi
    if ((now_epoch >= deadline_epoch)); then
      rm -f -- "${candidate}"; CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
      cloudformation_drift_poll_error 'category=timeout'; return 1
    fi
    if ! : >"${candidate}"; then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=staging-error'; return 1
    fi
    if ! run_bounded_cloudformation_drift_aws "${deadline_epoch}" \
      --cli-connect-timeout 5 --cli-read-timeout 15 --no-cli-pager \
      cloudformation describe-stack-drift-detection-status --region "${region}" \
      --stack-drift-detection-id "${detection_id}" --output json \
      >"${candidate}" 2>/dev/null; then
      consecutive_api_failures="$((consecutive_api_failures + 1))"
      if ((consecutive_api_failures >= max_api_failures || attempt == max_attempts)); then
        rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=status-api-error-or-timeout'; return 1
      fi
      if ! cloudformation_drift_bounded_sleep "${deadline_epoch}" "${delay_seconds}"; then
        rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
      fi
      continue
    fi
    if ! cloudformation_drift_remaining_seconds "${deadline_epoch}" >/dev/null; then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
    fi
    consecutive_api_failures=0
    if ! response_bytes="$(wc -c <"${candidate}")" || [[ ! "${response_bytes}" =~ ^[0-9]+$ ]] ||
      ((response_bytes == 0 || response_bytes > 65536)); then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=malformed-response'; return 1
    fi
    if ! jq -e --arg detectionId "${detection_id}" --arg stackPrefix "${expected_stack_prefix}" '
      type == "object" and .StackDriftDetectionId == $detectionId and
      (.StackId | (type == "string" and startswith($stackPrefix) and
        (ltrimstr($stackPrefix) | test("^[A-Za-z0-9-]+$")))) and
      (.Timestamp | (type == "string" and
        test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+]00:00)$"))) and
      (.DetectionStatus == "DETECTION_IN_PROGRESS" or
       .DetectionStatus == "DETECTION_COMPLETE" or .DetectionStatus == "DETECTION_FAILED")
    ' "${candidate}" >/dev/null 2>&1; then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=malformed-response'; return 1
    fi
    if ! detection_status="$(jq -er '.DetectionStatus' "${candidate}" 2>/dev/null)"; then
      rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=malformed-response'; return 1
    fi
    case "${detection_status}" in
      DETECTION_IN_PROGRESS)
        if ((attempt == max_attempts)); then
          rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
        fi
        if ! cloudformation_drift_bounded_sleep "${deadline_epoch}" "${delay_seconds}"; then
          rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
        fi ;;
      DETECTION_FAILED)
        rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=detection-failed'; return 1 ;;
      DETECTION_COMPLETE)
        if ! jq -e '.DetectionStatus == "DETECTION_COMPLETE" and .StackDriftStatus == "IN_SYNC" and
          (.DriftedStackResourceCount | (type == "number" and . == 0 and floor == .))' \
          "${candidate}" >/dev/null 2>&1; then
          rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=drifted-or-incomplete'; return 1
        fi
        if ! now_epoch="$(date +%s 2>/dev/null)" || [[ ! "${now_epoch}" =~ ^[1-9][0-9]*$ ]] ||
          ((now_epoch >= deadline_epoch)); then
          rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
        fi
        CFN_DRIFT_POLL_ELAPSED_SECONDS="$((now_epoch - started_epoch))"
        if ! mv -T -- "${candidate}" "${status_json}" || [[ ! -f "${status_json}" ]] || [[ -L "${status_json}" ]]; then
          rm -f -- "${candidate}" "${status_json}"; cloudformation_drift_poll_error 'category=publish-error'; return 1
        fi
        return 0 ;;
    esac
  done
  rm -f -- "${candidate}"; cloudformation_drift_poll_error 'category=timeout'; return 1
}

verify_cloudformation_stack_resource_drifts() (
  if [[ "$#" -ne 6 ]]; then cloudformation_drift_poll_error 'category=invalid-resource-invocation'; exit 64; fi
  local region="$1" stack_name="$2" exact_stack_id="$3" detection_timestamp="$4"
  local account_id="$5" deadline_epoch="$6" prefix suffix resource_json='' final_json=''
  local resource_bytes final_bytes checked_resource_count final_attempt final_state detection_utc_key
  local final_api_failures=0
  local final_max_attempts="${CFN_DRIFT_FINAL_BINDING_MAX_ATTEMPTS:-5}"
  local final_delay_seconds="${CFN_DRIFT_FINAL_BINDING_DELAY_SECONDS:-2}"
  local max_api_failures="${CFN_DRIFT_MAX_API_FAILURES:-3}"
  cleanup(){ rm -f -- "${resource_json}" "${final_json}"; }
  trap cleanup EXIT
  prefix="arn:aws:cloudformation:${region}:${account_id}:stack/${stack_name}/"
  if [[ ! "${region}" =~ ^(eu-west-1|us-east-1)$ ]] || [[ ! "${stack_name}" =~ ^[A-Za-z][A-Za-z0-9-]{0,127}$ ]] ||
    [[ ! "${account_id}" =~ ^[0-9]{12}$ ]] || [[ "${exact_stack_id}" != "${prefix}"* ]] ||
    [[ ! "${detection_timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|\+00:00)$ ]]; then
    cloudformation_drift_poll_error 'category=invalid-resource-input'; exit 64
  fi
  if ! detection_utc_key="$(cloudformation_drift_utc_key "${detection_timestamp}")"; then
    cloudformation_drift_poll_error 'category=invalid-resource-input'; exit 64
  fi
  suffix="${exact_stack_id:${#prefix}}"; [[ "${suffix}" =~ ^[A-Za-z0-9-]+$ ]] || exit 64
  if [[ ! "${final_max_attempts}" =~ ^[1-9][0-9]*$ ]] ||
    [[ ! "${final_delay_seconds}" =~ ^(0|[1-9][0-9]*)$ ]] ||
    [[ ! "${max_api_failures}" =~ ^[1-9][0-9]*$ ]] ||
    ((final_max_attempts > 5 || final_delay_seconds > 2 ||
      max_api_failures > 3 || max_api_failures > final_max_attempts)); then
    cloudformation_drift_poll_error 'category=invalid-final-binding-bounds'; exit 64
  fi
  resource_json="$(mktemp "${RUNNER_TEMP}/cloudformation-resource-drifts.XXXXXX.json")"
  final_json="$(mktemp "${RUNNER_TEMP}/cloudformation-final-stack.XXXXXX.json")"
  chmod 0600 "${resource_json}" "${final_json}"
  if ! run_bounded_cloudformation_drift_aws "${deadline_epoch}" --cli-connect-timeout 5 --cli-read-timeout 15 \
    --no-cli-pager cloudformation describe-stack-resource-drifts --region "${region}" \
    --stack-name "${exact_stack_id}" --output json >"${resource_json}" 2>/dev/null; then
    cloudformation_drift_poll_error 'category=resource-api-error-or-timeout'; exit 1
  fi
  if ! cloudformation_drift_remaining_seconds "${deadline_epoch}" >/dev/null; then
    cloudformation_drift_poll_error 'category=timeout'; exit 1
  fi
  resource_bytes="$(wc -c <"${resource_json}")"
  if [[ ! "${resource_bytes}" =~ ^[0-9]+$ ]] ||
    ((resource_bytes == 0 || resource_bytes > 1048576)); then
    cloudformation_drift_poll_error 'category=resource-malformed-response'; exit 1
  fi
  if ! jq -e --arg exactStackId "${exact_stack_id}" --arg detectionKey "${detection_utc_key}" '
    def digits_number:
      sub("^0+"; "") | if . == "" then 0 else tonumber end;
    def leap_year($year):
      (($year % 4) == 0) and ((($year % 100) != 0) or (($year % 400) == 0));
    def month_days($year; $month):
      if $month == 2 then (if leap_year($year) then 29 else 28 end)
      elif ($month == 4 or $month == 6 or $month == 9 or $month == 11) then 30
      elif ($month >= 1 and $month <= 12) then 31
      else 0 end;
    def utc_key:
      if type != "string" then error("invalid timestamp") else
        sub("[+]00:00$"; "Z") |
        capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T" +
          "(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})" +
          "(?:\\.(?<fraction>[0-9]{1,9}))?Z$") |
        (.year | digits_number) as $year |
        (.month | digits_number) as $month |
        (.day | digits_number) as $day |
        (.hour | digits_number) as $hour |
        (.minute | digits_number) as $minute |
        (.second | digits_number) as $second |
        if ($year < 1 or $month < 1 or $month > 12 or $day < 1 or
          $day > month_days($year; $month) or $hour > 23 or
          $minute > 59 or $second > 59) then error("invalid timestamp")
        else
          .year + "-" + .month + "-" + .day + "T" + .hour + ":" +
          .minute + ":" + .second + "." +
          (((.fraction // "") + "000000000")[0:9])
        end
      end;
    type == "object" and (.StackResourceDrifts | type) == "array" and
    all(.StackResourceDrifts[];
      .StackId == $exactStackId and .StackResourceDriftStatus == "IN_SYNC" and
      ((.Timestamp | utc_key) >= $detectionKey))
  ' "${resource_json}" >/dev/null 2>&1; then
    cloudformation_drift_poll_error 'category=resource-drift-stale-or-mismatched'; exit 1
  fi
  if ! checked_resource_count="$(jq -er '.StackResourceDrifts | length' "${resource_json}" 2>/dev/null)" ||
    [[ ! "${checked_resource_count}" =~ ^[0-9]+$ ]]; then
    cloudformation_drift_poll_error 'category=resource-malformed-response'; exit 1
  fi
  for ((final_attempt = 1; final_attempt <= final_max_attempts; final_attempt += 1)); do
    : >"${final_json}"
    if ! run_bounded_cloudformation_drift_aws "${deadline_epoch}" \
      --cli-connect-timeout 5 --cli-read-timeout 15 --no-cli-pager \
      cloudformation describe-stacks --region "${region}" \
      --stack-name "${exact_stack_id}" --output json \
      >"${final_json}" 2>/dev/null; then
      final_api_failures="$((final_api_failures + 1))"
      if ((final_api_failures >= max_api_failures ||
        final_attempt == final_max_attempts)); then
        cloudformation_drift_poll_error 'category=final-stack-api-error-or-timeout'; exit 1
      fi
      if ! cloudformation_drift_bounded_sleep \
        "${deadline_epoch}" "${final_delay_seconds}"; then
        cloudformation_drift_poll_error 'category=timeout'; exit 1
      fi
      continue
    fi
    final_api_failures=0
    if ! cloudformation_drift_remaining_seconds "${deadline_epoch}" >/dev/null; then`n      cloudformation_drift_poll_error 'category=timeout'; exit 1`n    fi
    final_bytes="$(wc -c <"${final_json}")"
    if [[ ! "${final_bytes}" =~ ^[0-9]+$ ]] ||
      ((final_bytes == 0 || final_bytes > 65536)); then
      cloudformation_drift_poll_error 'category=final-stack-malformed-response'; exit 1
    fi
    if ! final_state="$(jq -er \
      --arg exactStackId "${exact_stack_id}" \
      --arg detectionKey "${detection_utc_key}" '
        def digits_number:
          sub("^0+"; "") | if . == "" then 0 else tonumber end;
        def leap_year($year):
          (($year % 4) == 0) and ((($year % 100) != 0) or (($year % 400) == 0));
        def month_days($year; $month):
          if $month == 2 then (if leap_year($year) then 29 else 28 end)
          elif ($month == 4 or $month == 6 or $month == 9 or $month == 11) then 30
          elif ($month >= 1 and $month <= 12) then 31
          else 0 end;
        def utc_key:
          if type != "string" then error("invalid timestamp") else
            sub("[+]00:00$"; "Z") |
            capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T" +
              "(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})" +
              "(?:\\.(?<fraction>[0-9]{1,9}))?Z$") |
            (.year | digits_number) as $year |
            (.month | digits_number) as $month |
            (.day | digits_number) as $day |
            (.hour | digits_number) as $hour |
            (.minute | digits_number) as $minute |
            (.second | digits_number) as $second |
            if ($year < 1 or $month < 1 or $month > 12 or $day < 1 or
              $day > month_days($year; $month) or $hour > 23 or
              $minute > 59 or $second > 59) then error("invalid timestamp")
            else
              .year + "-" + .month + "-" + .day + "T" + .hour + ":" +
              .minute + ":" + .second + "." +
              (((.fraction // "") + "000000000")[0:9])
            end
          end;
        def valid_stack_drift_status:
          . == "DRIFTED" or . == "IN_SYNC" or . == "UNKNOWN" or . == "NOT_CHECKED";
        if type != "object" or (.Stacks | type) != "array" or
          (.Stacks | length) != 1 or (.Stacks[0].StackId | type) != "string" or
          .Stacks[0].StackId != $exactStackId then
          "mismatch"
        else
          .Stacks[0].DriftInformation as $drift |
          if $drift == null then "stale"
          elif ($drift | type) != "object" then error("invalid drift information")
          elif (($drift.StackDriftStatus | type) != "string") then error("invalid drift status")
          elif (($drift.StackDriftStatus | valid_stack_drift_status) | not) then error("invalid drift status")
          elif $drift.LastCheckTimestamp == null then "stale"
          else
            ($drift.LastCheckTimestamp | utc_key) as $actualKey |
            if $actualKey < $detectionKey then "stale"
            elif $actualKey > $detectionKey then "mismatch"
            elif $drift.StackDriftStatus == "IN_SYNC" then "match"
            else "mismatch" end
          end
        end
      ' "${final_json}" 2>/dev/null)"; then
      cloudformation_drift_poll_error 'category=final-stack-malformed-response'; exit 1
    fi
    case "${final_state}" in
      match) break ;;
      stale)
        if ((final_attempt == final_max_attempts)); then
          cloudformation_drift_poll_error 'category=final-stack-binding-stale'; exit 1
        fi
        if ! cloudformation_drift_bounded_sleep \
          "${deadline_epoch}" "${final_delay_seconds}"; then
          cloudformation_drift_poll_error 'category=timeout'; exit 1
        fi ;;
      mismatch)
        cloudformation_drift_poll_error 'category=final-stack-binding-mismatch'; exit 1 ;;
      *)
        cloudformation_drift_poll_error 'category=final-stack-malformed-response'; exit 1 ;;
    esac
  done
  if ! cloudformation_drift_remaining_seconds "${deadline_epoch}" >/dev/null; then`n    cloudformation_drift_poll_error 'category=timeout'; exit 1`n  fi
  printf '%s\n' "${checked_resource_count}"
)
