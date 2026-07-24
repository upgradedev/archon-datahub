#!/usr/bin/env bash
set -euo pipefail

# CI/CD-only, read-only observer for the exact production runtime bytes.
# Observer mode (default) derives the canonical manifest entirely from AWS.
# Deploy verification mode additionally compares those bytes with the exact CI
# candidates already downloaded and verified by deploy.yml.

: "${AWS_REGION:?AWS_REGION is required}"
: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${STACK_NAME:?STACK_NAME is required}"
: "${OUTPUT_PATH:?OUTPUT_PATH is required}"

VERIFY_LOCAL_CANDIDATES="${VERIFY_LOCAL_CANDIDATES:-false}"
MAX_SPA_VERSION_RECORDS=20000
MAX_SPA_LATEST_STATES=8192
MAX_SPA_LIVE_OBJECTS=4096
MAX_SPA_TOTAL_BYTES=536870912
ECS_SNAPSHOT_ATTEMPTS=3
ECS_SNAPSHOT_BACKOFF_SECONDS=5
if [[ "${VERIFY_LOCAL_CANDIDATES}" != "true" &&
      "${VERIFY_LOCAL_CANDIDATES}" != "false" ]]; then
  echo "::error::VERIFY_LOCAL_CANDIDATES must be true or false"
  exit 1
fi
[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]
[[ "${AWS_REGION}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]
test "${STACK_NAME}" = "Archon-production"

if [[ "${VERIFY_LOCAL_CANDIDATES}" == "true" ]]; then
  : "${RELEASE_SHA:?RELEASE_SHA is required in deploy verification mode}"
  : "${EXPECTED_IMAGE_DIGEST:?EXPECTED_IMAGE_DIGEST is required}"
  : "${EXPECTED_CONTAINER_ARCHIVE_SHA256:?EXPECTED_CONTAINER_ARCHIVE_SHA256 is required}"
  : "${EXPECTED_LAMBDA_ARCHIVE_SHA256:?EXPECTED_LAMBDA_ARCHIVE_SHA256 is required}"
  : "${EXPECTED_WEB_ARCHIVE_SHA256:?EXPECTED_WEB_ARCHIVE_SHA256 is required}"
  : "${EXPECTED_RUNTIME_CONFIG_SHA256:?EXPECTED_RUNTIME_CONFIG_SHA256 is required}"
  : "${WEB_DIR:?WEB_DIR is required in deploy verification mode}"
  : "${LAMBDA_DIR:?LAMBDA_DIR is required in deploy verification mode}"
  : "${RUNTIME_CONFIG:?RUNTIME_CONFIG is required in deploy verification mode}"
fi

umask 077
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-live-runtime.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
[[ "${OUTPUT_PATH}" == /* ]]
test "$(basename "${OUTPUT_PATH}")" = "live-runtime-manifest.json"
mkdir -p "$(dirname "${OUTPUT_PATH}")"
test ! -L "${OUTPUT_PATH}"
if [[ -e "${OUTPUT_PATH}" ]]; then
  test -f "${OUTPUT_PATH}"
  rm -- "${OUTPUT_PATH}"
fi

sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

read_stack() {
  local destination="$1"
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${STACK_NAME}" \
    --output json >"${destination}"
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg region "${AWS_REGION}" \
    --arg stack "${STACK_NAME}" '
      (.Stacks | type == "array" and length == 1) and
      .Stacks[0].StackName == $stack and
      (
        .Stacks[0].StackStatus == "CREATE_COMPLETE" or
        .Stacks[0].StackStatus == "UPDATE_COMPLETE"
      ) and
      (.Stacks[0].StackId |
        test(
          "^arn:aws[^:]*:cloudformation:" + $region + ":" + $account +
          ":stack/" + $stack + "/[0-9a-f-]+$"
        )) and
      ((.Stacks[0].Outputs // []) | type == "array") and
      (
        [
          (.Stacks[0].Outputs // [])[] |
          .OutputKey
        ] as $keys |
        ($keys | length) == ($keys | unique | length)
      )
    ' "${destination}" >/dev/null
}

stack_initial="${work_dir}/stack-initial.json"
read_stack "${stack_initial}"
stack_state_initial="$(
  jq -cS '
    .Stacks[0] |
    {
      stackId: .StackId,
      stackName: .StackName,
      stackStatus: .StackStatus,
      generation: (.LastUpdatedTime // .CreationTime),
      outputs: (
        (.Outputs // []) |
        map({key: .OutputKey, value: .OutputValue}) |
        sort_by(.key)
      )
    }
  ' "${stack_initial}"
)"
stack_outputs="$(
  jq -cS '
    (.Stacks[0].Outputs // []) |
    map({key: .OutputKey, value: .OutputValue}) |
    from_entries
  ' "${stack_initial}"
)"

required_outputs=(
  ArchonReleaseSha
  ArchonContainerImageDigest
  ArchonContainerArchiveSha256
  ArchonLambdaArchiveSha256
  ArchonSpaArtifactSha256
  ArchonEcsClusterName
  ArchonApiServiceName
  ArchonAuditWorkerServiceName
  ArchonRemediationWorkerServiceName
  ArchonSpaBucketName
  ArchonSpaKeyArn
)
for output_name in "${required_outputs[@]}"; do
  jq -e --arg key "${output_name}" '
    has($key) and
    (.[$key] | type == "string" and length > 0)
  ' <<<"${stack_outputs}" >/dev/null || {
    echo "::error::Missing production stack output ${output_name}"
    exit 1
  }
done

live_release_sha="$(jq -er '.ArchonReleaseSha' <<<"${stack_outputs}")"
live_image_digest="$(
  jq -er '.ArchonContainerImageDigest' <<<"${stack_outputs}"
)"
live_container_archive="$(
  jq -er '.ArchonContainerArchiveSha256' <<<"${stack_outputs}"
)"
live_lambda_archive="$(
  jq -er '.ArchonLambdaArchiveSha256' <<<"${stack_outputs}"
)"
live_web_archive="$(
  jq -er '.ArchonSpaArtifactSha256' <<<"${stack_outputs}"
)"
[[ "${live_release_sha}" =~ ^[0-9a-f]{40}$ ]]
[[ "${live_image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
for digest in \
  "${live_container_archive}" \
  "${live_lambda_archive}" \
  "${live_web_archive}"; do
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]
done

if [[ -n "${RELEASE_SHA:-}" ]]; then
  test "${live_release_sha}" = "${RELEASE_SHA}"
fi
if [[ -n "${EXPECTED_IMAGE_DIGEST:-}" ]]; then
  test "${live_image_digest}" = "${EXPECTED_IMAGE_DIGEST}"
fi
if [[ -n "${EXPECTED_CONTAINER_ARCHIVE_SHA256:-}" ]]; then
  test "${live_container_archive}" = \
    "${EXPECTED_CONTAINER_ARCHIVE_SHA256}"
fi
if [[ -n "${EXPECTED_LAMBDA_ARCHIVE_SHA256:-}" ]]; then
  test "${live_lambda_archive}" = "${EXPECTED_LAMBDA_ARCHIVE_SHA256}"
fi
if [[ -n "${EXPECTED_WEB_ARCHIVE_SHA256:-}" ]]; then
  test "${live_web_archive}" = "${EXPECTED_WEB_ARCHIVE_SHA256}"
fi

cluster_name="$(jq -er '.ArchonEcsClusterName' <<<"${stack_outputs}")"
api_service="$(jq -er '.ArchonApiServiceName' <<<"${stack_outputs}")"
audit_service="$(
  jq -er '.ArchonAuditWorkerServiceName' <<<"${stack_outputs}"
)"
remediation_service="$(
  jq -er '.ArchonRemediationWorkerServiceName' <<<"${stack_outputs}"
)"

observe_ecs_once() {
  local manifest_path="$1"
  local snapshot_dir="$2"
  local services_json service_entries
  services_json="$(
    aws ecs describe-services \
      --region "${AWS_REGION}" \
      --cluster "${cluster_name}" \
      --services \
        "${api_service}" \
        "${audit_service}" \
        "${remediation_service}" \
      --output json
  )"
  jq -e '
    (.failures | length) == 0 and
    (.services | length) == 3
  ' <<<"${services_json}" >/dev/null

  service_entries="${snapshot_dir}/ecs-services.ndjson"
  : >"${service_entries}"
  while IFS='|' read -r role service_name; do
    service_json="$(
      jq -cer --arg name "${service_name}" '
        [.services[] | select(.serviceName == $name)] |
        if length == 1 then .[0]
        else error("expected one exact ECS service")
        end
      ' <<<"${services_json}"
    )"
    jq -e '
      .status == "ACTIVE" and
      .schedulingStrategy == "REPLICA" and
      .desiredCount > 0 and
      .runningCount == .desiredCount and
      .pendingCount == 0 and
      (.deployments | length) == 1 and
      .deployments[0].status == "PRIMARY" and
      .deployments[0].rolloutState == "COMPLETED" and
      .deployments[0].desiredCount == .desiredCount and
      .deployments[0].runningCount == .desiredCount and
      .deployments[0].pendingCount == 0
    ' <<<"${service_json}" >/dev/null || {
      echo "::error::${role} ECS service is not a single stable PRIMARY deployment"
      exit 1
    }
    task_definition_arn="$(jq -er '.taskDefinition' <<<"${service_json}")"
    test "${task_definition_arn}" = "$(
      jq -er '.deployments[0].taskDefinition' <<<"${service_json}"
    )"

    task_definition_json="$(
      aws ecs describe-task-definition \
        --region "${AWS_REGION}" \
        --task-definition "${task_definition_arn}" \
        --output json
    )"
    jq -e --arg digest "${live_image_digest}" '
      .taskDefinition.status == "ACTIVE" and
      (.taskDefinition.containerDefinitions | length) > 0 and
      all(
        .taskDefinition.containerDefinitions[];
        (.image | type == "string") and
        endswith("@" + $digest)
      )
    ' <<<"${task_definition_json}" >/dev/null || {
      echo "::error::${role} task definition does not reference the production image digest"
      exit 1
    }
    # Hash the exact image URI without retaining the account-qualified URI.
    task_definition_containers="$(
      printf '%s' "${snapshot_dir}/task-definition-${role}.ndjson"
    )"
    : >"${task_definition_containers}"
    while IFS=$'\t' read -r container_name image_reference; do
      jq -cnS \
        --arg name "${container_name}" \
        --arg imageDigest "${live_image_digest}" \
        --arg imageReferenceSha256 "$(sha256_text "${image_reference}")" '
          {
            name: $name,
            imageDigest: $imageDigest,
            imageReferenceSha256: $imageReferenceSha256
          }
        ' >>"${task_definition_containers}"
    done < <(
      jq -r '
        .taskDefinition.containerDefinitions |
        sort_by(.name)[] |
        [.name, .image] |
        @tsv
      ' <<<"${task_definition_json}"
    )
    task_definition_container_json="$(
      jq -cSs 'sort_by(.name)' "${task_definition_containers}"
    )"

    task_list_json="$(
      aws ecs list-tasks \
        --region "${AWS_REGION}" \
        --cluster "${cluster_name}" \
        --service-name "${service_name}" \
        --desired-status RUNNING \
        --output json
    )"
    jq -e --argjson desired "$(jq -er '.desiredCount' <<<"${service_json}")" '
      ((.nextToken // "") == "") and
      (.taskArns | length) == $desired and
      $desired > 0
    ' <<<"${task_list_json}" >/dev/null
    mapfile -t task_arns < <(jq -er '.taskArns[]' <<<"${task_list_json}")
    tasks_json="$(
      aws ecs describe-tasks \
        --region "${AWS_REGION}" \
        --cluster "${cluster_name}" \
        --tasks "${task_arns[@]}" \
        --output json
    )"
    jq -e \
      --arg digest "${live_image_digest}" \
      --arg taskDefinition "${task_definition_arn}" \
      --argjson expectedCount "${#task_arns[@]}" '
        (.failures | length) == 0 and
        (.tasks | length) == $expectedCount and
        all(
          .tasks[];
          .lastStatus == "RUNNING" and
          .taskDefinitionArn == $taskDefinition and
          (.containers | length) > 0 and
          all(
            .containers[];
            .lastStatus == "RUNNING" and
            .imageDigest == $digest
          )
        )
      ' <<<"${tasks_json}" >/dev/null || {
        echo "::error::${role} has a running task outside the exact image digest"
        exit 1
      }
    running_digests="$(
      jq -cS '[.tasks[].containers[].imageDigest] | unique' <<<"${tasks_json}"
    )"
    test "${running_digests}" = "$(jq -cn --arg digest "${live_image_digest}" '[$digest]')"

    jq -cnS \
      --arg role "${role}" \
      --arg name "${service_name}" \
      --arg taskDefinitionArn "${task_definition_arn}" \
      --argjson containers "${task_definition_container_json}" \
      --argjson runningImageDigests "${running_digests}" '
        {
          role: $role,
          name: $name,
          primaryDeployment: {
            taskDefinitionArn: $taskDefinitionArn
          },
          taskDefinition: {
            containers: $containers
          },
          runningImageDigests: $runningImageDigests
        }
      ' >>"${service_entries}"

  done <<EOF
api|${api_service}
audit-worker|${audit_service}
remediation-worker|${remediation_service}
EOF

  jq -cSs 'sort_by(.role)' "${service_entries}" >"${manifest_path}"
}

observe_ecs() {
  local manifest_path="$1"
  local attempt=1
  local attempt_status
  local backoff_seconds
  local snapshot_dir
  local attempt_manifest
  local attempt_log

  rm -f -- "${manifest_path}"
  while (( attempt <= ECS_SNAPSHOT_ATTEMPTS )); do
    snapshot_dir="${work_dir}/ecs-snapshot-${attempt}"
    case "${snapshot_dir}" in
      "${work_dir}"/ecs-snapshot-[1-3]) ;;
      *)
        echo "::error::Refusing an unsafe ECS snapshot path"
        return 1
        ;;
    esac
    rm -rf -- "${snapshot_dir}"
    mkdir -p "${snapshot_dir}"
    attempt_manifest="${snapshot_dir}/manifest.json"
    attempt_log="${snapshot_dir}/attempt.stderr"

    # Run each complete snapshot in its own errexit-enabled subshell. The
    # parent temporarily captures only the exit status; no partial service,
    # task-definition, or task observation can flow into another attempt.
    set +e
    (
      set -euo pipefail
      observe_ecs_once "${attempt_manifest}" "${snapshot_dir}"
      test -s "${attempt_manifest}"
    ) 2>"${attempt_log}"
    attempt_status=$?
    set -e

    if (( attempt_status == 0 )); then
      mv -- "${attempt_manifest}" "${manifest_path}"
      rm -rf -- "${snapshot_dir}"
      return 0
    fi

    if (( attempt == ECS_SNAPSHOT_ATTEMPTS )); then
      echo "::error::Unable to obtain one stable ECS snapshot after ${ECS_SNAPSHOT_ATTEMPTS} attempts"
      sed 's/^/[ecs-observer] /' "${attempt_log}" >&2
      rm -rf -- "${snapshot_dir}"
      return "${attempt_status}"
    fi

    echo "::warning::ECS snapshot attempt ${attempt}/${ECS_SNAPSHOT_ATTEMPTS} was unstable; retrying from an empty snapshot"
    rm -rf -- "${snapshot_dir}"
    backoff_seconds=$((attempt * ECS_SNAPSHOT_BACKOFF_SECONDS))
    sleep "${backoff_seconds}"
    attempt=$((attempt + 1))
  done

  echo "::error::ECS snapshot retry loop ended without a canonical manifest"
  return 1
}

ecs_manifest="${work_dir}/ecs-manifest.json"
observe_ecs "${ecs_manifest}"

directory_manifest_python='
import hashlib, json, os, stat, sys

def safe_manifest(root):
    result = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            path = os.path.join(current, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise SystemExit("unsafe directory member")
        for name in files:
            path = os.path.join(current, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise SystemExit("unsafe file member")
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in relative):
                raise SystemExit("control character in file path")
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result.append({
                "path": relative,
                "size": os.path.getsize(path),
                "sha256": digest.hexdigest()
            })
    return sorted(result, key=lambda item: item["path"])

actual = safe_manifest(sys.argv[1])
if len(sys.argv) == 4:
    expected = safe_manifest(sys.argv[2])
    if actual != expected:
        raise SystemExit("live Lambda bytes differ from exact CI candidate")
    output = sys.argv[3]
else:
    output = sys.argv[2]
with open(output, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(actual, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
'

lambda_config_projection() {
  jq -cS '
    {
      FunctionName,
      FunctionArn,
      Runtime,
      Role,
      Handler,
      CodeSize,
      Description,
      Timeout,
      MemorySize,
      CodeSha256,
      Version,
      VpcConfig,
      DeadLetterConfig,
      Environment,
      KMSKeyArn,
      TracingConfig,
      MasterArn,
      RevisionId,
      Layers,
      State,
      LastUpdateStatus,
      FileSystemConfigs,
      PackageType,
      Architectures,
      EphemeralStorage,
      SnapStart,
      RuntimeVersionConfig,
      LoggingConfig
    }
  '
}

lambda_entries="${work_dir}/lambdas.ndjson"
: >"${lambda_entries}"
lambda_config_receipts="${work_dir}/lambda-configs.ndjson"
: >"${lambda_config_receipts}"
while IFS='|' read -r role function_name expected_handler candidate_subdir; do
  function_json="$(
    aws lambda get-function \
      --region "${AWS_REGION}" \
      --function-name "${function_name}" \
      --output json
  )"
  configuration_json="$(
    aws lambda get-function-configuration \
      --region "${AWS_REGION}" \
      --function-name "${function_name}" \
      --output json
  )"
  expected_arn="arn:aws:lambda:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:function:${function_name}"
  jq -e \
    --arg arn "${expected_arn}" \
    --arg handler "${expected_handler}" \
    --arg name "${function_name}" '
      .Configuration.FunctionName == $name and
      .Configuration.FunctionArn == $arn and
      .Configuration.Version == "$LATEST" and
      .Configuration.Runtime == "nodejs24.x" and
      .Configuration.Handler == $handler and
      .Configuration.PackageType == "Zip" and
      .Configuration.Architectures == ["x86_64"] and
      .Configuration.State == "Active" and
      .Configuration.LastUpdateStatus == "Successful" and
      (.Configuration.RevisionId | type == "string" and length > 0) and
      (.Configuration.CodeSha256 |
        test("^[A-Za-z0-9+/]{43}=$")) and
      .Code.RepositoryType == "S3" and
      (.Code.Location | startswith("https://"))
    ' <<<"${function_json}" >/dev/null || {
      echo "::error::${role} Lambda configuration violates the production contract"
      exit 1
    }
  initial_projection="$(
    jq -cS '.Configuration' <<<"${function_json}" |
      lambda_config_projection
  )"
  observed_projection="$(
    lambda_config_projection <<<"${configuration_json}"
  )"
  test "${observed_projection}" = "${initial_projection}" || {
    echo "::error::${role} get-function/configuration observations disagree"
    exit 1
  }

  code_location="$(jq -er '.Code.Location' <<<"${function_json}")"
  code_zip="${work_dir}/${role}.zip"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --output "${code_zip}" "${code_location}"
  expected_code_sha="$(jq -er '.Configuration.CodeSha256' <<<"${function_json}")"
  actual_code_sha="$(
    openssl dgst -sha256 -binary "${code_zip}" | base64 --wrap=0
  )"
  test "${actual_code_sha}" = "${expected_code_sha}" || {
    echo "::error::${role} Lambda ZIP does not match AWS CodeSha256"
    exit 1
  }
  code_zip_sha256="$(sha256sum "${code_zip}" | awk '{print $1}')"
  extracted="${work_dir}/lambda-${role}"
  mkdir -p "${extracted}"
  python3 - "${code_zip}" "${extracted}" <<'PY'
import os
from pathlib import PurePosixPath
import stat
import sys
import zipfile

archive, destination = sys.argv[1:3]
seen = set()
total = 0
with zipfile.ZipFile(archive) as source:
    infos = source.infolist()
    if not infos:
        raise SystemExit("empty Lambda ZIP")
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if (
            not name or name.startswith("/") or "\\" in name or
            any(ord(ch) < 32 or ord(ch) == 127 for ch in name) or
            any(part in ("", ".", "..") for part in path.parts)
        ):
            raise SystemExit("unsafe Lambda ZIP path")
        canonical = path.as_posix() + ("/" if info.is_dir() else "")
        if canonical != name or canonical in seen:
            raise SystemExit("non-canonical or duplicate Lambda ZIP path")
        seen.add(canonical)
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise SystemExit("symlink or special Lambda ZIP entry")
        total += info.file_size
        if total > 262_144_000:
            raise SystemExit("Lambda ZIP exceeds the deployment size bound")
    for info in infos:
        path = PurePosixPath(info.filename)
        target = os.path.join(destination, *path.parts)
        if info.is_dir():
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target):
            raise SystemExit("conflicting Lambda ZIP paths")
        with source.open(info) as reader, open(target, "xb") as writer:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                writer.write(chunk)
PY

  content_manifest="${work_dir}/${role}-content.json"
  if [[ "${VERIFY_LOCAL_CANDIDATES}" == "true" ]]; then
    candidate_dir="${LAMBDA_DIR}/${candidate_subdir}"
    test -d "${candidate_dir}"
    python3 -c "${directory_manifest_python}" \
      "${extracted}" "${candidate_dir}" "${content_manifest}"
  else
    python3 -c "${directory_manifest_python}" \
      "${extracted}" "${content_manifest}"
  fi
  content_json="$(jq -cS '.' "${content_manifest}")"
  configuration_sha256="$(sha256_text "${initial_projection}")"

  final_configuration="$(
    aws lambda get-function-configuration \
      --region "${AWS_REGION}" \
      --function-name "${function_name}" \
      --output json
  )"
  final_projection="$(
    lambda_config_projection <<<"${final_configuration}"
  )"
  test "${final_projection}" = "${initial_projection}" || {
    echo "::error::${role} Lambda changed while its bytes were observed"
    exit 1
  }

  jq -cnS \
    --arg role "${role}" \
    --arg functionName "${function_name}" \
    --arg functionArn "${expected_arn}" \
    --arg version '$LATEST' \
    --arg handler "${expected_handler}" \
    --arg runtime "nodejs24.x" \
    --arg revisionId "$(jq -er '.Configuration.RevisionId' <<<"${function_json}")" \
    --arg codeSha256 "${expected_code_sha}" \
    --arg codeZipSha256 "${code_zip_sha256}" \
    --arg configurationSha256 "${configuration_sha256}" \
    --argjson content "${content_json}" '
      {
        role: $role,
        functionName: $functionName,
        functionArn: $functionArn,
        version: $version,
        handler: $handler,
        runtime: $runtime,
        revisionId: $revisionId,
        codeSha256: $codeSha256,
        codeZipSha256: $codeZipSha256,
        configurationSha256: $configurationSha256,
        content: $content
      }
    ' >>"${lambda_entries}"
  jq -cnS \
    --arg functionName "${function_name}" \
    --argjson configuration "${initial_projection}" '
      {
        functionName: $functionName,
        configuration: $configuration
      }
    ' >>"${lambda_config_receipts}"
done <<'EOF'
approval|archon-production-approval|index.handler|approval
approval-handoff|archon-production-approval-handoff|handoff.handler|approval
control|archon-production-control|index.handler|control
EOF
jq -cSs 'sort_by(.role)' "${lambda_entries}" >"${work_dir}/lambdas.json"
jq -cSs 'sort_by(.functionName)' \
  "${lambda_config_receipts}" >"${work_dir}/lambda-configs-initial.json"

bucket_name="$(jq -er '.ArchonSpaBucketName' <<<"${stack_outputs}")"
spa_key_arn="$(jq -er '.ArchonSpaKeyArn' <<<"${stack_outputs}")"
[[ "${spa_key_arn}" =~ ^arn:aws[a-z-]*:kms:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:key/[0-9a-fA-F-]{36}$ ]] || {
  echo "::error::ArchonSpaKeyArn is outside the configured account or region"
  exit 1
}
bucket_versioning="$(
  aws s3api get-bucket-versioning \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --output json
)"
jq -e '
  .Status == "Enabled" and
  ((.MFADelete // "Disabled") == "Disabled")
' <<<"${bucket_versioning}" >/dev/null || {
  echo "::error::Production SPA bucket versioning is not enabled"
  exit 1
}
bucket_versioning_projection_initial="$(
  jq -cS '
    {
      status: .Status,
      mfaDelete: (.MFADelete // "Disabled")
    }
  ' <<<"${bucket_versioning}"
)"
bucket_encryption="$(
  aws s3api get-bucket-encryption \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --output json
)"
jq -e \
  --arg keyArn "${spa_key_arn}" '
    (.ServerSideEncryptionConfiguration.Rules | length) == 1 and
    .ServerSideEncryptionConfiguration.Rules[0]
      .ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms" and
    .ServerSideEncryptionConfiguration.Rules[0]
      .ApplyServerSideEncryptionByDefault.KMSMasterKeyID == $keyArn and
    .ServerSideEncryptionConfiguration.Rules[0].BucketKeyEnabled == true
  ' <<<"${bucket_encryption}" >/dev/null || {
  echo "::error::Production SPA bucket is not bound to its exact KMS key"
  exit 1
}
bucket_encryption_projection_initial="$(
  jq -cS '
    .ServerSideEncryptionConfiguration |
    {
      rules: (
        .Rules |
        map({
          algorithm:
            .ApplyServerSideEncryptionByDefault.SSEAlgorithm,
          kmsMasterKeyId:
            .ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
          bucketKeyEnabled: .BucketKeyEnabled
        })
      )
    }
  ' <<<"${bucket_encryption}"
)"

create_expected_spa_manifest() {
  local destination="$1"
  python3 - "${WEB_DIR}" "${RUNTIME_CONFIG}" "${destination}" <<'PY'
import hashlib, json, os, stat, sys

web_root, runtime_config, destination = sys.argv[1:4]
entries = []
for current, directories, files in os.walk(web_root, followlinks=False):
    for name in directories:
        mode = os.lstat(os.path.join(current, name)).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise SystemExit("unsafe SPA directory")
    for name in files:
        path = os.path.join(current, name)
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise SystemExit("unsafe SPA file")
        key = os.path.relpath(path, web_root).replace(os.sep, "/")
        if key == "runtime-config.json":
            raise SystemExit("CI SPA must not contain runtime-config.json")
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        entries.append({
            "key": key,
            "size": os.path.getsize(path),
            "sha256": digest.hexdigest()
        })
mode = os.lstat(runtime_config).st_mode
if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
    raise SystemExit("unsafe runtime-config.json")
digest = hashlib.sha256()
with open(runtime_config, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
entries.append({
    "key": "runtime-config.json",
    "size": os.path.getsize(runtime_config),
    "sha256": digest.hexdigest()
})
entries.sort(key=lambda item: item["key"])
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(entries, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY
}

if [[ "${VERIFY_LOCAL_CANDIDATES}" == "true" ]]; then
  test -d "${WEB_DIR}"
  test -f "${RUNTIME_CONFIG}"
  test ! -L "${RUNTIME_CONFIG}"
  test "$(sha256sum "${RUNTIME_CONFIG}" | awk '{print $1}')" = \
    "${EXPECTED_RUNTIME_CONFIG_SHA256}"
  create_expected_spa_manifest "${work_dir}/spa-expected.json"
fi

list_spa_versions() {
  local destination="$1"
  aws s3api list-object-versions \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --max-items "${MAX_SPA_VERSION_RECORDS}" \
    --output json >"${destination}"
  jq -e \
    --argjson maxLatestStates "${MAX_SPA_LATEST_STATES}" \
    --argjson maxLiveObjects "${MAX_SPA_LIVE_OBJECTS}" \
    --argjson maxTotalBytes "${MAX_SPA_TOTAL_BYTES}" '
    ((.NextToken // "") == "") and
    ([((.Versions // [])[]) | select(.IsLatest == true)] | length) > 0 and
    (
      [((.Versions // [])[]) | select(.IsLatest == true)] as $live |
      [((.DeleteMarkers // [])[]) |
        select(.IsLatest == true)] as $deleted |
      ($live | length) <= $maxLiveObjects and
      (($live | length) + ($deleted | length)) <= $maxLatestStates and
      (($live | map(.Size) | add) // 0) <= $maxTotalBytes
    ) and
    all(
      ((.Versions // [])[]) |
        select(.IsLatest == true);
      (.Key | type == "string" and length > 0) and
      (.VersionId | type == "string" and length > 0 and . != "null") and
      (.Size | type == "number" and . >= 0) and
      .StorageClass == "STANDARD"
    ) and
    all(
      ((.DeleteMarkers // [])[]) |
        select(.IsLatest == true);
      (.Key | type == "string" and length > 0) and
      (.VersionId | type == "string" and length > 0 and . != "null")
    ) and
    (
      [((.Versions // [])[]) | select(.IsLatest == true) | .Key] as $keys |
      ($keys | length) == ($keys | unique | length)
    ) and
    (
      [((.DeleteMarkers // [])[]) |
        select(.IsLatest == true) |
        .Key] as $deleted |
      ($deleted | length) == ($deleted | unique | length)
    ) and
    (
      [((.Versions // [])[]) |
        select(.IsLatest == true) |
        .Key] as $live |
      [((.DeleteMarkers // [])[]) |
        select(.IsLatest == true) |
        .Key] as $deleted |
      (
        [
          $live[] as $key |
          select(($deleted | index($key)) != null) |
          $key
        ] |
        length
      ) == 0
    )
  ' "${destination}" >/dev/null || {
    echo "::error::Production SPA has a malformed or ambiguous latest version state"
    exit 1
  }
}

spa_versions_initial="${work_dir}/spa-versions-initial.json"
list_spa_versions "${spa_versions_initial}"
jq -cS '
  (
    [
      ((.Versions // [])[]) |
      select(.IsLatest == true) |
      {
        type: "version",
        key: .Key,
        versionId: .VersionId,
        size: .Size
      }
    ] +
    [
      ((.DeleteMarkers // [])[]) |
      select(.IsLatest == true) |
      {
        type: "deleteMarker",
        key: .Key,
        versionId: .VersionId
      }
    ]
  ) |
  sort_by(.key)
' "${spa_versions_initial}" >"${work_dir}/spa-version-projection-initial.json"

spa_entries="${work_dir}/spa-objects.ndjson"
: >"${spa_entries}"
object_index=0
while IFS= read -r encoded; do
  version_record="$(printf '%s' "${encoded}" | base64 --decode)"
  key="$(jq -er '.key' <<<"${version_record}")"
  version_id="$(jq -er '.versionId' <<<"${version_record}")"
  expected_size="$(jq -er '.size' <<<"${version_record}")"
  jq -en --arg key "${key}" '
    ($key | length) > 0 and
    ($key | startswith("/") | not) and
    ($key | contains("\\") | not) and
    ($key | test("(^|/)\\.\\.(/|$)") | not) and
    ($key | test("[\\u0000-\\u001f\\u007f]") | not)
  ' >/dev/null || {
    echo "::error::Unsafe production SPA object key"
    exit 1
  }
  object_body="${work_dir}/spa-object-${object_index}"
  object_metadata="${work_dir}/spa-object-${object_index}.json"
  aws s3api get-object \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --key "${key}" \
    --version-id "${version_id}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --checksum-mode ENABLED \
    "${object_body}" >"${object_metadata}"
  jq -e \
    --arg keyArn "${spa_key_arn}" \
    --arg versionId "${version_id}" \
    --argjson size "${expected_size}" '
      .VersionId == $versionId and
      .ContentLength == $size and
      ((.DeleteMarker // false) == false) and
      (has("Restore") | not) and
      .ServerSideEncryption == "aws:kms" and
      .SSEKMSKeyId == $keyArn and
      .BucketKeyEnabled == true
    ' "${object_metadata}" >/dev/null || {
    echo "::error::Production SPA object returned a special or mismatched version"
    exit 1
  }
  actual_size="$(wc -c <"${object_body}" | tr -d '[:space:]')"
  test "${actual_size}" = "${expected_size}"
  object_sha256="$(sha256sum "${object_body}" | awk '{print $1}')"
  jq -cnS \
    --arg key "${key}" \
    --arg versionId "${version_id}" \
    --argjson size "${expected_size}" \
    --arg sha256 "${object_sha256}" '
      {
        key: $key,
        versionId: $versionId,
        size: $size,
        sha256: $sha256
      }
    ' >>"${spa_entries}"
  object_index=$((object_index + 1))
done < <(
  jq -cr '
    [
      ((.Versions // [])[]) |
      select(.IsLatest == true) |
      {
        key: .Key,
        versionId: .VersionId,
        size: .Size
      }
    ] |
    sort_by(.key)[] |
    @base64
  ' "${spa_versions_initial}"
)
jq -cSs 'sort_by(.key)' "${spa_entries}" >"${work_dir}/spa-objects.json"
if [[ "${VERIFY_LOCAL_CANDIDATES}" == "true" ]]; then
  jq -cS 'map({key, size, sha256})' \
    "${work_dir}/spa-objects.json" >"${work_dir}/spa-live-content.json"
  cmp --silent \
    "${work_dir}/spa-expected.json" \
    "${work_dir}/spa-live-content.json" || {
    echo "::error::Live SPA objects differ from the exact CI SPA plus runtime config"
    exit 1
  }
fi

spa_versions_final="${work_dir}/spa-versions-final.json"
list_spa_versions "${spa_versions_final}"
jq -cS '
  (
    [
      ((.Versions // [])[]) |
      select(.IsLatest == true) |
      {
        type: "version",
        key: .Key,
        versionId: .VersionId,
        size: .Size
      }
    ] +
    [
      ((.DeleteMarkers // [])[]) |
      select(.IsLatest == true) |
      {
        type: "deleteMarker",
        key: .Key,
        versionId: .VersionId
      }
    ]
  ) |
  sort_by(.key)
' "${spa_versions_final}" >"${work_dir}/spa-version-projection-final.json"
cmp --silent \
  "${work_dir}/spa-version-projection-initial.json" \
  "${work_dir}/spa-version-projection-final.json" || {
  echo "::error::Production SPA latest versions changed during observation"
  exit 1
}
bucket_versioning_final="$(
  aws s3api get-bucket-versioning \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --output json
)"
bucket_versioning_projection_final="$(
  jq -cS '
    {
      status: .Status,
      mfaDelete: (.MFADelete // "Disabled")
    }
  ' <<<"${bucket_versioning_final}"
)"
test "${bucket_versioning_projection_final}" = \
  "${bucket_versioning_projection_initial}" || {
  echo "::error::Production SPA bucket versioning changed during observation"
  exit 1
}
bucket_encryption_final="$(
  aws s3api get-bucket-encryption \
    --region "${AWS_REGION}" \
    --bucket "${bucket_name}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --output json
)"
bucket_encryption_projection_final="$(
  jq -cS '
    .ServerSideEncryptionConfiguration |
    {
      rules: (
        .Rules |
        map({
          algorithm:
            .ApplyServerSideEncryptionByDefault.SSEAlgorithm,
          kmsMasterKeyId:
            .ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
          bucketKeyEnabled: .BucketKeyEnabled
        })
      )
    }
  ' <<<"${bucket_encryption_final}"
)"
test "${bucket_encryption_projection_final}" = \
  "${bucket_encryption_projection_initial}" || {
  echo "::error::Production SPA bucket encryption changed during observation"
  exit 1
}

# Re-read every mutable semantic projection before sealing one cross-service
# manifest, preventing a mixed snapshot across ECS, Lambda, S3, and the stack.
ecs_manifest_final="${work_dir}/ecs-manifest-final.json"
observe_ecs "${ecs_manifest_final}"
cmp --silent "${ecs_manifest}" "${ecs_manifest_final}" || {
  echo "::error::Production ECS changed during live-runtime observation"
  exit 1
}

lambda_configs_final="${work_dir}/lambda-configs-final.ndjson"
: >"${lambda_configs_final}"
for function_name in \
  archon-production-approval \
  archon-production-approval-handoff \
  archon-production-control; do
  configuration="$(
    aws lambda get-function-configuration \
      --region "${AWS_REGION}" \
      --function-name "${function_name}" \
      --output json
  )"
  projection="$(
    lambda_config_projection <<<"${configuration}"
  )"
  jq -cnS \
    --arg functionName "${function_name}" \
    --argjson configuration "${projection}" '
      {
        functionName: $functionName,
        configuration: $configuration
      }
    ' >>"${lambda_configs_final}"
done
jq -cSs 'sort_by(.functionName)' \
  "${lambda_configs_final}" >"${work_dir}/lambda-configs-final.json"
cmp --silent \
  "${work_dir}/lambda-configs-initial.json" \
  "${work_dir}/lambda-configs-final.json" || {
  echo "::error::Production Lambda configuration changed during observation"
  exit 1
}

stack_final="${work_dir}/stack-final.json"
read_stack "${stack_final}"
stack_state_final="$(
  jq -cS '
    .Stacks[0] |
    {
      stackId: .StackId,
      stackName: .StackName,
      stackStatus: .StackStatus,
      generation: (.LastUpdatedTime // .CreationTime),
      outputs: (
        (.Outputs // []) |
        map({key: .OutputKey, value: .OutputValue}) |
        sort_by(.key)
      )
    }
  ' "${stack_final}"
)"
test "${stack_state_final}" = "${stack_state_initial}" || {
  echo "::error::Production stack changed during observation"
  exit 1
}
final_stack_outputs="$(
  jq -cS '
    (.Stacks[0].Outputs // []) |
    map({key: .OutputKey, value: .OutputValue}) |
    from_entries
  ' "${stack_final}"
)"
test "${final_stack_outputs}" = "${stack_outputs}" || {
  echo "::error::Production stack outputs changed during observation"
  exit 1
}

ecs_json="$(jq -cS '.' "${ecs_manifest}")"
lambdas_json="$(jq -cS '.' "${work_dir}/lambdas.json")"
spa_json="$(jq -cS '.' "${work_dir}/spa-objects.json")"
jq -cnS \
  --arg releaseSha "${live_release_sha}" \
  --arg containerImageDigest "${live_image_digest}" \
  --arg containerArchiveSha256 "${live_container_archive}" \
  --arg lambdaArchiveSha256 "${live_lambda_archive}" \
  --arg spaArtifactSha256 "${live_web_archive}" \
  --arg clusterName "${cluster_name}" \
  --arg bucketName "${bucket_name}" \
  --arg spaKeyArnSha256 "$(sha256_text "${spa_key_arn}")" \
  --argjson services "${ecs_json}" \
  --argjson lambdas "${lambdas_json}" \
  --argjson objects "${spa_json}" '
    {
      schemaVersion: "archon.live-runtime-manifest/v1",
      releaseBinding: {
        releaseSha: $releaseSha,
        containerImageDigest: $containerImageDigest,
        containerArchiveSha256: $containerArchiveSha256,
        lambdaArchiveSha256: $lambdaArchiveSha256,
        spaArtifactSha256: $spaArtifactSha256
      },
      ecs: {
        clusterName: $clusterName,
        services: ($services | sort_by(.role))
      },
      lambdas: ($lambdas | sort_by(.role)),
      spa: {
        bucketName: $bucketName,
        versioningStatus: "Enabled",
        encryption: {
          algorithm: "aws:kms",
          bucketKeyEnabled: true,
          keyArnSha256: $spaKeyArnSha256
        },
        objects: ($objects | sort_by(.key))
      },
      verification: {
        result: "passed"
      }
    }
  ' >"${OUTPUT_PATH}"
test -s "${OUTPUT_PATH}"
test ! -L "${OUTPUT_PATH}"
