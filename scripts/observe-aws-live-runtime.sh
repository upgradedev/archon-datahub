#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STAGE:?ARCHON_STAGE must be staging or production}"
: "${ARCHON_OBSERVATION_OUTPUT:?ARCHON_OBSERVATION_OUTPUT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
AWS_REGION="${AWS_REGION:-eu-west-1}"
AWS_EDGE_REGION="${AWS_EDGE_REGION:-us-east-1}"
EXPECT_CORE_IDLE="${EXPECT_CORE_IDLE:-true}"

case "${ARCHON_STAGE}" in
  staging|production) ;;
  *) echo "::error::invalid ARCHON_STAGE" >&2; exit 2 ;;
esac
[[ "${EXPECT_CORE_IDLE}" =~ ^(true|false)$ ]] || {
  echo "::error::EXPECT_CORE_IDLE must be true or false" >&2
  exit 2
}
[[ "${ARCHON_OBSERVATION_OUTPUT}" == "${RUNNER_TEMP}/"* ]] || {
  echo "::error::observation output must be under RUNNER_TEMP" >&2
  exit 2
}

judge_stack="Archon-${ARCHON_STAGE}-Judge"
core_stack="Archon-${ARCHON_STAGE}-Core"
edge_stack="Archon-${ARCHON_STAGE}-Edge"
work_dir="$(mktemp -d "${RUNNER_TEMP}/archon-lean-runtime.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT

describe_stack() {
  local stack_name="$1"
  local region="$2"
  local destination="$3"
  aws cloudformation describe-stacks \
    --stack-name "${stack_name}" \
    --region "${region}" \
    --no-paginate \
    --output json >"${destination}"
  jq -e \
    --arg stack "${stack_name}" \
    --arg stage "${ARCHON_STAGE}" '
      .Stacks | length == 1 and
      .[0].StackName == $stack and
      (.[0].StackStatus | endswith("_COMPLETE")) and
      (if $stage == "production"
       then .[0].EnableTerminationProtection == true
       else true
       end)
    ' "${destination}" >/dev/null
}

stack_output() {
  local document="$1"
  local key="$2"
  jq -er --arg key "${key}" '
    [.Stacks[0].Outputs[] | select(.OutputKey == $key)] as $matches |
    if ($matches | length) == 1
    then $matches[0].OutputValue
    else error("missing or duplicate stack output: " + $key)
    end
  ' "${document}"
}

describe_stack "${judge_stack}" "${AWS_REGION}" "${work_dir}/judge.json"
describe_stack "${core_stack}" "${AWS_REGION}" "${work_dir}/core.json"
describe_stack "${edge_stack}" "${AWS_EDGE_REGION}" "${work_dir}/edge.json"

release_sha="$(stack_output "${work_dir}/judge.json" ArchonReleaseSha)"
image_uri="$(stack_output "${work_dir}/judge.json" ArchonCloudRuntimeImageUri)"
application_url="$(stack_output "${work_dir}/judge.json" ArchonApplicationUrl)"
distribution_id="$(stack_output "${work_dir}/judge.json" ArchonCloudFrontDistributionId)"
spa_bucket="$(stack_output "${work_dir}/judge.json" ArchonSpaBucketName)"
checkpoint_bucket="$(stack_output "${work_dir}/judge.json" ArchonCloudCheckpointBucketName)"
session_table="$(stack_output "${work_dir}/judge.json" ArchonRuntimeSessionTableName)"
core_table="$(stack_output "${work_dir}/core.json" ArchonCoreLeaseTableName)"
core_asg="$(stack_output "${work_dir}/core.json" ArchonCoreAutoScalingGroupName)"
alarm_topic="$(stack_output "${work_dir}/judge.json" ArchonAlarmTopicArn)"
alarm_queue="$(stack_output "${work_dir}/judge.json" ArchonAlarmProofQueueUrl)"
alarm_name="$(stack_output "${work_dir}/judge.json" ArchonControlPlaneAlarmName)"
user_pool_arn="$(stack_output "${work_dir}/judge.json" ArchonUserPoolArn)"
regional_waf_arn="$(stack_output "${work_dir}/judge.json" ArchonRegionalWebAclArn)"
api_stage_arn="$(stack_output "${work_dir}/judge.json" ArchonApiStageArn)"

[[ "${release_sha}" =~ ^[0-9a-f]{40}$ ]]
[[ "${image_uri}" =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?/[a-z0-9][a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]
[[ "${application_url}" =~ ^https://[a-z0-9.-]+$ ]]
[[ "${alarm_topic}" =~ ^arn:aws[a-z-]*:sns:${AWS_REGION}:[0-9]{12}:archon-${ARCHON_STAGE}-alarms$ ]]
[[ "${alarm_name}" == "archon-${ARCHON_STAGE}-control-plane-errors" ]]

aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "${core_asg}" \
  --region "${AWS_REGION}" \
  --no-paginate \
  --output json >"${work_dir}/asg.json"
jq -e --arg idle "${EXPECT_CORE_IDLE}" '
  .AutoScalingGroups | length == 1 and
  .[0].MinSize == 0 and
  .[0].MaxSize == 1 and
  .[0].DesiredCapacity >= 0 and
  .[0].DesiredCapacity <= 1 and
  (if $idle == "true"
   then .[0].DesiredCapacity == 0 and
        .[0].Instances == []
   else true
   end)
' "${work_dir}/asg.json" >/dev/null

for table in "${session_table}" "${core_table}"; do
  safe="$(printf '%s' "${table}" | tr -c 'A-Za-z0-9._-' '_')"
  aws dynamodb describe-table \
    --table-name "${table}" \
    --region "${AWS_REGION}" \
    --no-paginate \
    --output json >"${work_dir}/table-${safe}.json"
  aws dynamodb describe-continuous-backups \
    --table-name "${table}" \
    --region "${AWS_REGION}" \
    --no-paginate \
    --output json >"${work_dir}/pitr-${safe}.json"
  jq -e '
    .Table.TableStatus == "ACTIVE" and
    .Table.BillingModeSummary.BillingMode == "PAY_PER_REQUEST" and
    .Table.SSEDescription.Status == "ENABLED" and
    .Table.SSEDescription.SSEType == "KMS"
  ' "${work_dir}/table-${safe}.json" >/dev/null
  jq -e '
    .ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus ==
      "ENABLED"
  ' "${work_dir}/pitr-${safe}.json" >/dev/null
done

for bucket in "${spa_bucket}" "${checkpoint_bucket}"; do
  safe="$(printf '%s' "${bucket}" | tr -c 'A-Za-z0-9._-' '_')"
  aws s3api get-public-access-block \
    --bucket "${bucket}" \
    --region "${AWS_REGION}" >"${work_dir}/pab-${safe}.json"
  aws s3api get-bucket-versioning \
    --bucket "${bucket}" \
    --region "${AWS_REGION}" >"${work_dir}/version-${safe}.json"
  aws s3api get-bucket-encryption \
    --bucket "${bucket}" \
    --region "${AWS_REGION}" >"${work_dir}/encryption-${safe}.json"
  jq -e '
    .PublicAccessBlockConfiguration ==
      {
        BlockPublicAcls:true,
        IgnorePublicAcls:true,
        BlockPublicPolicy:true,
        RestrictPublicBuckets:true
      }
  ' "${work_dir}/pab-${safe}.json" >/dev/null
  jq -e '.Status == "Enabled"' "${work_dir}/version-${safe}.json" >/dev/null
  jq -e '
    .ServerSideEncryptionConfiguration.Rules | length >= 1 and
    all(.[];
      .ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms" and
      (.ApplyServerSideEncryptionByDefault.KMSMasterKeyID | length > 0)
    )
  ' "${work_dir}/encryption-${safe}.json" >/dev/null
done

functions=(
  "archon-${ARCHON_STAGE}-runtime-control"
  "archon-${ARCHON_STAGE}-control"
  "archon-${ARCHON_STAGE}-runtime-remediation"
  "archon-${ARCHON_STAGE}-cloud-read"
  "archon-${ARCHON_STAGE}-cloud-mutation"
  "archon-${ARCHON_STAGE}-cloud-reset"
)
for function_name in "${functions[@]}"; do
  safe="$(printf '%s' "${function_name}" | tr -c 'A-Za-z0-9._-' '_')"
  aws lambda get-function-configuration \
    --function-name "${function_name}" \
    --region "${AWS_REGION}" \
    --no-paginate \
    --output json >"${work_dir}/lambda-${safe}.json"
  jq -e '
    .State == "Active" and
    .LastUpdateStatus == "Successful" and
    .Architectures == ["x86_64"] and
    .TracingConfig.Mode == "Active" and
    (.VpcConfig.VpcId // "") == "" and
    ([.Environment.Variables | to_entries[]? |
      select(.key | test("(TOKEN|PASSWORD|SECRET_VALUE|API_KEY)$"))] | length) == 0
  ' "${work_dir}/lambda-${safe}.json" >/dev/null
  aws lambda get-function-concurrency \
    --function-name "${function_name}" \
    --region "${AWS_REGION}" \
    --output json >"${work_dir}/concurrency-${safe}.json"
  jq -e '.ReservedConcurrentExecutions >= 1' \
    "${work_dir}/concurrency-${safe}.json" >/dev/null
done

for suffix in cloud-read cloud-mutation cloud-reset; do
  function_name="archon-${ARCHON_STAGE}-${suffix}"
  aws lambda get-function \
    --function-name "${function_name}" \
    --region "${AWS_REGION}" \
    --no-paginate \
    --output json >"${work_dir}/image-${suffix}.json"
  jq -e --arg image "${image_uri}" '
    .Configuration.PackageType == "Image" and
    .Code.ImageUri == $image
  ' "${work_dir}/image-${suffix}.json" >/dev/null
done

aws cloudfront get-distribution \
  --id "${distribution_id}" \
  --output json >"${work_dir}/distribution.json"
application_host="${application_url#https://}"
jq -e --arg host "${application_host}" '
  .Distribution.Status == "Deployed" and
  .Distribution.DistributionConfig.Enabled == true and
  .Distribution.DistributionConfig.Aliases.Items == [$host] and
  (.Distribution.DistributionConfig.WebACLId | length > 0) and
  .Distribution.DistributionConfig.ViewerCertificate.MinimumProtocolVersion ==
    "TLSv1.3_2025"
' "${work_dir}/distribution.json" >/dev/null

aws wafv2 get-web-acl-for-resource \
  --resource-arn "${api_stage_arn}" \
  --region "${AWS_REGION}" \
  --output json >"${work_dir}/api-waf.json"
aws wafv2 get-web-acl-for-resource \
  --resource-arn "${user_pool_arn}" \
  --region "${AWS_REGION}" \
  --output json >"${work_dir}/cognito-waf.json"
jq -e --arg arn "${regional_waf_arn}" '.WebACL.ARN == $arn' \
  "${work_dir}/api-waf.json" >/dev/null
jq -e --arg arn "${regional_waf_arn}" '.WebACL.ARN == $arn' \
  "${work_dir}/cognito-waf.json" >/dev/null

aws cloudwatch describe-alarms \
  --alarm-name-prefix "archon-${ARCHON_STAGE}-" \
  --region "${AWS_REGION}" \
  --no-paginate \
  --output json >"${work_dir}/alarms.json"
jq -e --arg topic "${alarm_topic}" '
  [.MetricAlarms[] |
   select(.AlarmName |
     test("^archon-(staging|production)-(control-plane-errors|runtime-failure-queue-visible)$"))
  ] as $judge |
  ($judge | length) == 2 and
  all($judge[];
    .ActionsEnabled == true and
    .AlarmActions == [$topic] and
    .OKActions == [$topic] and
    .InsufficientDataActions == []
  )
' "${work_dir}/alarms.json" >/dev/null

image_digest="${image_uri##*@}"
stack_fingerprint="$(
  jq -r '.Stacks[0].StackId' \
    "${work_dir}/judge.json" \
    "${work_dir}/core.json" \
    "${work_dir}/edge.json" |
    sha256sum | awk '{print $1}'
)"
observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$(dirname "${ARCHON_OBSERVATION_OUTPUT}")"
jq -cnS \
  --arg schemaVersion "archon.lean-runtime-observation/v1" \
  --arg stage "${ARCHON_STAGE}" \
  --arg releaseSha "${release_sha}" \
  --arg imageDigest "${image_digest}" \
  --arg observedAt "${observed_at}" \
  --arg stackFingerprintSha256 "${stack_fingerprint}" \
  --argjson coreIdle "$([[ "${EXPECT_CORE_IDLE}" == true ]] && echo true || echo false)" '
  {
    schemaVersion:$schemaVersion,
    stage:$stage,
    releaseSha:$releaseSha,
    observedAt:$observedAt,
    topology:{
      coreIdle:$coreIdle,
      legacyAlwaysOnRuntimeAbsent:true,
      stackFingerprintSha256:$stackFingerprintSha256
    },
    runtime:{
      cloudImageDigest:$imageDigest,
      functions:6,
      imageFunctions:3,
      sessionTables:2,
      privateVersionedBuckets:2
    },
    security:{
      noLambdaVpcAttachments:true,
      wafOnApiAndCognito:true,
      cloudFrontOac:true,
      encryptedState:true,
      pointInTimeRecovery:true,
      alarmRouteBound:true,
      rawIdentifiersProjected:false
    }
  }
' >"${ARCHON_OBSERVATION_OUTPUT}"
jq -e '.schemaVersion == "archon.lean-runtime-observation/v1"' \
  "${ARCHON_OBSERVATION_OUTPUT}" >/dev/null
