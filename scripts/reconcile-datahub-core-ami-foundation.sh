#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "DataHub Core AMI foundation reconciliation is CI-only" >&2
  exit 1
fi

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

readonly REGION="eu-west-1"
readonly STACK_NAME="Archon-DataHub-Core-AMI-Builder-Foundation"
readonly TEMPLATE="infra/aws/foundation/datahub-core-ami-builder.yml"
readonly BUILD_ROLE="archon-datahub-core-ami-build-staging"
readonly BUILDER_ROLE="archon-datahub-core-ami-builder-staging"
readonly BUILDER_PROFILE="archon-datahub-core-ami-builder-staging"
readonly BUILD_POLICY="archon-datahub-core-ami-build"
readonly SSM_POLICY_ARN="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
readonly DRIFT_HELPER="scripts/aws-cloudformation-drift.sh"
readonly EVIDENCE_DIR="${RUNNER_TEMP}/aws-core-ami-foundation-evidence"
readonly CFN_DRIFT_MAX_ATTEMPTS=120
readonly CFN_DRIFT_DELAY_SECONDS=2
readonly CFN_DRIFT_MAX_API_FAILURES=3
readonly CFN_DRIFT_PHASE_TIMEOUT_SECONDS=900
readonly IAM_ROLE_INLINE_POLICY_AGGREGATE_CHARACTER_LIMIT=10240
phase="startup"

fail() {
  printf '::error title=DataHub Core AMI foundation failed::phase=%s; reason=%s\n'     "${phase}" "$1" >&2
  return 1
}

report_error() {
  local status="$1"
  printf '::error title=DataHub Core AMI foundation failed::phase=%s; exit=%s\n'     "${phase}" "${status}" >&2
}
trap 'report_error "$?"' ERR

[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] || fail "invalid-account-binding"
[[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "invalid-source-binding"
for path in "${TEMPLATE}" "${DRIFT_HELPER}" contracts/aws-foundation-v1.json; do
  test -f "${path}"
  test ! -L "${path}"
done
# shellcheck source=scripts/aws-cloudformation-drift.sh
source "${DRIFT_HELPER}"
printf '::add-mask::%s\n' "${EXPECTED_ACCOUNT_ID}"

revalidate_master() {
  test "${GITHUB_REPOSITORY}" = "upgradedev/archon-datahub"
  test "${GITHUB_REF}" = "refs/heads/master"
  test "${GITHUB_SHA}" = "${CONTROL_PLANE_SHA}"
  test "$(git rev-parse HEAD)" = "${CONTROL_PLANE_SHA}"
  test -z "$(git status --porcelain --untracked-files=all)"
  test "$(
    gh api -H "Accept: application/vnd.github+json"       "/repos/${GITHUB_REPOSITORY}/git/ref/heads/master" --jq '.object.sha'
  )" = "${CONTROL_PLANE_SHA}"
}

safe_aws_json() {
  local output="$1"
  shift
  if ! aws "$@" --output json >"${output}" 2>/dev/null; then
    fail "sanitized-aws-call-failed"
    return 1
  fi
  test -f "${output}"
  test ! -L "${output}"
  chmod 0600 "${output}"
}

phase="preflight"
revalidate_master
aws cloudformation validate-template   --region "${REGION}" --template-body "file://${TEMPLATE}"   >/dev/null 2>/dev/null
existing="${RUNNER_TEMP}/core-ami-foundation-existing.json"
if aws cloudformation describe-stacks   --region "${REGION}" --stack-name "${STACK_NAME}"   --output json >"${existing}" 2>/dev/null; then
  chmod 0600 "${existing}"
  jq -e --arg stack "${STACK_NAME}" '
    (.Stacks | length) == 1 and
    .Stacks[0].StackName == $stack and
    ((.Stacks[0].RoleARN // "") == "") and
    (.Stacks[0].StackStatus | IN(
      "CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"
    ))
  ' "${existing}" >/dev/null || fail "existing-stack-binding-differs"
else
  rm -f -- "${existing}"
fi

phase="deploy"
revalidate_master
if ! aws cloudformation deploy   --region "${REGION}"   --stack-name "${STACK_NAME}"   --template-file "${TEMPLATE}"   --capabilities CAPABILITY_NAMED_IAM   --no-fail-on-empty-changeset   --parameter-overrides     GitHubOrganization=upgradedev     GitHubRepository=archon-datahub     GitHubEnvironment=staging     GitHubBranch=master   --tags     Application=archon-datahub     Environment=staging     ManagedBy=aws-foundation     Purpose=datahub-core-ami-builder   >/dev/null 2>/dev/null; then
  fail "cloudformation-deploy-failed"
fi
aws cloudformation update-termination-protection   --region "${REGION}" --stack-name "${STACK_NAME}"   --enable-termination-protection >/dev/null 2>/dev/null

phase="profile-tags"
profile_tags_before="${RUNNER_TEMP}/core-ami-profile-tags-before.json"
safe_aws_json "${profile_tags_before}" iam list-instance-profile-tags   --instance-profile-name "${BUILDER_PROFILE}"
jq -e '
  all(.Tags[];
    (.Key == "Application" and .Value == "archon-datahub") or
    (.Key == "Environment" and .Value == "staging") or
    (.Key == "ManagedBy" and .Value == "aws-foundation") or
    (.Key == "archon:Purpose" and .Value == "datahub-core-ami-builder")
  )
' "${profile_tags_before}" >/dev/null ||
  fail "profile-has-extra-or-mismatched-tags"
aws iam tag-instance-profile   --instance-profile-name "${BUILDER_PROFILE}"   --tags     Key=Application,Value=archon-datahub     Key=Environment,Value=staging     Key=ManagedBy,Value=aws-foundation     Key=archon:Purpose,Value=datahub-core-ami-builder   >/dev/null 2>/dev/null

phase="identity-postcheck"
stack="${RUNNER_TEMP}/core-ami-foundation-stack.json"
build_role="${RUNNER_TEMP}/core-ami-build-role.json"
builder_role="${RUNNER_TEMP}/core-ami-builder-role.json"
profile="${RUNNER_TEMP}/core-ami-builder-profile.json"
build_inline="${RUNNER_TEMP}/core-ami-build-inline.json"
profile_tags="${RUNNER_TEMP}/core-ami-profile-tags.json"
safe_aws_json "${stack}" cloudformation describe-stacks   --region "${REGION}" --stack-name "${STACK_NAME}"
safe_aws_json "${build_role}" iam get-role --role-name "${BUILD_ROLE}"
safe_aws_json "${builder_role}" iam get-role --role-name "${BUILDER_ROLE}"
safe_aws_json "${profile}" iam get-instance-profile   --instance-profile-name "${BUILDER_PROFILE}"
safe_aws_json "${build_inline}" iam get-role-policy   --role-name "${BUILD_ROLE}" --policy-name "${BUILD_POLICY}"
safe_aws_json "${profile_tags}" iam list-instance-profile-tags   --instance-profile-name "${BUILDER_PROFILE}"
inline_policy_characters="$(
  jq -cS -j '.PolicyDocument' "${build_inline}" | wc -c | tr -d '[:space:]'
)"
[[ "${inline_policy_characters}" =~ ^[1-9][0-9]*$ ]] ||
  fail "build-policy-character-count-invalid"
((inline_policy_characters <= IAM_ROLE_INLINE_POLICY_AGGREGATE_CHARACTER_LIMIT)) ||
  fail "build-policy-exceeds-inline-character-limit"

jq -e --arg account "${EXPECTED_ACCOUNT_ID}" --arg stack "${STACK_NAME}" '
  (.Stacks | length) == 1 and
  .Stacks[0].StackName == $stack and
  .Stacks[0].EnableTerminationProtection == true and
  ((.Stacks[0].RoleARN // "") == "") and
  (.Stacks[0].StackStatus | IN("CREATE_COMPLETE", "UPDATE_COMPLETE")) and
  ([.Stacks[0].Outputs[] | {key:.OutputKey,value:.OutputValue}] | from_entries) as $o |
  $o.GitHubCoreAmiBuildRoleArn ==
    ("arn:aws:iam::" + $account + ":role/archon-datahub-core-ami-build-staging") and
  $o.CoreAmiBuilderRoleArn ==
    ("arn:aws:iam::" + $account + ":role/archon-datahub-core-ami-builder-staging") and
  $o.CoreAmiBuilderInstanceProfileName ==
    "archon-datahub-core-ami-builder-staging" and
  $o.CoreAmiBuilderInstanceProfileArn ==
    ("arn:aws:iam::" + $account +
      ":instance-profile/archon-datahub-core-ami-builder-staging")
' "${stack}" >/dev/null || fail "stack-output-postcheck-differs"

jq -e --arg account "${EXPECTED_ACCOUNT_ID}" '
  .Role.RoleName == "archon-datahub-core-ami-build-staging" and
  .Role.MaxSessionDuration == 7200 and
  (.Role.PermissionsBoundary == null) and
  (.Role.Tags | map(select(.Key | startswith("aws:") | not)) | sort_by(.Key)) ==
    ([
      {Key:"Application",Value:"archon-datahub"},
      {Key:"Environment",Value:"staging"},
      {Key:"ManagedBy",Value:"aws-foundation"},
      {Key:"archon:Purpose",Value:"datahub-core-ami-build"}
    ] | sort_by(.Key)) and
  .Role.AssumeRolePolicyDocument.Statement == [{
    Action:"sts:AssumeRoleWithWebIdentity",
    Condition:{StringEquals:{
      "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
      "token.actions.githubusercontent.com:environment":"staging",
      "token.actions.githubusercontent.com:ref":"refs/heads/master",
      "token.actions.githubusercontent.com:repository":"upgradedev/archon-datahub",
      "token.actions.githubusercontent.com:sub":
        "repo:upgradedev/archon-datahub:environment:staging",
      "token.actions.githubusercontent.com:workflow_ref":
        "upgradedev/archon-datahub/.github/workflows/datahub-core-ami.yml@refs/heads/master"
    }},
    Effect:"Allow",
    Principal:{Federated:
      ("arn:aws:iam::" + $account +
        ":oidc-provider/token.actions.githubusercontent.com")},
    Sid:"ExactProtectedCoreAmiWorkflow"
  }]
' "${build_role}" >/dev/null || fail "build-role-postcheck-differs"

jq -e '
  .RoleName == "archon-datahub-core-ami-build-staging" and
  .PolicyName == "archon-datahub-core-ami-build" and
  .PolicyDocument.Version == "2012-10-17" and
  (.PolicyDocument.Statement | length) == 16 and
  ([.PolicyDocument.Statement[].Sid] | sort) == ([
    "CreateTaggedCoreAmiResources",
    "MutateOnlyOwnedCoreAmiResources",
    "ObserveOnlyEuWestOneSessions",
    "ObserveOwnPackerRequestTags",
    "PassOnlyStableBuilderRole",
    "ReadEuWestOneEc2BuildState",
    "ReadExactAmazonLinux2023Parameter",
    "ReadExactStableBuilderIdentity",
    "RunOnlyAmazonLinux2023Family",
    "RunOnlyInsideOwnedBoundary",
    "RunOnlyTaggedBuilderCompute",
    "StartSessionOnlyOnOwnedBuilder",
    "TagOnlyDuringOwnedCreation",
    "TerminateOnlyOwnSessions",
    "UseOnlyAwsStartSshSession",
    "VerifyCaller"
  ] | sort) and
  ([.PolicyDocument.Statement[] |
    select(.Sid == "ObserveOwnPackerRequestTags")]) == [{
      Action: "cloudtrail:LookupEvents",
      Condition: {
        StringEquals: {"aws:RequestedRegion": "eu-west-1"}
      },
      Effect: "Allow",
      Resource: "*",
      Sid: "ObserveOwnPackerRequestTags"
    }] and
  all([
    "CreateTaggedCoreAmiResources",
    "TagOnlyDuringOwnedCreation",
    "RunOnlyTaggedBuilderCompute"
  ][];
    . as $sid |
    ([.PolicyDocument.Statement[] | select(.Sid == $sid)] | length) == 1 and
    [.PolicyDocument.Statement[] | select(.Sid == $sid)][0].
      Condition.StringEquals["aws:RequestTag/Environment"] == "staging") and
  all([
    "RunOnlyInsideOwnedBoundary",
    "MutateOnlyOwnedCoreAmiResources"
  ][];
    . as $sid |
    ([.PolicyDocument.Statement[] | select(.Sid == $sid)] | length) == 1 and
    [.PolicyDocument.Statement[] | select(.Sid == $sid)][0].
      Condition.StringEquals["aws:ResourceTag/Environment"] == "staging") and
  [.PolicyDocument.Statement[] |
    select(.Sid == "StartSessionOnlyOnOwnedBuilder")][0].
      Condition.StringEquals["ssm:resourceTag/Environment"] == "staging" and
  ([.PolicyDocument.Statement[].Action] | flatten |
    any(. == "ec2:AuthorizeSecurityGroupIngress" or
        . == "iam:CreateRole" or
        . == "iam:PutRolePolicy" or
        . == "ssm:SendCommand") | not)
' "${build_inline}" >/dev/null || fail "build-policy-postcheck-differs"
aws iam list-role-policies --role-name "${BUILD_ROLE}" --output json |
  jq -e '.PolicyNames == ["archon-datahub-core-ami-build"]' >/dev/null
aws iam list-attached-role-policies --role-name "${BUILD_ROLE}" --output json |
  jq -e '.AttachedPolicies == []' >/dev/null

jq -e --arg account "${EXPECTED_ACCOUNT_ID}" '
  .Role.RoleName == "archon-datahub-core-ami-builder-staging" and
  .Role.MaxSessionDuration == 3600 and
  (.Role.PermissionsBoundary == null) and
  (.Role.Tags | map(select(.Key | startswith("aws:") | not)) | sort_by(.Key)) ==
    ([
      {Key:"Application",Value:"archon-datahub"},
      {Key:"Environment",Value:"staging"},
      {Key:"ManagedBy",Value:"aws-foundation"},
      {Key:"archon:Purpose",Value:"datahub-core-ami-builder"}
    ] | sort_by(.Key)) and
  .Role.AssumeRolePolicyDocument.Statement == [{
    Action:"sts:AssumeRole",
    Effect:"Allow",
    Principal:{Service:"ec2.amazonaws.com"},
    Sid:"Ec2Only"
  }]
' "${builder_role}" >/dev/null || fail "builder-role-postcheck-differs"
aws iam list-role-policies --role-name "${BUILDER_ROLE}" --output json |
  jq -e '.PolicyNames == []' >/dev/null
aws iam list-attached-role-policies --role-name "${BUILDER_ROLE}" --output json |
  jq -e --arg policy "${SSM_POLICY_ARN}" '
    .AttachedPolicies == [{PolicyArn:$policy,PolicyName:"AmazonSSMManagedInstanceCore"}]
  ' >/dev/null

jq -e --arg account "${EXPECTED_ACCOUNT_ID}" '
  .InstanceProfile.InstanceProfileName ==
    "archon-datahub-core-ami-builder-staging" and
  .InstanceProfile.Arn ==
    ("arn:aws:iam::" + $account +
      ":instance-profile/archon-datahub-core-ami-builder-staging") and
  (.InstanceProfile.Roles | length) == 1 and
  .InstanceProfile.Roles[0].RoleName ==
    "archon-datahub-core-ami-builder-staging"
' "${profile}" >/dev/null || fail "builder-profile-postcheck-differs"
jq -e '
  (.Tags | sort_by(.Key)) == ([
    {Key:"Application",Value:"archon-datahub"},
    {Key:"Environment",Value:"staging"},
    {Key:"ManagedBy",Value:"aws-foundation"},
    {Key:"archon:Purpose",Value:"datahub-core-ami-builder"}
  ] | sort_by(.Key))
' "${profile_tags}" >/dev/null || fail "profile-tags-postcheck-differs"

phase="drift"
drift_raw="${RUNNER_TEMP}/core-ami-foundation-drift-raw.json"
drift_started_epoch="$(date +%s)"
readonly CFN_DRIFT_DEADLINE_EPOCH="$((drift_started_epoch + CFN_DRIFT_PHASE_TIMEOUT_SECONDS))"
detect_and_wait_for_cloudformation_stack_in_sync   "${REGION}" "${STACK_NAME}" "${drift_raw}" "${EXPECTED_ACCOUNT_ID}"
exact_stack_id="$(jq -er '.StackId' "${drift_raw}")"
detection_timestamp="$(jq -er '.Timestamp' "${drift_raw}")"
checked_resources="$(verify_cloudformation_stack_resource_drifts   "${REGION}" "${STACK_NAME}" "${exact_stack_id}" "${detection_timestamp}"   "${EXPECTED_ACCOUNT_ID}" "${CFN_DRIFT_DEADLINE_EPOCH}")"
[[ "${checked_resources}" =~ ^[0-9]+$ ]]
rm -f -- "${drift_raw}"

phase="evidence"
install -d -m 0700 "${EVIDENCE_DIR}"
template_sha="$(sha256sum "${TEMPLATE}" | awk '{print $1}')"
policy_sha="$(
  jq -cS '.PolicyDocument' "${build_inline}" | sha256sum | awk '{print $1}'
)"
role_binding_sha="$(
  jq -cS '{
    buildRole:.Role.RoleName,
    maxSession:.Role.MaxSessionDuration,
    trust:.Role.AssumeRolePolicyDocument,
    tags:.Role.Tags
  }' "${build_role}" | sha256sum | awk '{print $1}'
)"
profile_binding_sha="$(
  jq -cS --slurpfile tags "${profile_tags}" '{
    profile:.InstanceProfile.InstanceProfileName,
    roles:.InstanceProfile.Roles,
    tags:$tags[0].Tags
  }' "${profile}" | sha256sum | awk '{print $1}'
)"
jq -cnS   --arg controlPlaneSha "${CONTROL_PLANE_SHA}"   --arg templateSha "${template_sha}"   --arg policySha "${policy_sha}"   --arg roleBindingSha "${role_binding_sha}"   --arg profileBindingSha "${profile_binding_sha}"   --argjson inlinePolicyCharacters "${inline_policy_characters}"   --argjson checkedResources "${checked_resources}"   --argjson runId "${GITHUB_RUN_ID}"   --argjson runAttempt "${GITHUB_RUN_ATTEMPT}" '
  {
    schemaVersion:"archon.aws-core-ami-foundation-evidence/v1",
    source:{
      repository:"upgradedev/archon-datahub",
      ref:"refs/heads/master",
      controlPlaneSha:$controlPlaneSha,
      templateSha256:$templateSha,
      runId:$runId,
      runAttempt:$runAttempt
    },
    stack:{
      name:"Archon-DataHub-Core-AMI-Builder-Foundation",
      region:"eu-west-1",
      terminationProtection:true,
      drift:{
        status:"IN_SYNC",
        coverage:"cloudformation-supported-resources",
        checkedResourceCount:$checkedResources,
        method:"detect-then-bounded-describe-poll",
        globalTimeoutSeconds:900
      }
    },
    identities:{
      githubBuildRole:{
        arnTemplate:
          "arn:aws:iam::<AWS_ACCOUNT_ID>:role/archon-datahub-core-ami-build-staging",
        maxSessionDurationSeconds:7200,
        inlinePolicyCharacters:$inlinePolicyCharacters,
        inlinePolicyCharacterLimit:10240,
        requestTagObservation:{
          action:"cloudtrail:LookupEvents",
          region:"eu-west-1",
          resourceScope:"wildcard-required-by-aws-action",
          requiredTags:{
            Application:"archon-datahub",
            Environment:"staging",
            ManagedBy:"github-actions",
            "archon:Purpose":"datahub-core-ami",
            "archon:BuildRun":"exact-build-id"
          }
        },
        policySha256:$policySha,
        bindingSha256:$roleBindingSha
      },
      ec2Builder:{
        roleArnTemplate:
          "arn:aws:iam::<AWS_ACCOUNT_ID>:role/archon-datahub-core-ami-builder-staging",
        profileArnTemplate:
          "arn:aws:iam::<AWS_ACCOUNT_ID>:instance-profile/archon-datahub-core-ami-builder-staging",
        managedPolicy:
          "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        profileBindingSha256:$profileBindingSha
      }
    },
    githubVariables:{
      buildRole:"AWS_CORE_AMI_BUILD_ROLE_ARN",
      instanceProfile:"AWS_CORE_AMI_BUILDER_INSTANCE_PROFILE"
    },
    idleAwsCost:"zero",
    validation:"passed"
  }
' >"${EVIDENCE_DIR}/core-ami-foundation.json"
chmod 0600 "${EVIDENCE_DIR}/core-ami-foundation.json"
jq -cS . "${EVIDENCE_DIR}/core-ami-foundation.json" |
  cmp -s - "${EVIDENCE_DIR}/core-ami-foundation.json"
if grep -Eq 'arn:aws:iam::[0-9]{12}:'   "${EVIDENCE_DIR}/core-ami-foundation.json"; then
  fail "evidence-leaked-account-arn"
fi
(
  cd "${EVIDENCE_DIR}"
  sha256sum core-ami-foundation.json >SHA256SUMS
  sha256sum --check --strict SHA256SUMS >/dev/null
)
evidence_sha="$(sha256sum "${EVIDENCE_DIR}/core-ami-foundation.json" | awk '{print $1}')"
jq -cnS --arg evidenceSha "${evidence_sha}" '{
  schemaVersion:"archon.aws-core-ami-foundation-attestation/v1",
  evidenceSha256:$evidenceSha,
  validation:"passed"
}' >"${EVIDENCE_DIR}/attestation-predicate.json"
chmod 0600 "${EVIDENCE_DIR}/SHA256SUMS"   "${EVIDENCE_DIR}/attestation-predicate.json"
{
  printf 'path=%s\n' "${EVIDENCE_DIR}"
  printf 'evidence_sha=%s\n' "${evidence_sha}"
  printf 'subject=%s\n' "${EVIDENCE_DIR}/SHA256SUMS"
  printf 'predicate=%s\n' "${EVIDENCE_DIR}/attestation-predicate.json"
  printf 'build_role_arn=arn:aws:iam::%s:role/%s\n'     "${EXPECTED_ACCOUNT_ID}" "${BUILD_ROLE}"
  printf 'instance_profile=%s\n' "${BUILDER_PROFILE}"
} >>"${GITHUB_OUTPUT}"
phase="complete"
