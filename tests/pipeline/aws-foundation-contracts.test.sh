#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
foundation_workflow="${repository_root}/.github/workflows/aws-foundation.yml"
deploy_workflow="${repository_root}/.github/workflows/deploy.yml"
ci_workflow="${repository_root}/.github/workflows/ci.yml"
contract="${repository_root}/contracts/aws-foundation-v1.json"
foundation_policy="${repository_root}/infra/aws/foundation/github-actions-foundation-policy.json"
foundation_role="${repository_root}/infra/aws/foundation/github-actions-foundation-role.yml"
deploy_role="${repository_root}/infra/aws/foundation/github-actions-deploy-role.yml"
canary_roles="${repository_root}/infra/aws/foundation/governed-canary-roles.yml"
execution_policy="${repository_root}/infra/aws/foundation/cdk-execution-policy.yml"
api_gateway_account="${repository_root}/infra/aws/foundation/api-gateway-account.yml"
bootstrap_patcher="${repository_root}/scripts/patch-cdk-bootstrap-template.mjs"
bootstrap_sealer="${repository_root}/scripts/seal-cdk-bootstrap-templates.sh"
inline_template_renderer="${repository_root}/scripts/render-inline-cloudformation-template.sh"
foundation_renderer="${repository_root}/scripts/render-aws-foundation-policy.mjs"
foundation_bootstrap="${repository_root}/scripts/bootstrap-aws-foundation-role.sh"
reconciler="${repository_root}/scripts/reconcile-aws-foundation.sh"
runtime_verifier="${repository_root}/scripts/verify-aws-runtime-boundary.mjs"
runbook="${repository_root}/docs/AWS_FOUNDATION.md"

fail() {
  echo "::error::$*" >&2
  exit 1
}

require_text() {
  local path="$1"
  shift
  local expected
  for expected in "$@"; do
    grep -Fq -- "${expected}" "${path}" ||
      fail "${path#${repository_root}/} is missing: ${expected}"
  done
}

forbid_text() {
  local path="$1"
  shift
  local forbidden
  for forbidden in "$@"; do
    if grep -Fq -- "${forbidden}" "${path}"; then
      fail "${path#${repository_root}/} contains forbidden text: ${forbidden}"
    fi
  done
}

for path in \
  "${foundation_workflow}" \
  "${deploy_workflow}" \
  "${ci_workflow}" \
  "${contract}" \
  "${foundation_policy}" \
  "${foundation_role}" \
  "${deploy_role}" \
  "${canary_roles}" \
  "${execution_policy}" \
  "${api_gateway_account}" \
  "${bootstrap_patcher}" \
  "${bootstrap_sealer}" \
  "${inline_template_renderer}" \
  "${foundation_renderer}" \
  "${foundation_bootstrap}" \
  "${reconciler}" \
  "${runtime_verifier}" \
  "${runbook}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must be a regular file"
done

jq --exit-status '
  .schemaVersion == "archon.aws-foundation/v1" and
  .repository == "upgradedev/archon-datahub" and
  .defaultBranch == "master" and
  .workflow == {
    confirmation: "BOOTSTRAP_CDK_FOUNDATION",
    environment: "aws-foundation",
    path: ".github/workflows/aws-foundation.yml"
  } and
  .aws.partition == "aws" and
  .aws.primaryRegion == "eu-west-1" and
  .aws.regions == ["eu-west-1", "us-east-1"] and
  .aws.foundationRoleName == "archon-datahub-github-foundation" and
  .aws.foundationRoleAdoption == {
    allowsOnlyLegacyOrCanonicalComponentsForInterruptedRetry: true,
    convergesToCanonicalRole: true,
    knownLegacyDescription:
      "GitHub OIDC role for the Archon DataHub CDK foundation bootstrap pipeline",
    knownLegacyTags: {
      Application: "archon-datahub",
      Environment: "foundation",
      ManagedBy: "github-actions"
    },
    knownLegacyTrustDifference: "missing-canonical-sid-only",
    requiresZeroAttachedManagedPolicies: true,
    requiresZeroInlinePolicies: true
  } and
  .aws.foundationPolicies == {
    attachedPolicyNames: [
      "archon-aws-foundation-control",
      "archon-aws-foundation-assets",
      "archon-aws-foundation-identity",
      "archon-aws-foundation-attachments"
    ],
    maximumDocumentBytes: 6144,
    renderer: "scripts/render-aws-foundation-policy.mjs",
    roleAttachedPolicyCount: 4,
    roleInlinePolicyCount: 0,
    roleManagedPolicyHeadroom: 6,
    roleManagedPolicyQuota: 10,
    sourceBundle: "infra/aws/foundation/github-actions-foundation-policy.json",
    sourceBundleAttachable: false
  } and
  .aws.inlineTemplateRendering == {
    deployedOriginalMatchesSemanticSha256: true,
    flowEmitter: {
      linuxAmd64Sha256:
        "1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0",
      name: "mikefarah/yq",
      version: "v4.47.2"
    },
    format: "canonical-flow-yaml",
    maximumTemplateBodyBytes: 51200,
    outputRoot: "RUNNER_TEMP",
    renderer: "scripts/render-inline-cloudformation-template.sh",
    sameBytesForValidationAndDeploy: true,
    semanticRoundTrip: "rain-json-canonical-equality",
    source: "infra/aws/foundation/cdk-execution-policy.yml",
    tool: {
      linuxAmd64ArchiveSha256:
        "5358d6daf35322101566376a38e37d1f89c6588479af2e20240579fc2d4c660a",
      name: "aws-cloudformation/rain",
      version: "v1.24.4"
    }
  } and
  .aws.governedCanaryRoles.stackName == "Archon-Governed-Canary-Roles" and
  .aws.governedCanaryRoles.region == "eu-west-1" and
  .aws.governedCanaryRoles.roles.prepare == {
    environment: "governed-canary-prepare",
    permissions: ["cloudformation:DescribeStacks"],
    roleName: "archon-datahub-github-governed-canary-prepare",
    variable: "AWS_CANARY_PREPARE_ROLE_ARN"
  } and
  .aws.governedCanaryRoles.roles.approval == {
    environment: "governed-canary",
    permissions: [
      "cloudformation:DescribeStacks",
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminListGroupsForUser"
    ],
    roleName: "archon-datahub-github-governed-canary-approval",
    variable: "AWS_CANARY_APPROVAL_ROLE_ARN"
  } and
  .aws.governedCanaryRoles.roles.recovery == {
    environment: "governed-canary-recovery",
    permissions: ["cloudformation:DescribeStacks"],
    roleName: "archon-datahub-github-governed-canary-recovery",
    variable: "AWS_CANARY_RECOVERY_ROLE_ARN"
  } and
  .aws.privateLink == {
    disassociateVpcFromHostedZoneAllowed: false,
    ec2Actions: [
      "ec2:CreateTags",
      "ec2:CreateVpcEndpoint",
      "ec2:DeleteTags",
      "ec2:DeleteVpcEndpoints",
      "ec2:DescribeVpcEndpointServices",
      "ec2:DescribeVpcEndpoints",
      "ec2:ModifyVpcEndpoint"
    ],
    executionPolicyFamily: "endpoint",
    privateDnsEnabled: true,
    region: "eu-west-1",
    route53Actions: ["route53:AssociateVPCWithHostedZone"],
    route53VpcArnConditionAllowed: false,
    route53VpcCondition: "VPCId=vpc-*,VPCRegion=eu-west-1",
    serviceOwnerMustDifferFromDeploymentAccount: true
  } and
  .aws.operationalRoles == {
    judgeAccess: {
      production: {
        environment: "judge-access-production",
        roleName: "archon-production-judge-user",
        variable: "AWS_JUDGE_USER_ROLE_ARN"
      },
      staging: {
        environment: "judge-access-staging",
        roleName: "archon-staging-judge-user",
        variable: "AWS_JUDGE_USER_ROLE_ARN"
      }
    },
    managedPolicyCountPerRole: 0,
    maximumSessionDurationSeconds: 3600,
    productionObserver: {
      environment: "production-observer",
      roleName: "archon-production-posture-observer",
      variable: "AWS_READ_ROLE_ARN"
    },
    productionPagingTest: {
      environment: "production-paging-test",
      roleName: "archon-production-paging-test",
      variable: "AWS_PAGING_TEST_ROLE_ARN"
    },
    productionRuntimeRead: {
      environment: "production-observer",
      roleName: "archon-production-runtime-read",
      variable: "AWS_RUNTIME_READ_ROLE_ARN"
    }
  } and
  .aws.publicViewerDns == {
    acmActions: [
      "acm:AddTagsToCertificate",
      "acm:DeleteCertificate",
      "acm:DescribeCertificate",
      "acm:ListTagsForCertificate",
      "acm:RemoveTagsFromCertificate",
      "acm:RequestCertificate",
      "acm:UpdateCertificateOptions"
    ],
    aliasRecordTypes: ["A", "AAAA"],
    certificateExport: "DISABLED",
    certificateKeyAlgorithm: "EC_prime256v1",
    certificateRegion: "us-east-1",
    certificateTransparencyLogging: "ENABLED",
    certificateValidation: "DNS",
    cloudFrontMinimumProtocolVersion: "TLSv1.3_2025",
    deploymentVariables: {
      domainName: "ARCHON_CLOUDFRONT_DOMAIN_NAME",
      hostedZoneId: "ARCHON_CLOUDFRONT_HOSTED_ZONE_ID"
    },
    executionPolicyFamilies: {
      aliasesAndCanonicalHost: "delivery",
      certificateAndValidation: "edge"
    },
    foundationVariables: {
      productionDomainName: "PRODUCTION_CLOUDFRONT_DOMAIN_NAME",
      productionHostedZoneId: "PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID",
      stagingDomainName: "STAGING_CLOUDFRONT_DOMAIN_NAME",
      stagingHostedZoneId: "STAGING_CLOUDFRONT_HOSTED_ZONE_ID"
    },
    requiresDistinctStageHostnames: true,
    route53Actions: [
      "route53:ChangeResourceRecordSets",
      "route53:GetChange",
      "route53:GetHostedZone",
      "route53:ListResourceRecordSets"
    ],
    route53DomainsAllowed: false,
    validationRecordTypes: ["CNAME"]
  } and
  .aws.stages.staging.qualifier == "archonstg" and
  .aws.stages.production.qualifier == "archonprd" and
  (.aws.stages.staging.executionPolicyNames | length) == 10 and
  (.aws.stages.production.executionPolicyNames | length) == 10 and
  .aws.stages.staging.executionPolicyAttachments == {
    "eu-west-1": [
      "guard",
      "identity",
      "data",
      "state",
      "observability",
      "compute",
      "network",
      "endpoint",
      "delivery"
    ],
    "us-east-1": ["guard", "edge"]
  } and
  .aws.stages.staging.executionPolicyAttachments ==
    .aws.stages.production.executionPolicyAttachments and
  .aws.bootstrap == {
    customerManagedKey: false,
    minimumVersion: 6,
    pinnedVersion: 32,
    terminationProtection: true
  } and
  .oidc.foundationSubject ==
    "repo:upgradedev/archon-datahub:environment:aws-foundation" and
  .oidc.governedCanarySubjects == [
    "repo:upgradedev/archon-datahub:environment:governed-canary-prepare",
    "repo:upgradedev/archon-datahub:environment:governed-canary",
    "repo:upgradedev/archon-datahub:environment:governed-canary-recovery"
  ] and
  .oidc.operationalSubjects == [
    "repo:upgradedev/archon-datahub:environment:judge-access-production",
    "repo:upgradedev/archon-datahub:environment:judge-access-staging",
    "repo:upgradedev/archon-datahub:environment:production-observer",
    "repo:upgradedev/archon-datahub:environment:production-paging-test"
  ] and
  .evidence.containsRawAccountId == false and
  .evidence.containsRawRoleArn == false and
  .evidence.applicationStackRolePreflight == {
    allowedEntryValidations: [
      "passed",
      "requires-explicit-deploy-migration"
    ],
    deployFinalPostcheckRequiresExactBindings: true,
    entryCount: 5,
    migrationRequiredState:
      "foundation-complete-deploy-migration-required",
    readyState: "ready-for-deploy"
  }
' "${contract}" >/dev/null

jq --exit-status '
  .aws.runtimeBoundary.schemaVersion == "archon.aws-runtime-boundary/v1" and
  (.aws.runtimeBoundary.allowedActions | length) > 0 and
  (
    .aws.runtimeBoundary.approvedAwsManagedPolicies |
    keys |
    sort
  ) == [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ] and
  (
    [.aws.runtimeBoundary.allowedActions[] |
      select(
        startswith("iam:") or
        startswith("sts:") or
        startswith("account:") or
        startswith("organizations:")
      )] |
    length
  ) == 0
' "${contract}" >/dev/null

trigger_contract="$(
  sed -n '/^on:/,/^permissions:/p' "${foundation_workflow}" |
    sed '$d'
)"
grep -Fq '  workflow_dispatch:' <<<"${trigger_contract}"
for forbidden_trigger in push: pull_request: schedule: workflow_call:; do
  if grep -Fq "${forbidden_trigger}" <<<"${trigger_contract}"; then
    fail "AWS foundation must remain manual-only: ${forbidden_trigger}"
  fi
done

require_text "${foundation_workflow}" \
  'name: Bootstrap AWS foundation' \
  'group: archon-aws-control-plane' \
  'cancel-in-progress: false' \
  'name: aws-foundation' \
  'id-token: write' \
  'attestations: write' \
  'test "${GITHUB_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"' \
  'test "${GITHUB_TRIGGERING_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"' \
  'test "${CONFIRMATION_INPUT}" = "BOOTSTRAP_CDK_FOUNDATION"' \
  '$rule.prevent_self_review == false' \
  'role-to-assume: ${{ vars.AWS_FOUNDATION_ROLE_ARN }}' \
  'scripts/render-aws-foundation-policy.mjs' \
  'archon-aws-foundation-control' \
  'archon-aws-foundation-assets' \
  'archon-aws-foundation-identity' \
  'archon-aws-foundation-attachments' \
  "jq -e '.PolicyNames == []'" \
  'infra/aws/foundation/governed-canary-roles.yml' \
  'run: bash scripts/seal-cdk-bootstrap-templates.sh' \
  'run: bash scripts/reconcile-aws-foundation.sh' \
  'Clear AWS credentials before artifact handling' \
  'subject-checksums: ${{ steps.reconcile.outputs.subject }}' \
  'retention-days: 90'
require_text "${foundation_workflow}" \
  '"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"'
forbid_text "${foundation_workflow}" \
  '"arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"'
require_text "${execution_policy}" \
  'arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
forbid_text "${execution_policy}" \
  'AmazonECSTaskExecutionRolePolicy'
require_text "${bootstrap_sealer}" \
  'CDK bootstrap seal failed:' \
  'EXPECTED_BOOTSTRAP_VERSION is required' \
  'expected one CdkBootstrapVersion resource' \
  'gsub(/["\047]/, "", $2)' \
  'required logical ID is missing:' \
  'node "${patcher}"' \
  'template is missing its isolation marker' \
  'echo "${stage}_${region_slot}_path=${stage_template}"' \
  'echo "${stage}_${region_slot}_sha=${stage_sha}"' \
  'echo "path=${template}"' \
  'echo "sha=${template_sha}"' \
  'echo "version=${template_version}"' \
  'Sealed CDK bootstrap v${template_version}'
require_text "${bootstrap_patcher}" \
  "Default: 'AWS CDK: Default Resources'" \
  'Default: "AWS CDK: Default Resources"' \
  'defaultVariantCount !== 1'
if grep -Fq '${{ secrets.' "${foundation_workflow}"; then
  fail "AWS foundation must not consume long-lived GitHub secrets"
fi
if grep -E '^[[:space:]]*uses: [^@]+@(main|master|v[0-9]+)' \
  "${foundation_workflow}"; then
  fail "AWS foundation contains a mutable action reference"
fi

jq --exit-status '
  .Version == "2012-10-17" and
  ([.Statement[].Action] | flatten | index("*") | not) and
  (
    [.Statement[] | select(.Sid == "ReadFoundationManagedPolicies")] |
    length
  ) == 1 and
  (
    [.Statement[] | select(.Sid == "ReadFoundationManagedPolicies")][0] |
    .Resource |
    length
  ) == 4 and
  (
    [.Statement[] | select(.Sid == "ReadFoundationManagedPolicies")][0] |
    .Resource |
    index(
      "arn:aws:iam::${aws:PrincipalAccount}:policy/archon-aws-foundation-attachments"
    )
  ) != null and
  (
    [.Statement[] | select(.Sid == "ReconcileExactFoundationStacks")][0] |
    .Resource |
    index(
      "arn:aws:cloudformation:eu-west-1:${aws:PrincipalAccount}:stack/Archon-Governed-Canary-Roles/*"
    )
  ) != null and
  (
    [.Statement[] |
      select(.Sid == "ReconcileExactBootstrapAndDeployRoles")][0] |
    .Resource |
    map(select(contains("governed-canary"))) |
    length
  ) == 3
' "${foundation_policy}" >/dev/null

require_text "${foundation_renderer}" \
  'const policyGroups = ["control", "assets", "identity", "attachments"]' \
  '.replace(/-([a-z])/g, (_, character) => character.toUpperCase())' \
  'if (Buffer.byteLength(compact, "utf8") > 6144)' \
  'source statement Sids must be unique, non-empty strings'

renderer_runtime_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
test -d "${renderer_runtime_root}"
test ! -L "${renderer_runtime_root}"
renderer_runtime_dir="$(
  mktemp -d \
    "${renderer_runtime_root%/}/archon-foundation-renderer.XXXXXX"
)"
cleanup_renderer_runtime() {
  rm -rf -- "${renderer_runtime_dir}"
}
trap cleanup_renderer_runtime EXIT
declare -A renderer_stdout
for group in control assets identity attachments; do
  renderer_stdout["${group}"]="$(
    node "${foundation_renderer}" \
      --input "${foundation_policy}" \
      --account 123456789012 \
      --stdout-group "${group}"
  )"
  jq -e \
    --arg account "123456789012" '
      .Version == "2012-10-17" and
      (.Statement | type == "array" and length > 0) and
      (tostring | contains($account)) and
      (tostring | contains("${aws:PrincipalAccount}") | not)
    ' <<<"${renderer_stdout[${group}]}" >/dev/null
done

node "${foundation_renderer}" \
  --input "${foundation_policy}" \
  --account 123456789012 \
  --control-output "${renderer_runtime_dir}/control.json" \
  --assets-output "${renderer_runtime_dir}/assets.json" \
  --identity-output "${renderer_runtime_dir}/identity.json" \
  --attachments-output "${renderer_runtime_dir}/attachments.json"
test "$(
  find "${renderer_runtime_dir}" -mindepth 1 -maxdepth 1 -type f |
    wc -l |
    awk '{print $1}'
)" = "4"
for group in control assets identity attachments; do
  rendered_path="${renderer_runtime_dir}/${group}.json"
  test -f "${rendered_path}"
  test ! -L "${rendered_path}"
  test "$(
    jq -cS . "${rendered_path}"
  )" = "$(
    jq -cS . <<<"${renderer_stdout[${group}]}"
  )"
done
cleanup_renderer_runtime
trap - EXIT

require_text "${foundation_bootstrap}" \
  'test "${CONFIRMATION}" = "BOOTSTRAP_FOUNDATION_POLICIES"' \
  'readonly -a POLICY_GROUPS=(control assets identity attachments)' \
  'aws iam get-open-id-connect-provider' \
  'expected_attachments='\''[]'\''' \
  '--stdout-group "${group}"' \
  'aws iam create-policy' \
  'test "${compact_size}" -le 6144' \
  'role_error="$(' \
  'if grep -q '\''NoSuchEntity'\'' <<<"${role_error}"; then' \
  'aws iam create-role' \
  'LEGACY_FOUNDATION_ROLE_DESCRIPTION="GitHub OIDC role for the Archon DataHub CDK foundation bootstrap pipeline"' \
  '{"Key":"Environment","Value":"foundation"}' \
  '{"Key":"ManagedBy","Value":"github-actions"}' \
  '--argjson legacyTrust "${legacy_trust_policy}"' \
  'def normalize_actions:' \
  'jq -e '\''.AttachedPolicies == []'\'' >/dev/null' \
  'aws iam update-assume-role-policy' \
  'aws iam update-role-description' \
  'aws iam tag-role' \
  '(.Role.AssumeRolePolicyDocument | normalize_actions) ==' \
  '($trust | normalize_actions)' \
  '($expected | index($actual)) != null' \
  '(10 - (.AttachedPolicies | length)) >= 6' \
  'aws iam attach-role-policy'
forbid_text "${foundation_bootstrap}" \
  'aws iam detach-role-policy' \
  'aws iam put-role-policy' \
  'aws iam untag-role'
policy_first_line="$(
  grep -n '^for group in "${POLICY_GROUPS\[@\]}"; do$' \
    "${foundation_bootstrap}" |
    head -n 1 |
    cut -d: -f1
)"
role_adoption_line="$(
  grep -n '^role_error=' "${foundation_bootstrap}" |
    cut -d: -f1
)"
test -n "${policy_first_line}"
test -n "${role_adoption_line}"
test "${policy_first_line}" -lt "${role_adoption_line}"
legacy_zero_attachments_line="$(
  grep -n "jq -e '.AttachedPolicies == \\[\\]' >/dev/null" \
    "${foundation_bootstrap}" |
    cut -d: -f1
)"
legacy_trust_update_line="$(
  grep -n '^[[:space:]]*aws iam update-assume-role-policy' \
    "${foundation_bootstrap}" |
    cut -d: -f1
)"
test -n "${legacy_zero_attachments_line}"
test -n "${legacy_trust_update_line}"
test "${legacy_zero_attachments_line}" -lt "${legacy_trust_update_line}"

require_text "${foundation_role}" \
  'The policy-first bootstrap creates or safely adopts this' \
  'RoleName: archon-datahub-github-foundation' \
  'Action: sts:AssumeRoleWithWebIdentity' \
  'repo:${GitHubOrganization}/${GitHubRepository}:environment:${GitHubEnvironment}' \
  'policy/archon-aws-foundation-control' \
  'policy/archon-aws-foundation-assets' \
  'policy/archon-aws-foundation-identity' \
  'policy/archon-aws-foundation-attachments'
test "$(
  grep -Fc -- '- !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/archon-aws-foundation-' \
    "${foundation_role}"
)" -eq 4
forbid_text "${foundation_role}" \
  'Policies:' \
  'PolicyName:' \
  'AdministratorAccess'

require_text "${canary_roles}" \
  'RoleName: archon-datahub-github-governed-canary-prepare' \
  'RoleName: archon-datahub-github-governed-canary-approval' \
  'RoleName: archon-datahub-github-governed-canary-recovery' \
  'environment:governed-canary-prepare' \
  'environment:governed-canary' \
  'environment:governed-canary-recovery' \
  'Action: cloudformation:DescribeStacks' \
  'cognito-idp:AdminGetUser' \
  'cognito-idp:AdminListGroupsForUser' \
  'aws:ResourceTag/Application: archon-datahub' \
  'aws:ResourceTag/Environment: staging' \
  'aws:ResourceTag/ManagedBy: aws-cdk'
test "$(
  grep -Fc 'Action: sts:AssumeRoleWithWebIdentity' "${canary_roles}"
)" -eq 3
if grep -Eq \
  "^[[:space:]]*(Action:[[:space:]]*|-)[[:space:]]*['\"]?\\*['\"]?[[:space:]]*$" \
  "${canary_roles}"; then
  fail "governed canary roles contain a wildcard action"
fi

for family in \
  identity guard data state observability compute network endpoint delivery edge; do
  grep -Fq \
    "ManagedPolicyName: !Sub archon-datahub-cdk-${family}-\${DeploymentEnvironment}" \
    "${execution_policy}" ||
    fail "execution template omits ${family} managed policy"
done
require_text "${execution_policy}" \
  'CloudFrontDomainName:' \
  'CloudFrontHostedZoneId:' \
  'ArchonCdkEuWest1ExecutionPolicyArns:' \
  'ArchonCdkUsEast1ExecutionPolicyArns:' \
  'ArchonCdkExecutionPolicyNames:' \
  'ArchonRuntimeBoundaryArn:' \
  'DenySharedApiGatewayAccountMutation' \
  'DenyRuntimeBoundaryRemoval' \
  'DenyFoundationControlPlaneMutation' \
  'role/archon-staging-judge-user' \
  'role/archon-production-judge-user' \
  'role/archon-production-posture-observer' \
  'role/archon-production-runtime-read' \
  'role/archon-production-paging-test' \
  'iam:PermissionsBoundary: !Ref ArchonRuntimeBoundary' \
  'CreateOnlyTaggedSameRegionVpcEndpoints' \
  'ReconcileOnlyOwnedStageVpcEndpoints' \
  'DenyVpcEndpointOwnershipTagRemoval' \
  'ec2:VpceServiceOwner: !Ref AWS::AccountId' \
  'Action: route53:AssociateVPCWithHostedZone' \
  'route53:VPCs: VPCId=vpc-*,VPCRegion=eu-west-1' \
  'RequestOnlyExactStageViewerCertificate' \
  'acm:CertificateTransparencyLogging: ENABLED' \
  'acm:Export: DISABLED' \
  'acm:KeyAlgorithm: EC_prime256v1' \
  'TagOnlyExactStageViewerCertificateAtCreate' \
  'ReconcileOnlyExactStageViewerAliases' \
  'ReconcileOnlyExactStageDnsValidation' \
  "!Sub '_*.\${CloudFrontDomainName}'" \
  'CreateOnlyTaggedStageCloudFrontFunctions' \
  'ReconcileOnlyExactCanonicalHostFunction'
forbid_text "${execution_policy}" \
  'route53:DisassociateVPCFromHostedZone' \
  'route53:VPCs: arn:' \
  'route53:*' \
  'acm:*'
actual_route53_actions="$(
  grep -E \
    '^[[:space:]]*(Action:[[:space:]]+|-[[:space:]]+)route53:[A-Za-z0-9]+' \
    "${execution_policy}" |
    grep -Eo 'route53:[A-Za-z0-9]+' |
    sort -u
)"
expected_route53_actions="$(
  printf '%s\n' \
    'route53:AssociateVPCWithHostedZone' \
    'route53:ChangeResourceRecordSets' \
    'route53:GetChange' \
    'route53:GetHostedZone' \
    'route53:ListResourceRecordSets' |
    sort -u
)"
test "${actual_route53_actions}" = "${expected_route53_actions}" ||
  fail "execution template Route53 action inventory is not exact"
actual_acm_actions="$(
  grep -E \
    '^[[:space:]]*(Action:[[:space:]]+|-[[:space:]]+)acm:[A-Za-z0-9]+' \
    "${execution_policy}" |
    grep -Eo 'acm:[A-Za-z0-9]+' |
    sort -u
)"
expected_acm_actions="$(
  printf '%s\n' \
    'acm:AddTagsToCertificate' \
    'acm:DeleteCertificate' \
    'acm:DescribeCertificate' \
    'acm:ListTagsForCertificate' \
    'acm:RemoveTagsFromCertificate' \
    'acm:RequestCertificate' \
    'acm:UpdateCertificateOptions' |
    sort -u
)"
test "${actual_acm_actions}" = "${expected_acm_actions}" ||
  fail "execution template ACM action inventory is not exact"
if ! awk '
  /^[[:space:]]*-[[:space:]]+Sid:[[:space:]]+RequestOnlyExactStageViewerCertificate[[:space:]]*$/ {
    in_statement = 1
    next
  }
  in_statement && /^[[:space:]]*-[[:space:]]+Sid:/ {
    exit found_region ? 0 : 1
  }
  in_statement &&
    /^[[:space:]]+aws:RequestedRegion:[[:space:]]+us-east-1[[:space:]]*$/ {
      found_region = 1
    }
  END {
    if (in_statement) {
      exit found_region ? 0 : 1
    }
  }
' "${execution_policy}"; then
  fail "viewer certificate request must be region-bound to us-east-1"
fi
if ! awk '
  /^[[:space:]]*-[[:space:]]+Sid:[[:space:]]+TagOnlyExactStageViewerCertificateAtCreate[[:space:]]*$/ {
    in_statement = 1
    next
  }
  in_statement && /^[[:space:]]*-[[:space:]]+Sid:/ {
    exit (found_action && found_resource && found_application && found_environment && found_managed_by && found_region) ? 0 : 1
  }
  in_statement &&
    /^[[:space:]]+Action:[[:space:]]+acm:AddTagsToCertificate[[:space:]]*$/ {
      found_action = 1
    }
  in_statement &&
    /arn:\$\{AWS::Partition\}:acm:us-east-1:\$\{AWS::AccountId\}:certificate\/\*/ {
      found_resource = 1
    }
  in_statement &&
    /^[[:space:]]+aws:RequestTag\/Application:[[:space:]]+archon-datahub[[:space:]]*$/ {
      found_application = 1
    }
  in_statement &&
    /^[[:space:]]+aws:RequestTag\/Environment:[[:space:]]+!Ref DeploymentEnvironment[[:space:]]*$/ {
      found_environment = 1
    }
  in_statement &&
    /^[[:space:]]+aws:RequestTag\/ManagedBy:[[:space:]]+aws-cdk[[:space:]]*$/ {
      found_managed_by = 1
    }
  in_statement &&
    /^[[:space:]]+aws:RequestedRegion:[[:space:]]+us-east-1[[:space:]]*$/ {
      found_region = 1
    }
  END {
    if (in_statement) {
      exit (found_action && found_resource && found_application && found_environment && found_managed_by && found_region) ? 0 : 1
    }
  }
' "${execution_policy}"; then
  fail "viewer certificate create-time tagging policy is not exact"
fi
if awk '
  /^[[:space:]]*-[[:space:]]+Sid:/ {
    effect = ""
  }
  /^[[:space:]]+Effect:[[:space:]]+/ {
    effect = $2
  }
  effect == "Allow" &&
    /^[[:space:]]*-[[:space:]]+[a-z0-9-]+:\*[[:space:]]*$/ {
      wildcard_allow = 1
    }
  END {
    exit wildcard_allow ? 0 : 1
  }
' "${execution_policy}"; then
  fail "execution template contains a service-wide allow action"
fi

require_text "${bootstrap_patcher}" \
  '--stage' \
  '--region' \
  'CreateOrUpdateOnlyWithBootstrapExecutionRole' \
  'CreateOnlyCdkDeployChangeSet' \
  'UseOnlyCdkDeployChangeSets' \
  'cloudformation:ChangeSetName' \
  'cloudformation:RoleArn'
require_text "${inline_template_renderer}" \
  'if [[ "${GITHUB_ACTIONS:-}" != "true" ]]' \
  'RAIN_VERSION="v1.24.4"' \
  'RAIN_LINUX_AMD64_ARCHIVE_SHA256="5358d6daf35322101566376a38e37d1f89c6588479af2e20240579fc2d4c660a"' \
  'YQ_VERSION="v4.47.2"' \
  'YQ_LINUX_AMD64_SHA256="1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0"' \
  'CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES=51200' \
  'test ! -L "$1"' \
  'sha256sum --check --strict' \
  '"${rain_bin}" fmt --json --unsorted "${source_path}"' \
  '"https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"' \
  '--output-format=yaml' \
  'jq -cS' \
  "'... style=\"\" | .. style=\"flow\"'" \
  'cmp -s "${canonical_json}" "${round_trip}"' \
  '[[ "${output_path}" == "${runner_temp_root}/"* ]]'
test "$(
  grep -nF 'test ! -L "$1"' "${inline_template_renderer}" |
    cut -d: -f1
)" -lt "$(
  grep -nF 'source_path="$(realpath "$1")"' "${inline_template_renderer}" |
    cut -d: -f1
)" ||
  fail "renderer must reject a source symlink before realpath resolution"
require_text "${reconciler}" \
  'IAM_FOUNDATION_TEMPLATE' \
  'IAM_FOUNDATION_TEMPLATE_SHA' \
  'IAM_FOUNDATION_CANONICAL_JSON' \
  'IAM_FOUNDATION_SEMANTIC_SHA' \
  'IAM_FOUNDATION_YQ_BIN' \
  'IAM_FOUNDATION_YQ_SHA' \
  '.aws.inlineTemplateRendering.flowEmitter.linuxAmd64Sha256' \
  '--template-file "${IAM_FOUNDATION_TEMPLATE}"' \
  '--template-stage Original' \
  '.TemplateBody |' \
  'if type == "string" then . else tojson end' \
  '--output-format=json' \
  'mktemp "${RUNNER_TEMP}/archon-deployed-template.XXXXXX' \
  'iamFoundationTemplateSha256: $iamFoundationTemplateSha256' \
  'iamFoundationSemanticSha256: $iamFoundationSemanticSha256' \
  'IAM_TEMPLATE_SHA["${stage}"]' \
  '"${IAM_FOUNDATION_SEMANTIC_SHA}"' \
  'deployed Original template does not match the pre-OIDC canonical template' \
  '.iamDeployedTemplateSha256 == $expected' \
  'STAGING_CLOUDFRONT_DOMAIN_NAME' \
  'STAGING_CLOUDFRONT_HOSTED_ZONE_ID' \
  'PRODUCTION_CLOUDFRONT_DOMAIN_NAME' \
  'PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID' \
  'CloudFrontHostedZoneId="${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}"' \
  'STAGING_PRIMARY_BOOTSTRAP_TEMPLATE' \
  'STAGING_EDGE_BOOTSTRAP_TEMPLATE' \
  'PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE' \
  'PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE' \
  'readonly CANARY_ROLE_STACK="Archon-Governed-Canary-Roles"' \
  'Reconcile the three governed-canary read roles' \
  'Require all ten foundation stacks to be IN_SYNC' \
  "jq -e 'length == 10 and all(.[]; .stackDriftStatus == \"IN_SYNC\")'" \
  'test "${compact_policy_size}" -le 6144' \
  'test "${boundary_compact_size}" -le 6144' \
  'stackCount: 10' \
  'sourceTemplateSha256: $sourceTemplateSha256' \
  'canary_role_binding_sha=${combined_canary_binding_sha}' \
  'operational_role_binding_sha=${combined_operational_binding_sha}' \
  '.Stacks[0].StackStatus == "UPDATE_ROLLBACK_COMPLETE"' \
  'foundation-complete-deploy-migration-required' \
  'requires-explicit-deploy-migration' \
  'deployRequirement: "explicit-role-migration"' \
  'applicationStackRoleTransition: $applicationStackRoleTransition' \
  'application_stack_role_transition=${application_stack_role_transition_state}'
test "$(
  grep -Fc 'infra/aws/foundation/cdk-execution-policy.yml' "${reconciler}"
)" -eq 1 ||
  fail "reconciler may reference the oversized source template only as evidence"

require_text "${runtime_verifier}" \
  'const uncovered' \
  'const unusedAllowed' \
  'const unseenApprovedPolicies' \
  'approved managed policies absent from synthesis'
require_text "${ci_workflow}" \
  'bash tests/pipeline/aws-foundation-contracts.test.sh' \
  'scripts/bootstrap-aws-foundation-role.sh' \
  'scripts/reconcile-aws-foundation.sh' \
  'scripts/patch-cdk-bootstrap-template.mjs' \
  'scripts/render-inline-cloudformation-template.sh' \
  'scripts/seal-cdk-bootstrap-templates.sh' \
  'Seal the exact CDK bootstrap templates without AWS access' \
  'EXPECTED_BOOTSTRAP_VERSION: "32"' \
  'run: bash scripts/seal-cdk-bootstrap-templates.sh' \
  'Render the exact inline-safe IAM foundation template' \
  '"${RUNNER_TEMP}/archon-cdk-execution-policy.yaml"' \
  '"${RUNNER_TEMP}/archon-cdk-execution-policy.canonical.json"' \
  'scripts/render-aws-foundation-policy.mjs' \
  'node scripts/verify-aws-runtime-boundary.mjs'
require_text "${deploy_workflow}" \
  'group: archon-aws-control-plane' \
  'cancel-in-progress: false' \
  'AWS_DEPLOY_ROLE_ARN: ${{ vars.AWS_DEPLOY_ROLE_ARN }}' \
  'ALLOW_ABSENT=false' \
  'ALLOW_ROLE_MIGRATION=false' \
  'bash scripts/validate-cloudformation-role-bindings.sh'
require_text "${foundation_workflow}" \
  'Render the inline-safe IAM foundation template' \
  'IAM_FOUNDATION_TEMPLATE: ${{ steps.iam_foundation_template.outputs.path }}' \
  'IAM_FOUNDATION_TEMPLATE_SHA: ${{ steps.iam_foundation_template.outputs.sha }}' \
  'IAM_FOUNDATION_CANONICAL_JSON: ${{ steps.iam_foundation_template.outputs.canonical_path }}' \
  'IAM_FOUNDATION_SEMANTIC_SHA: ${{ steps.iam_foundation_template.outputs.canonical_sha }}' \
  'IAM_FOUNDATION_YQ_BIN: ${{ steps.iam_foundation_template.outputs.yq_path }}' \
  'IAM_FOUNDATION_YQ_SHA: ${{ steps.iam_foundation_template.outputs.yq_sha }}' \
  'STAGING_CLOUDFRONT_DOMAIN_NAME: ${{ vars.STAGING_CLOUDFRONT_DOMAIN_NAME }}' \
  'STAGING_CLOUDFRONT_HOSTED_ZONE_ID: ${{ vars.STAGING_CLOUDFRONT_HOSTED_ZONE_ID }}' \
  'PRODUCTION_CLOUDFRONT_DOMAIN_NAME: ${{ vars.PRODUCTION_CLOUDFRONT_DOMAIN_NAME }}' \
  'PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID: ${{ vars.PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID }}' \
  'APPLICATION_STACK_ROLE_TRANSITION: ${{ steps.reconcile.outputs.application_stack_role_transition }}' \
  'OPERATIONAL_ROLE_BINDING_SHA: ${{ steps.reconcile.outputs.operational_role_binding_sha }}' \
  'Application stack RoleARN transition:'
require_text "${deploy_role}" \
  'CloudFrontHostedZoneId:' \
  'RoleName: !Sub archon-${DeploymentEnvironment}-judge-user' \
  'RoleName: archon-production-posture-observer' \
  'RoleName: archon-production-runtime-read' \
  'RoleName: archon-production-paging-test' \
  'environment:judge-access-${DeploymentEnvironment}' \
  'environment:production-observer' \
  'environment:production-paging-test' \
  'ProductionPostureObserverRoleArn:' \
  'ProductionRuntimeReadRoleArn:' \
  'ProductionPagingTestRoleArn:' \
  'acm:DescribeCertificate' \
  'cloudfront:GetDistributionConfig' \
  'cloudfront:DescribeFunction' \
  'route53:GetHostedZone' \
  'route53:ListResourceRecordSets' \
  'ec2:DescribeAvailabilityZones' \
  'ec2:DescribeSecurityGroupRules' \
  'ec2:DescribeSecurityGroups' \
  'ec2:DescribeSubnets' \
  'ec2:DescribeVpcEndpointServices' \
  'ec2:DescribeVpcEndpoints'
test "$(
  grep -Fc 'Action: sts:AssumeRoleWithWebIdentity' "${deploy_role}"
)" -eq 5
if grep -Eq \
  "^[[:space:]]*(Action:[[:space:]]*|-)[[:space:]]*['\"]?\\*['\"]?[[:space:]]*$" \
  "${deploy_role}"; then
  fail "deploy and operational roles contain a wildcard action"
fi
require_text "${foundation_policy}" \
  'role/archon-staging-judge-user' \
  'role/archon-production-judge-user' \
  'role/archon-production-posture-observer' \
  'role/archon-production-runtime-read' \
  'role/archon-production-paging-test'

require_text "${api_gateway_account}" \
  'AWS::ApiGateway::Account' \
  'RoleName: archon-datahub-apigateway-cloudwatch-logs' \
  'PolicyName: archon-apigateway-cloudwatch-logs'

for path in \
  "${foundation_policy}" \
  "${foundation_role}" \
  "${canary_roles}"; do
  if grep -Eiq '(^|[^[:alnum:]_-])(acm|route53|route53domains):' "${path}"; then
    fail "${path#${repository_root}/} must not grant or deny ACM/Route53"
  fi
  if grep -Fq 'AdministratorAccess' "${path}"; then
    fail "${path#${repository_root}/} must not refer to AdministratorAccess"
  fi
done
forbid_text "${deploy_role}" \
  'route53domains:*' \
  'acm:*' \
  'route53:*'
if grep -Fq 'AdministratorAccess' "${execution_policy}"; then
  fail "execution template must not refer to AdministratorAccess"
fi

require_text "${runbook}" \
  'pinned CDK CLI `2.1133.0`' \
  'version `32`' \
  'ten CloudFormation stack instances' \
  '`Archon-Governed-Canary-Roles`' \
  '`archon-aws-foundation-control`' \
  '`archon-aws-foundation-assets`' \
  '`archon-aws-foundation-identity`' \
  '`archon-aws-foundation-attachments`' \
  '`STAGING_CLOUDFRONT_DOMAIN_NAME`' \
  '`STAGING_CLOUDFRONT_HOSTED_ZONE_ID`' \
  '`PRODUCTION_CLOUDFRONT_DOMAIN_NAME`' \
  '`PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID`' \
  '`AWS_CANARY_PREPARE_ROLE_ARN`' \
  '`AWS_CANARY_APPROVAL_ROLE_ARN`' \
  '`AWS_CANARY_RECOVERY_ROLE_ARN`' \
  '`prevent_self_review=false`' \
  'not account-grade isolation' \
  'policy-first' \
  'On a fresh account' \
  'On an existing account' \
  'current policyless role' \
  'Before any role update' \
  'missing canonical `Sid`' \
  'Every other mismatch fails closed' \
  '`foundation-complete-deploy-migration-required`' \
  '`requires-explicit-deploy-migration`' \
  '`ready-for-deploy`'
