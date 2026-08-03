#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
foundation_workflow="${repository_root}/.github/workflows/aws-foundation.yml"
deploy_workflow="${repository_root}/.github/workflows/deploy.yml"
ci_workflow="${repository_root}/.github/workflows/ci.yml"
core_migration_state_test="${repository_root}/tests/pipeline/aws-foundation-core-ami-policy-migration-state.test.sh"
contract="${repository_root}/contracts/aws-foundation-v1.json"
migration_contract="${repository_root}/contracts/aws-foundation-policy-migration-v1.json"
core_migration_contract="${repository_root}/contracts/aws-foundation-core-ami-policy-migration-v1.json"
publisher_migration_contract="${repository_root}/contracts/aws-foundation-cloud-runtime-publisher-policy-migration-v1.json"
publisher_migration_entry="${repository_root}/.github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration.yml"
publisher_migration_driver="${repository_root}/.github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration-driver.yml"
publisher_migration_cleanup="${repository_root}/.github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration-cleanup.yml"
publisher_migration_common="${repository_root}/scripts/aws-foundation-cloud-runtime-publisher-policy-migration-common.sh"
publisher_migration_authorization="${repository_root}/scripts/aws-foundation-cloud-runtime-publisher-policy-migration-authorization.sh"
publisher_migration_state="${repository_root}/scripts/aws-foundation-cloud-runtime-publisher-policy-migration-state.sh"
publisher_migration_runner="${repository_root}/scripts/run-aws-foundation-cloud-runtime-publisher-policy-migration.sh"
cloud_runtime_workflow="${repository_root}/.github/workflows/datahub-cloud-runtime-image.yml"
infra_package_manifest="${repository_root}/infra/aws/package.json"
infra_package_lock="${repository_root}/infra/aws/package-lock.json"
foundation_policy="${repository_root}/infra/aws/foundation/github-actions-foundation-policy.json"
foundation_role="${repository_root}/infra/aws/foundation/github-actions-foundation-role.yml"
deploy_role="${repository_root}/infra/aws/foundation/github-actions-deploy-role.yml"
canary_roles="${repository_root}/infra/aws/foundation/governed-canary-roles.yml"
execution_policy="${repository_root}/infra/aws/foundation/cdk-execution-policy.yml"
api_gateway_account="${repository_root}/infra/aws/foundation/api-gateway-account.yml"
bootstrap_patcher="${repository_root}/scripts/patch-cdk-bootstrap-template.mjs"
bootstrap_sealer="${repository_root}/scripts/seal-cdk-bootstrap-templates.sh"
canonical_flow_renderer="${repository_root}/scripts/render-canonical-flow-yaml.mjs"
inline_template_renderer="${repository_root}/scripts/render-inline-cloudformation-template.sh"
foundation_renderer="${repository_root}/scripts/render-aws-foundation-policy.mjs"
foundation_policy_validator="${repository_root}/scripts/validate-aws-foundation-policy.jq"
foundation_bootstrap="${repository_root}/scripts/bootstrap-aws-foundation-role.sh"
dependency_patcher="${repository_root}/scripts/patch-cdk-brace-expansion.sh"
dependency_audit_verifier="${repository_root}/scripts/verify-cdk-npm-audit-compensation.sh"
dependency_override_verifier="${repository_root}/scripts/verify-exact-npm-overrides.mjs"
reconciler="${repository_root}/scripts/reconcile-aws-foundation.sh"
drift_poller="${repository_root}/scripts/aws-cloudformation-drift.sh"
drift_poller_test="${repository_root}/tests/pipeline/aws-cloudformation-drift-poll.test.sh"
failure_sanitizer="${repository_root}/scripts/sanitize-cloudformation-failure.mjs"
failure_sanitizer_test="${repository_root}/tests/pipeline/cloudformation-failure-sanitizer.test.mjs"
iam_resource_arn_verifier="${repository_root}/scripts/verify-iam-policy-resource-arns.mjs"
iam_resource_arn_verifier_test="${repository_root}/tests/pipeline/iam-policy-resource-arn-verifier.test.mjs"
runtime_verifier="${repository_root}/scripts/verify-aws-runtime-boundary.mjs"
role_binding_validator="${repository_root}/scripts/validate-cloudformation-role-bindings.sh"
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
  "${core_migration_state_test}" \
  "${contract}" \
  "${migration_contract}" \
  "${core_migration_contract}" \
  "${publisher_migration_contract}" \
  "${publisher_migration_entry}" \
  "${publisher_migration_driver}" \
  "${publisher_migration_cleanup}" \
  "${publisher_migration_common}" \
  "${publisher_migration_authorization}" \
  "${publisher_migration_state}" \
  "${publisher_migration_runner}" \
  "${cloud_runtime_workflow}" \
  "${infra_package_manifest}" \
  "${infra_package_lock}" \
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
  "${foundation_policy_validator}" \
  "${foundation_bootstrap}" \
  "${dependency_patcher}" \
  "${dependency_audit_verifier}" \
  "${dependency_override_verifier}" \
  "${reconciler}" \
  "${drift_poller}" \
  "${drift_poller_test}" \
  "${failure_sanitizer}" \
  "${failure_sanitizer_test}" \
  "${iam_resource_arn_verifier}" \
  "${iam_resource_arn_verifier_test}" \
  "${runtime_verifier}" \
  "${role_binding_validator}" \
  "${runbook}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must be a regular file"
done

node --test \
  "${failure_sanitizer_test}" \
  "${iam_resource_arn_verifier_test}"

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
  .aws.toolchain == {
    awsCdkCliVersionSource:
      "infra/aws/package-lock.json#packages/node_modules/aws-cdk/version",
    installedAwsCdkCliMatchesLock: true,
    nodeVersion: "22.23.1",
    npmVersion: "10.9.8"
  } and
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
    identityRoleMigration: {
      baselineCanonicalSha256:
        "afda76cf8cfddd34c876147a4b228dd51b63edc4fd810f6793eb22d462beb553",
      baselineDefaultVersion: "v1",
      contract:
        "contracts/aws-foundation-cloud-runtime-publisher-policy-migration-v1.json",
      exactRoleDelta: [
        "archon-datahub-github-staging-cloud-trial",
        "archon-datahub-github-production-cloud-trial",
        "archon-datahub-cloud-runtime-publish-production"
      ],
      policyName: "archon-aws-foundation-identity",
      targetCanonicalSha256:
        "f8aab593f428ac9d990cefb525d0919241e81c42b09f22d737a97d1fd3dc18a3",
      targetVersion: "v2",
      workflow:
        ".github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration.yml"
    },
    maximumDocumentBytes: 6144,
    migrationContract:
      "contracts/aws-foundation-policy-migration-v1.json",
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
      name: "scripts/render-canonical-flow-yaml.mjs",
      runtime: "node-22.23.1",
      scalarPolicy: "strict-ascii-plain-or-json-quoted"
    },
    format: "canonical-flow-yaml",
    iamPolicyResourceArnValidation: {
      directStrings: true,
      intrinsicSubStrings: true,
      malformedOrIncompleteArns: "forbidden",
      partitionResolution: "literal-aws-or-exact-AWS::Partition-ref",
      serviceSegment: "literal-lowercase-token",
      verifier: "scripts/verify-iam-policy-resource-arns.mjs",
      wildcardServiceSegments: "forbidden"
    },
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
    },
    yamlParser: {
      linuxAmd64Sha256:
        "1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0",
      name: "mikefarah/yq",
      version: "v4.47.2"
    }
  } and
  .aws.sharedApiGatewayLogging == {
    external: {
      bindingSha256Variable: "AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256",
      managedStackMustBeAbsent: true,
      mutation: "none",
      sameAccountRoleArnRequired: true,
      takeover: "forbidden"
    },
    managed: {
      inlinePolicyName: "archon-apigateway-cloudwatch-logs",
      roleName: "archon-datahub-apigateway-cloudwatch-logs",
      stackName: "Archon-Shared-ApiGateway-Logging"
    },
    ownershipModes: ["foundation-managed", "external-pinned"],
    region: "eu-west-1"
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
    permissions: [
      "cloudformation:DescribeStacks",
      "secretsmanager:GetSecretValue",
      "kms:Decrypt"
    ],
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
  .aws.applicationStackRoleBinding == {
    deployRoleArnTemplate:
      "arn:aws:iam::<account-id>:role/archon-datahub-github-<stage>-deploy",
    postDeploy: {
      allowAbsent: false,
      allowRoleMigration: false
    },
    preflight: {
      allowAbsent: true,
      allowRoleMigration: false
    },
    validator: "scripts/validate-cloudformation-role-bindings.sh"
  } and
  .aws.stages.staging.qualifier == "archonstg" and
  .aws.stages.production.qualifier == "archonprd" and
  .aws.stages.staging.applicationStackRoleBindings == [
    {
      stackName: "Archon-staging-Edge",
      region: "us-east-1",
      bootstrapQualifier: "archonstg"
    },
    {
      stackName: "Archon-staging-Core",
      region: "eu-west-1",
      bootstrapQualifier: "archonstg"
    },
    {
      stackName: "Archon-staging-Judge",
      region: "eu-west-1",
      bootstrapQualifier: "archonstg"
    }
  ] and
  .aws.stages.production.applicationStackRoleBindings == [
    {
      stackName: "Archon-production-Edge",
      region: "us-east-1",
      bootstrapQualifier: "archonprd"
    },
    {
      stackName: "Archon-production-Core",
      region: "eu-west-1",
      bootstrapQualifier: "archonprd"
    },
    {
      stackName: "Archon-production-Judge",
      region: "eu-west-1",
      bootstrapQualifier: "archonprd"
    }
  ] and
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
    entryCount: 6,
    perStageDeployEntryCount: 3,
    migrationRequiredState:
      "foundation-complete-deploy-migration-required",
    readyState: "ready-for-deploy"
  } and
  .evidence.driftVerification == {
    awsSdkMaxAttempts: 1,
    cliConnectTimeoutSeconds: 5,
    cliReadTimeoutSeconds: 15,
    coverage: "cloudformation-supported-resources",
    exactStackIncarnation: true,
    failureMode: "fail-closed",
    globalDeadline: "hard-wall-clock",
    globalTimeoutSeconds: 900,
    helper: "scripts/aws-cloudformation-drift.sh",
    maximumConsecutiveApiFailuresPerStack: 3,
    maximumPollAttemptsPerStack: 120,
    method: "detect-then-bounded-describe-poll",
    pollDelaySeconds: 2,
    rawAwsStderr: "suppressed",
    responseBinding: ["StackDriftDetectionId", "StackId", "Timestamp", "DriftInformation.LastCheckTimestamp"],
    finalStackBinding: {
      method: "bounded-describe-stacks-poll",
      maximumAttempts: 5,
      pollDelaySeconds: 2,
      timestampComparison: "normalized-utc-monotonic-lower-bound",
      currentOrNewerInSyncProjection: "accept",
      currentDriftedProjection: "fail-closed",
      currentOrNewerIndeterminateProjection: "bounded-retry",
      staleOrUnpublishedProjection: "bounded-retry",
      selectionMismatch: "fail-closed",
      malformedProjection: "fail-closed"
    },
    staleResourceEvidence: "forbidden",
    terminalSuccess: {
      detectionStatus: "DETECTION_COMPLETE",
      driftedStackResourceCount: 0,
      returnedResourceStatuses: ["IN_SYNC"],
      stackDriftStatus: "IN_SYNC"
    },
    unsupportedCliWaiter: "forbidden"
  } and  .evidence.failureDiagnostics == {
    allowlistedStackLabels: [
      "governed-canary-roles",
      "production-bootstrap-edge",
      "production-bootstrap-primary",
      "production-deploy",
      "production-iam",
      "shared-api-gateway",
      "staging-bootstrap-edge",
      "staging-bootstrap-primary",
      "staging-deploy",
      "staging-iam"
    ],
    artifactFiles: ["SHA256SUMS", "cfn-failure.json"],
    artifactRetentionDays: 90,
    artifactUpload: "explicit-files-only",
    autoRecovery: "forbidden",
    explicitIncidentRecoveryContract: "contracts/aws-incident-recovery-v1.json",
    explicitIncidentRecoveryStatus: "recovered-delete-complete-cleanup-proven",
    canonicalJson: true,
    credentialClearProofRequired: true,
    diagnosticCount: 1,
    digestFields: [
      "logicalResourceId",
      "reasonCategory",
      "resourceStatus",
      "resourceType",
      "schemaVersion",
      "stackLabel",
      "stackStatus"
    ],
    fields: [

      "diagnosticSha256",
      "logicalResourceId",
      "reasonCategory",
      "resourceStatus",
      "resourceType",
      "schemaVersion",
      "stackLabel",
      "stackStatus"
    ],
    managedCommandOutput: "suppressed",
    maxInputBytes: 1048576,
    maxRecentEvents: 100,
    deprioritizedReasonCategories: ["dependency-failure"],
    eventOrder: "cloudformation-newest-first",
    eventSelection: "newest-non-dependency-failed-else-newest-failed",
    postCredentialDigestRecomputed: true,
    rawReasonHashing: false,
    rawReasonRetention: false,
    recursiveInventory: "exact-two-root-regular-files",
    schemaVersion: "archon.aws-foundation-cfn-failure/v1",
    stackIdentity: "allowlisted-label-only",
    unknownReasonCategoryEligible: true
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
        startswith("account:") or
        startswith("organizations:")
      )] |
    length
  ) == 0 and
  (
    [.aws.runtimeBoundary.allowedActions[] |
      select(startswith("sts:"))] |
    sort
  ) == ["sts:AssumeRole", "sts:GetCallerIdentity"]
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
  'group: archon-governed-canary-mutation-recovery' \
  'cancel-in-progress: false' \
  'name: aws-foundation' \
  'id-token: write' \
  'attestations: write' \
  'test "${GITHUB_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"' \
  'test "${GITHUB_TRIGGERING_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"' \
  'test "${CONFIRMATION_INPUT}" = "BOOTSTRAP_CDK_FOUNDATION"' \
  '$rule.prevent_self_review == false' \
  'AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256: ${{ vars.AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256 }}' \
  '[[ "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" =~ ^[0-9a-f]{64}$ ]]' \
  'SHARED_API_GATEWAY_MODE: ${{ steps.reconcile.outputs.shared_api_gateway_mode }}' \
  'DRIFT_STACK_COUNT: ${{ steps.reconcile.outputs.drift_stack_count }}' \
  'Shared API Gateway logging account: pinned external binding, unchanged, no takeover' \
  'Managed stack inventory: \`9\` plus one external account binding' \
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
  'id: clear_aws_credentials' \
  'echo "cleared=true" >>"${GITHUB_OUTPUT}"' \
  'subject-checksums: ${{ steps.reconcile.outputs.subject }}' \
  'retention-days: 90' \
  'if: ${{ always() }}' \
  'Validate checksum-sealed sanitized failure evidence' \
  'if: ${{ failure() && steps.clear_aws_credentials.outputs.cleared' \
  'Retain checksum-sealed sanitized foundation failure evidence' \
  '-n "${AWS_ACCESS_KEY_ID:-}"' \
  '-n "${AWS_SECRET_ACCESS_KEY:-}"' \
  '-n "${AWS_SESSION_TOKEN:-}"' \
  '-n "${AWS_SECURITY_TOKEN:-}"' \
  'find -P "${FAILURE_EVIDENCE_DIR}"' \
  'LC_ALL=C sort -z' \
  'jq -cS .' \
  'cmp -s' \
  '.diagnosticSha256 == $computedDigest' \
  'path: |' \
  '${{ runner.temp }}/aws-foundation-failure/SHA256SUMS' \
  '${{ runner.temp }}/aws-foundation-failure/cfn-failure.json'
require_text "${foundation_workflow}" \
  'explicitIncidentRecoveryContract:' \
  '"contracts/aws-incident-recovery-v1.json"' \
  'explicitIncidentRecoveryStatus:' \
  '"recovered-delete-complete-cleanup-proven"' \
  '"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"'
require_text "${foundation_workflow}" \
  'test "${NODE_VERSION}" = "${contract_node_version}"' \
  'test "${NPM_VERSION}" = "${contract_npm_version}"' \
  'test "$(node --version)" = "v${contract_node_version}"' \
  'test "$(npm --version)" = "${contract_npm_version}"' \
  '.packages["node_modules/aws-cdk"].version' \
  'test("^[0-9]+\\.[0-9]+\\.[0-9]+$")' \
  'test "${installed_cdk_version}" = "${locked_cdk_version}"' \
  "printf 'Verified locked AWS CDK CLI %s\\n'"
require_text "${reconciler}" \
  'infra/aws/package.json' \
  'infra/aws/package-lock.json' \
  'scripts/patch-cdk-brace-expansion.sh' \
  'scripts/seal-cdk-bootstrap-templates.sh' \
  'scripts/verify-cdk-npm-audit-compensation.sh' \
  'scripts/verify-exact-npm-overrides.mjs'
failure_validation_line="$(
  grep -nF 'Validate checksum-sealed sanitized failure evidence' \
    "${foundation_workflow}" | cut -d: -f1
)"
failure_upload_line="$(
  grep -nF 'Retain checksum-sealed sanitized foundation failure evidence' \
    "${foundation_workflow}" | cut -d: -f1
)"
credential_clear_line="$(
  grep -nF 'Clear AWS credentials before artifact handling' \
    "${foundation_workflow}" | cut -d: -f1
)"
test "${credential_clear_line}" -lt "${failure_validation_line}" &&
  test "${failure_validation_line}" -lt "${failure_upload_line}" ||
  fail "failure evidence must be validated after credentials clear and before upload"
if grep -Fq 'path: ${{ runner.temp }}/aws-foundation-failure/' \
  "${foundation_workflow}"; then
  fail "failure evidence upload must name only the two sealed files"
fi
grep -Fq "steps.clear_aws_credentials.outputs.cleared == 'true'" \
  "${foundation_workflow}" ||
  fail "failure evidence handling must require credential-clear proof"
grep -Fq "steps.failure_evidence.outputs.available == 'true'" \
  "${foundation_workflow}" ||
  fail "failure evidence upload must require a validated diagnostic"
forbid_text "${foundation_workflow}" \
  '2.1133.0'
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
  '"Archon-staging-Core"' \
  '"Archon-staging-Judge"' \
  '"Archon-production-Core"' \
  '"Archon-production-Judge"' \
  'defaultVariantCount !== 1'
forbid_text "${bootstrap_patcher}" \
  '["Archon-staging", "Archon-Registry"]' \
  '["Archon-production"]'
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
  ) == 3 and
  (
    [.Statement[] |
      select(.Sid == "InspectExistingApplicationStackRoles")][0] |
    .Resource |
    sort
  ) == (
    [
      "arn:aws:cloudformation:us-east-1:${aws:PrincipalAccount}:stack/Archon-staging-Edge/*",
      "arn:aws:cloudformation:eu-west-1:${aws:PrincipalAccount}:stack/Archon-staging-Core/*",
      "arn:aws:cloudformation:eu-west-1:${aws:PrincipalAccount}:stack/Archon-staging-Judge/*",
      "arn:aws:cloudformation:us-east-1:${aws:PrincipalAccount}:stack/Archon-production-Edge/*",
      "arn:aws:cloudformation:eu-west-1:${aws:PrincipalAccount}:stack/Archon-production-Core/*",
      "arn:aws:cloudformation:eu-west-1:${aws:PrincipalAccount}:stack/Archon-production-Judge/*"
    ] |
    sort
  ) and
  (
    [.Statement[] |
      select(.Sid == "ReconcileExactCoreAmiFoundationStack")] |
    length
  ) == 1 and
  (
    [.Statement[] |
      select(.Sid == "ReconcileExactCoreAmiFoundationRoles")] |
    length
  ) == 1 and
  (
    [.Statement[] |
      select(.Sid == "ReconcileExactCoreAmiBuilderProfile")] |
    length
  ) == 1 and
  (
    [.Statement[] |
      select(.Sid == "AttachExactCoreAmiBuilderSsmPolicy")] |
    length
  ) == 1 and
  (
    [.Statement[] |
      select(.Sid == "PassExactCoreAmiBuilderRoleForProfile")] |
    length
  ) == 1 and
  (
    [.Statement[] |
      select(.Sid == "ReconcileExactBootstrapAndDeployRoles")][0] |
    .Resource |
    map(select(endswith("-cloud-trial"))) |
    sort
  ) == (
    [
      "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-github-production-cloud-trial",
      "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-github-staging-cloud-trial"
    ] |
    sort
  )
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

jq --exit-status '
  ([.Statement[].Sid] |
    index("ReconcileExactCoreAmiFoundationStack")) != null and
  ([.Statement[].Sid] |
    index("ReconcileExactCoreAmiFoundationRoles")) != null and
  ([.Statement[].Sid] |
    index("ReconcileExactCoreAmiBuilderProfile")) != null and
  ([.Statement[].Sid] |
    index("AttachExactCoreAmiBuilderSsmPolicy")) != null and
  ([.Statement[].Sid] |
    index("PassExactCoreAmiBuilderRoleForProfile")) != null
' <<<"${renderer_stdout[control]}" >/dev/null
jq --exit-status '
  ([.Statement[].Sid] |
    index("ReconcileExactBootstrapAndDeployRoles")) != null
' <<<"${renderer_stdout[identity]}" >/dev/null

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

publisher_migration_runtime="${renderer_runtime_dir}/publisher-migration"
(
  export GITHUB_ACTIONS=true
  export RUNNER_TEMP="${publisher_migration_runtime}"
  export GITHUB_OUTPUT="${publisher_migration_runtime}/github-output"
  export AWS_ACCOUNT_ID=123456789012
  mkdir -p "${RUNNER_TEMP}"
  : >"${GITHUB_OUTPUT}"
  # shellcheck source=/dev/null
  source "${publisher_migration_common}"
  # Stub only account-bound digests; execute the real renderer and jq filters.
  iam_policy_sha() {
    local policy="$1"
    if [[ "${policy}" == "${OLD_POLICY}" ]]; then
      jq -er '.policy.liveBaseline.canonicalSha256' "${CONTRACT}"
    elif [[ "${policy}" == "${NEW_POLICY}" ]]; then
      jq -er '.policy.target.canonicalSha256' "${CONTRACT}"
    else
      return 1
    fi
  }
  render_policy_documents
)

core_migration_common="${repository_root}/scripts/aws-foundation-core-ami-policy-migration-common.sh"
test -f "${core_migration_common}"
test ! -L "${core_migration_common}"
core_migration_runtime="${renderer_runtime_dir}/core-policy-migration"
(
  export GITHUB_ACTIONS=true
  export RUNNER_TEMP="${core_migration_runtime}"
  export GITHUB_OUTPUT="${core_migration_runtime}/github-output"
  export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?CI must provide AWS_ACCOUNT_ID}"
  [[ "${AWS_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] ||
    fail "CI AWS_ACCOUNT_ID must be exactly 12 digits"
  mkdir -p "${RUNNER_TEMP}"
  : >"${GITHUB_OUTPUT}"
  shopt -s extdebug
  # shellcheck source=/dev/null
  source "${core_migration_common}"
  for function_name in \
    iam_policy_sha \
    validate_policy_delta \
    render_policy_documents; do
    function_metadata="$(declare -F "${function_name}")" ||
      fail "Core migration renderer function is missing: ${function_name}"
    read -r resolved_name resolved_line resolved_source <<<"${function_metadata}"
    [[ "${resolved_name}" == "${function_name}" &&
      "${resolved_line}" =~ ^[1-9][0-9]*$ &&
      "${resolved_source}" == "${core_migration_common}" ]] ||
      fail "Core migration renderer function has unexpected provenance: ${function_name}"
  done
  render_policy_documents

  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" \
    --slurpfile contract "${CONTRACT}" \
    --slurpfile current "${NEW_POLICY}" '
      def bind_resources:
        map(gsub("\\$\\{aws:PrincipalAccount\\}"; $account)) | sort;
      . as $old |
      ($current[0]) as $new |
      ($contract[0].policy.exactDelta) as $delta |
      ($delta.resourceReplacements[0]) as $replacement |
      ($replacement.statementSid) as $sid |
      ($replacement.baselineResources | bind_resources) as $baseline |
      ($replacement.targetResources | bind_resources) as $target |
      ([$old.Statement[] | select(.Sid == $sid)] | length) == 1 and
      ([$new.Statement[] | select(.Sid == $sid)] | length) == 1 and
      ([$old.Statement[] | select(.Sid == $sid)][0].Resource | sort) ==
        $baseline and
      ([$new.Statement[] | select(.Sid == $sid)][0].Resource | sort) ==
        $target and
      all($delta.newStatementSids[];
        . as $newSid |
        ([$old.Statement[] | select(.Sid == $newSid)] | length) == 0 and
        ([$new.Statement[] | select(.Sid == $newSid)] | length) == 1)
    ' "${OLD_POLICY}" >/dev/null ||
      fail "Core migration did not reconstruct the exact historical v2"

  assert_core_delta_rejects() {
    local label="$1"
    local candidate_new="$2"
    local candidate_old="$3"
    if validate_policy_delta \
      "${candidate_new}" "${candidate_old}" >/dev/null 2>&1; then
      fail "Core migration delta validator accepted ${label}"
    fi
  }

  negative_new="${RUNNER_TEMP}/core-negative-new.json"
  negative_old="${RUNNER_TEMP}/core-negative-old.json"
  jq '
    (.Statement[] |
      select(.Sid == "InspectExistingApplicationStackRoles") |
      .Resource[0]) += "-drift"
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "target resource drift" "${negative_new}" "${OLD_POLICY}"

  jq '
    (.Statement[] |
      select(.Sid == "InspectExistingApplicationStackRoles") |
      .Action) = ["cloudformation:ListStacks"]
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "replacement action drift" "${negative_new}" "${OLD_POLICY}"

  jq '
    (.Statement[] |
      select(.Sid == "InspectExistingApplicationStackRoles") |
      .Effect) = "Deny"
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "replacement effect drift" "${negative_new}" "${OLD_POLICY}"

  jq '
    .Statement |= map(
      select(.Sid != "ReconcileExactCoreAmiFoundationStack")
    )
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "missing Core statement" "${negative_new}" "${OLD_POLICY}"

  jq '
    .Statement += [{
      Sid: "UnexpectedCoreAmiPermission",
      Effect: "Allow",
      Action: ["iam:GetRole"],
      Resource: ["arn:aws:iam::123456789012:role/unexpected"]
    }] |
    .Statement |= sort_by(.Sid)
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "extra statement" "${negative_new}" "${OLD_POLICY}"

  jq '
    (.Statement[] | select(.Sid == "VerifyCaller") | .Action[0]) =
      "sts:GetFederationToken"
  ' "${NEW_POLICY}" >"${negative_new}"
  assert_core_delta_rejects \
    "unrelated statement drift" "${negative_new}" "${OLD_POLICY}"

  jq '
    (.Statement[] |
      select(.Sid == "InspectExistingApplicationStackRoles") |
      .Resource[0]) += "-drift"
  ' "${OLD_POLICY}" >"${negative_old}"
  assert_core_delta_rejects \
    "baseline resource drift" "${NEW_POLICY}" "${negative_old}"
)
core_migration_render_test_block="$(
  sed -n '/^core_migration_common=/,/^)/p' "${BASH_SOURCE[0]}"
)"

test "$(
  grep -Ec '^[[:space:]]{2}render_policy_documents$' <<<"${core_migration_render_test_block}"
)" -eq 1 || fail "Core migration renderer test must execute one real render"

jq -e --slurpfile coreMigration "${core_migration_contract}" '
  .aws.coreAmiFoundation.policyMigration as $summary |
  $coreMigration[0] as $migration |
  [$migration.policy.liveBaseline[] | select(.isDefault == true)] as $defaults |
  ($defaults | length) == 1 and
  $summary.contract ==
    "contracts/aws-foundation-core-ami-policy-migration-v1.json" and
  $summary.workflow == $migration.workflow.entry and
  $summary.policyName == $migration.policy.name and
  $summary.baselineDefaultVersion == $defaults[0].versionId and
  $summary.baselineCanonicalSha256 == $defaults[0].canonicalSha256 and
  $summary.targetVersion == $migration.policy.target.expectedVersionId and
  ($summary.deltaSids | sort) ==
    ($migration.policy.exactDelta.newStatementSids | sort) and
  ($summary.replacementSids | sort) ==
    ($migration.policy.exactDelta.resourceReplacements |
      map(.statementSid) | sort)
' "${contract}" >/dev/null ||
  fail "Foundation summary and Core policy migration contract differ"

jq --exit-status \
  --slurpfile migration "${migration_contract}" \
  --from-file "${foundation_policy_validator}" \
  "${foundation_policy}" >/dev/null

wrong_source_policy="${renderer_runtime_dir}/wrong-source-policy.json"
jq '
  . as $policy |
  (.Statement[] |
    select(.Sid == "ReadExactStagePoliciesForDrift") |
    .Resource) =
  ($policy.Statement[] |
    select(.Sid == "ReconcileExactBootstrapBuckets") |
    .Resource)
' "${foundation_policy}" >"${wrong_source_policy}"
missing_source_sid_policy="${renderer_runtime_dir}/missing-source-sid-policy.json"
jq '
  .Statement |= map(
    select(.Sid != "ReadExactStagePoliciesForDrift")
  )
' "${foundation_policy}" >"${missing_source_sid_policy}"
for invalid_policy in \
  "${wrong_source_policy}" \
  "${missing_source_sid_policy}"; do
  if jq --exit-status \
    --slurpfile migration "${migration_contract}" \
    --from-file "${foundation_policy_validator}" \
    "${invalid_policy}" >/dev/null 2>&1; then
    fail "shared foundation policy validator accepted $(basename "${invalid_policy}")"
  fi
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
  'ScaleOnlyStageCoreRuntime' \
  'InvokeOnlyReviewedAnalyticsModels' \
  'EmitOnlyCoreRuntimeMetrics' \
  'UseOnlyStageTableStreams' \
  'CreateOnlyTaggedCoreSessionEndpoints' \
  'TagOnlyNewCoreSessionEndpoints' \
  'ReconcileOnlyOwnedCoreSessionEndpoints' \
  'InspectOnlyEuWest1CoreResources' \
  'UseOnlyStageRuntimeEncryptionKeys' \
  'ReadOnlyStageMutationVerificationKeys' \
  'SignOnlyStageGovernedMutations' \
  'InvokeOnlyStageRuntimeFunctions' \
  'ObserveOnlyStageCloudCheckpointVersioning' \
  'AssumeOnlyStageCoreScopedRuntimeRoles' \
  'ConfirmOnlyCurrentRuntimeIdentity' \
  'DenyVersionDeletionOutsideCloudCheckpointResets' \
  'kms:SigningAlgorithm: ECDSA_SHA_256' \
  'alias/archon/${DeploymentEnvironment}/datahub-core-mutation-signing' \
  'bedrock:InferenceProfileArn: !Sub arn:aws:bedrock:eu-west-1:${AWS::AccountId}:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0' \
  'arn:aws:bedrock:eu-*::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0' \
  'secret:archon/${DeploymentEnvironment}/datahub-cloud/*' \
  '- dynamodb:ListStreams' \
  'NotResource: !Sub arn:aws:s3:::archon-${DeploymentEnvironment}-cloud-checkpoints-*/cloud-runtime/v2/*' \
  'DenySharedApiGatewayAccountMutation' \
  'DenyRuntimeBoundaryRemoval' \
  'DenyFoundationControlPlaneMutation' \
  'DenyProductionNamedBuckets' \
  'DenyStagingNamedBuckets' \
  'arn:${AWS::Partition}:s3:::archon-production-*' \
  'arn:${AWS::Partition}:s3:::archon-production-*/*' \
  'arn:${AWS::Partition}:s3:::archon-staging-*' \
  'arn:${AWS::Partition}:s3:::archon-staging-*/*' \
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
  'Action: sts:*' \
  'kms:Describe*' \
  'application-inference-profile' \
  'secret:archon/${DeploymentEnvironment}/datahub-read-' \
  'secret:archon/${DeploymentEnvironment}/datahub-write-' \
  'route53:DisassociateVPCFromHostedZone' \
  'route53:VPCs: arn:' \
  'route53:*' \
  'acm:*' \
  'DenyProductionNamedResources' \
  'DenyStagingNamedResources' \
  'arn:${AWS::Partition}:*:*:${AWS::AccountId}:'
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
require_text "${iam_resource_arn_verifier}" \
  'Object.hasOwn(value, "Fn::Sub")' \
  'isExactAwsPartitionReference' \
  'serviceSegment.includes("*")' \
  'serviceSegment.includes("?")' \
  'literalPartition' \
  'No IAM PolicyDocument Resource ARNs were available for validation'
require_text "${iam_resource_arn_verifier_test}" \
  'accepts exact AWS partitions, exact services, and resource-name wildcards' \
  'rejects wildcard and nonliteral service segments without substitution-map bypass' \
  'fails closed for malformed, incomplete, empty, and unresolved ARN shapes'

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
  'node "${workspace_root}/scripts/render-canonical-flow-yaml.mjs"' \
  'jq -cS' \
  'scripts/verify-iam-policy-resource-arns.mjs' \
  'cmp -s "${canonical_json}" "${round_trip}"' \
  '[[ "${output_path}" == "${runner_temp_root}/"* ]]'
require_text "${canonical_flow_renderer}" \
  'process.env.GITHUB_ACTIONS !== "true"' \
  'process.env.RUNNER_TEMP' \
  'requestedInputStat.isSymbolicLink()' \
  'safePlainScalar' \
  'implicitYamlScalar' \
  'JSON.stringify(value)' \
  'Object.entries(value)' \
  'process.stdout.write(`${emit(document)}\n`)'
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
  '.aws.inlineTemplateRendering.yamlParser.linuxAmd64Sha256' \
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
  'AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256="${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256:-}"' \
  'inspect_api_gateway_binding() {' \
  'assert_stack_absent() {' \
  '^arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$' \
  'AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256=${observed_sha}' \
  'clear the stale external API Gateway binding pin before managed reconciliation' \
  'test "${shared_api_gateway_mode}" = "${shared_api_gateway_preflight_mode}"' \
  'bindingState: "UNCHANGED"' \
  'managedStackAbsent: true' \
  'mutation: "none"' \
  'takeover: "forbidden"' \
  'validation: "pinned-and-unchanged"' \
  'validation: "managed-and-verified"' \
  'Require every managed foundation stack to be IN_SYNC' \
  'test "${drift_stack_count}" -eq 10' \
  'test "${drift_stack_count}" -eq 9' \
  'managedStackCount: $driftStackCount' \
  'externalBindingCount:' \
  'test "${compact_policy_size}" -le 6144' \
  'test "${boundary_compact_size}" -le 6144' \
  'sourceTemplateSha256: $sourceTemplateSha256' \
  'canary_role_binding_sha=${combined_canary_binding_sha}' \
  'operational_role_binding_sha=${combined_operational_binding_sha}' \
  '.Stacks[0].StackStatus == "UPDATE_ROLLBACK_COMPLETE"' \
  'foundation-complete-deploy-migration-required' \
  'requires-explicit-deploy-migration' \
  'deployRequirement: "explicit-role-migration"' \
  'applicationStackRoleTransition: $applicationStackRoleTransition' \
  'application_stack_role_transition=${application_stack_role_transition_state}' \
  'readonly FAILURE_EVIDENCE_DIR="${RUNNER_TEMP}/aws-foundation-failure"' \
  'assert_diagnostic_stack_allowlisted() {' \
  'capture_managed_stack_failure() {' \
  'cleanup_failure_evidence_staging() {' \
  'run_managed_stack_command() {' \
  'if "$@" >/dev/null 2>&1; then' \
  'aws cloudformation describe-stack-events' \
  '--max-items 100' \
  '--output json 2>/dev/null |' \
  'node scripts/sanitize-cloudformation-failure.mjs' \
  'find -P "${staging_dir}" -mindepth 1 -printf' \
  'LC_ALL=C sort -z' \
  'cmp -s "${diagnostic_tmp}" "${canonical_tmp}"' \
  '.diagnosticSha256 == $computedDigest' \
  'mv -T -- "${staging_dir}" "${FAILURE_EVIDENCE_DIR}"' \
  'stackLabel=%s; stackStatus=%s' \
  'ROLLBACK_COMPLETE | *_FAILED)' \
  'sha256sum cfn-failure.json >SHA256SUMS'
test "$(grep -Ec '^[[:space:]]*run_managed_stack_command \\$' "${reconciler}")" -eq 9 ||
  fail "all nine managed stack mutator sites must use the sanitized wrapper"
test "$(grep -Fc 'aws cloudformation update-termination-protection' "${reconciler}")" -eq 4 ||
  fail "expected exactly four managed termination-protection call sites"
while IFS=: read -r update_line _; do
  wrapper_line="$((update_line - 2))"
  sed -n "${wrapper_line},${update_line}p" "${reconciler}" |
    grep -Fq 'run_managed_stack_command \' ||
    fail "termination-protection call at line ${update_line} bypasses the wrapper"
done < <(grep -nF 'aws cloudformation update-termination-protection' "${reconciler}")
forbid_text "${reconciler}" \
  'Purpose=stage-iam-foundation >/dev/null' \
  'Purpose=shared-apigateway-logging >/dev/null' \
  'GitHubRepository=archon-datahub >/dev/null' \
  'Purpose=github-deployment-role >/dev/null'
shared_api_gateway_block="$(
  sed -n \
    "/foundation_phase='shared-api-gateway'/,/foundation_phase='governed-canary-roles'/p" \
    "${reconciler}"
)"
external_shared_branch="$(
  sed -n \
    '/if \[\[ "${shared_api_gateway_mode}" == "external-pinned" \]\]/,/^else$/p' \
    <<<"${shared_api_gateway_block}" |
    sed '$d'
)"
test -n "${external_shared_branch}" ||
  fail "missing external-pinned reconciliation branch"
for forbidden_external_action in \
  'aws cloudformation deploy' \
  'aws cloudformation update-termination-protection' \
  'aws iam ' \
  'aws apigateway update-account' \
  'aws apigateway patch'; do
  if grep -Fq "${forbidden_external_action}" <<<"${external_shared_branch}"; then
    fail "external API Gateway mode must remain mutation- and IAM-inspection-free"
  fi
done
for forbidden_recovery_action in \
  'aws cloudformation delete-stack' \
  'aws cloudformation continue-update-rollback'; do
  if grep -Fq "${forbidden_recovery_action}" "${reconciler}"; then
    fail "foundation diagnostics must never mutate or recover a failed stack"
  fi
done
forbid_text "${reconciler}" \
  'Require all ten foundation stacks to be IN_SYNC' \
  'stackCount: 10'
test "$(
  grep -Fc 'infra/aws/foundation/cdk-execution-policy.yml' "${reconciler}"
)" -eq 1 ||
  fail "reconciler may reference the oversized source template only as evidence"

require_text "${failure_sanitizer}" \
  'const MAX_INPUT_BYTES = 1_048_576;' \
  'const MAX_EVENTS = 100;' \
  'const MAX_OUTPUT_BYTES = 2_048;' \
  'ALLOWLISTED_STACK_LABELS' \
  'const failedEvents = document.StackEvents.filter(' \
  'classifyReason(reason) !== "dependency-failure"' \
  '?? failedEvents[0]' \
  'const canonicalSafeFields = Object.freeze({' \
  'diagnosticSha256: sha256(JSON.stringify(canonicalSafeFields))' \
  'schemaVersion: "archon.aws-foundation-cfn-failure/v1"' \
  'process.stderr.write("CloudFormation failure sanitization failed\n")'
forbid_text "${failure_sanitizer}" \
  'console.log' \
  'console.error' \
  'process.stderr.write(error' \
  'physicalResourceId' \
  'StackId'
require_text "${runtime_verifier}" \
  'function normalizeAction(action)' \
  'return action.toLowerCase();' \
  'allowedActions.map(normalizeAction)' \
  'case-insensitively unique' \
  'const uncovered' \
  'const unusedAllowed' \
  'const unseenApprovedPolicies' \
  'approved managed policies absent from synthesis'
require_text "${ci_workflow}" \
  'bash tests/pipeline/aws-foundation-contracts.test.sh' \
  'scripts/bootstrap-aws-foundation-role.sh' \
  'scripts/reconcile-aws-foundation.sh' \
  'scripts/patch-cdk-bootstrap-template.mjs' \
  'scripts/render-canonical-flow-yaml.mjs' \
  'scripts/render-inline-cloudformation-template.sh' \
  'scripts/seal-cdk-bootstrap-templates.sh' \
  'Seal the exact CDK bootstrap templates without AWS access' \
  'EXPECTED_BOOTSTRAP_VERSION: "32"' \
  'run: bash scripts/seal-cdk-bootstrap-templates.sh' \
  'Render the exact inline-safe IAM foundation template' \
  '"${RUNNER_TEMP}/archon-cdk-execution-policy.yaml"' \
  '"${RUNNER_TEMP}/archon-cdk-execution-policy.canonical.json"' \
  'scripts/render-aws-foundation-policy.mjs' \
  'AWS_ACCOUNT_ID: ${{ vars.AWS_ACCOUNT_ID }}' \
  'tests/pipeline/aws-foundation-core-ami-policy-migration-state.test.sh \' \
  'bash tests/pipeline/aws-foundation-core-ami-policy-migration-state.test.sh' \
  'node scripts/verify-aws-runtime-boundary.mjs'
test "$(
  grep -Fc 'AWS_ACCOUNT_ID: ${{ vars.AWS_ACCOUNT_ID }}' "${ci_workflow}"
)" -eq 1 || fail "CI must bind the account-aware policy digest test exactly once"
require_text "${deploy_workflow}" \
  'group: archon-aws-control-plane' \
  'cancel-in-progress: false' \
  'permissions: {}' \
  '    permissions:' \
  '      actions: read' \
  '      attestations: write' \
  '      contents: read' \
  '      id-token: write' \
  'Fail closed on exact stage deployment role before AWS trust' \
  'id: deploy_authority' \
  'AWS_DEPLOY_ROLE_ARN: ${{ vars.AWS_DEPLOY_ROLE_ARN }}' \
  'expected_deploy_role_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/archon-datahub-github-${STAGE}-deploy"' \
  'printf '\''role_arn=%s\n'\'' "${AWS_DEPLOY_ROLE_ARN}" >>"${GITHUB_OUTPUT}"' \
  'role-to-assume: ${{ steps.deploy_authority.outputs.role_arn }}' \
  'allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}' \
  'mask-aws-account-id: true' \
  'unset-current-credentials: true' \
  'Preflight exact lean stack execution-role bindings' \
  'ALLOW_ABSENT=true' \
  'Verify exact post-deploy CloudFormation role bindings' \
  'ALLOW_ABSENT=false' \
  'ALLOW_ROLE_MIGRATION=false' \
  'bash scripts/validate-cloudformation-role-bindings.sh'
forbid_text "${deploy_workflow}" \
  'role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}'
test "$(
  grep -Ec '^permissions: \{\}$' "${deploy_workflow}"
)" -eq 1 || fail 'deploy workflow must deny permissions by default at root'
test "$(
  grep -Fc 'bash scripts/validate-cloudformation-role-bindings.sh' \
    "${deploy_workflow}"
)" -eq 2 || fail 'deploy workflow must verify role bindings twice'
test "$(
  grep -Fc 'ALLOW_ABSENT=true' "${deploy_workflow}"
)" -eq 1 || fail 'deploy preflight must allow only first-deploy absence'
test "$(
  grep -Fc 'ALLOW_ABSENT=false' "${deploy_workflow}"
)" -eq 1 || fail 'post-deploy role verification must forbid absence'
test "$(
  grep -Fc 'ALLOW_ROLE_MIGRATION=false' "${deploy_workflow}"
)" -eq 2 || fail 'deploy role verification must always forbid migration'

require_text "${role_binding_validator}" \
  'bootstrap_qualifier="archonstg"' \
  'bootstrap_qualifier="archonprd"' \
  '"Archon-${EXPECTED_STAGE}-Edge|us-east-1|${bootstrap_qualifier}"' \
  '"Archon-${EXPECTED_STAGE}-Core|eu-west-1|${bootstrap_qualifier}"' \
  '"Archon-${EXPECTED_STAGE}-Judge|eu-west-1|${bootstrap_qualifier}"' \
  'state: "present-and-exact"'
forbid_text "${role_binding_validator}" \
  '"Archon-staging|eu-west-1|archonstg"' \
  '"Archon-production|eu-west-1|archonprd"'
require_text "${reconciler}" \
  'Archon-staging-Core "${staging_cfn_eu}"' \
  'Archon-staging-Judge "${staging_cfn_eu}"' \
  'Archon-production-Core "${production_cfn_eu}"' \
  'Archon-production-Judge "${production_cfn_eu}"' \
  'application stack role preflight inventory must contain six entries' \
  'stack_names='\''["Archon-staging-Core","Archon-staging-Judge"]'\''' \
  'stack_names='\''["Archon-production-Core","Archon-production-Judge"]'\'''
forbid_text "${reconciler}" \
  'stack_names='\''["Archon-staging","Archon-Registry"]'\''' \
  'stack_names='\''["Archon-production"]'\'''
require_text "${foundation_workflow}" \
  'Render the inline-safe IAM foundation template' \
  'scripts/render-canonical-flow-yaml.mjs' \
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
  'GitHubDataHubCloudTrialRoleArn:' \
  'AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN in the matching' \
  'Value: !GetAtt GitHubDataHubCloudTrialRole.Arn' \
  'RoleName: !Sub archon-datahub-github-${DeploymentEnvironment}-cloud-trial' \
  'StageAndPromoteExactCloudRuntimeSecrets' \
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
  'CloudRuntimeImagePublisherRoleArn:' \
  'CloudRuntimeImagePublisherRoleName:' \
  'token.actions.githubusercontent.com:workflow: DataHub Cloud runtime OCI v2' \
  'ProveRetiredStacksAbsent' \
  'ResolveExactDeploymentAndRuntimeInputs' \
  'ReadExactCloudRuntimeImage' \
  'ReadExactStageRuntimeTables' \
  'ReadExactStageBucketPosture' \
  'PublishExactStageSpaBucket' \
  'PublishExactStageSpaObjects' \
  'UseExactStageSpaKeyViaS3' \
  'ReadExactStageFunctionConfiguration' \
  'ReadExactStageImageFunctions' \
  'ReadAndInvalidateTaggedStageDistribution' \
  'ReadExactStageRegionalWebAcl' \
  'ReadTaggedStageCognitoWebAclAssociation' \
  'ReadExactStageRuntimeAlarms' \
  'autoscaling:DescribeAutoScalingGroups' \
  'ec2:DescribeImages' \
  'ec2:DescribeManagedPrefixLists' \
  'ecr:DescribeRepositories' \
  'repository/archon-datahub-cloud-runtime-v2' \
  'dynamodb:DescribeContinuousBackups' \
  's3:GetBucketPublicAccessBlock' \
  'lambda:GetFunctionConcurrency' \
  'cloudfront:GetDistribution' \
  'cognito-idp:GetWebACLForResource' \
  'cloudwatch:DescribeAlarms' \
  'alias/archon/${DeploymentEnvironment}/judge-spa' \
  'archon-${DeploymentEnvironment}-cloud-checkpoints-${AWS::AccountId}-eu-west-1' \
  'stack/Archon-${DeploymentEnvironment}-Core/*' \
  'stack/Archon-${DeploymentEnvironment}-Judge/*' \
  'stack/Archon-${DeploymentEnvironment}-Edge/*'

github_deploy_role_block="$(
  awk '
    /^  GitHubDeployRole:$/ { inside=1 }
    /^  CloudRuntimeImagePublisherRole:$/ { inside=0 }
    inside { print }
  ' "${deploy_role}"
)"
for stale in \
  'ecs:' \
  'elasticloadbalancing:' \
  'route53:' \
  'acm:' \
  'secretsmanager:' \
  'iam:SimulatePrincipalPolicy'; do
  if grep -Fq -- "${stale}" <<<"${github_deploy_role_block}"; then
    fail "GitHub deploy role retains unused permission: ${stale}"
  fi
done
if grep -Eq 'repository/archon-datahub[[:space:]]*$' \
  <<<"${github_deploy_role_block}"; then
  fail 'GitHub deploy role retains the retired ECR repository'
fi
if grep -Eq 'alias/archon/\${DeploymentEnvironment\}/(data|secrets|spa)[[:space:]]*$' \
  <<<"${github_deploy_role_block}"; then
  fail 'GitHub deploy role retains a legacy runtime KMS alias'
fi
test "$(
  grep -Fc 'stack/Archon-${DeploymentEnvironment}/*' \
    <<<"${github_deploy_role_block}"
)" -eq 1 || fail 'legacy monolith read must exist only for absence proof'
test "$(
  grep -Fc 'stack/Archon-Registry/*' <<<"${github_deploy_role_block}"
)" -eq 1 || fail 'retired Registry read must exist only for absence proof'
test "$(
  grep -Fc 'Action: sts:AssumeRoleWithWebIdentity' "${deploy_role}"
)" -eq 7
if grep -Eq \
  "^[[:space:]]*(Action:[[:space:]]*|-)[[:space:]]*['\"]?\\*['\"]?[[:space:]]*$" \
  "${deploy_role}"; then
  fail "deploy and operational roles contain a wildcard action"
fi
require_text "${foundation_policy}" \
  'cloudformation:DescribeStackEvents' \
  'cloudformation:DetectStackResourceDrift' \
  'cloudformation:BatchDescribeTypeConfigurations' \
  'role/archon-datahub-github-staging-cloud-trial' \
  'role/archon-datahub-github-production-cloud-trial' \
  'role/archon-staging-judge-user' \
  'role/archon-production-judge-user' \
  'role/archon-production-posture-observer' \
  'role/archon-production-runtime-read' \
  'role/archon-production-paging-test'

jq --exit-status \
  --slurpfile migration "${migration_contract}" '
    $migration[0] as $m |
    . as $policy |

    $m.policy.group == "assets" and
    $m.policy.name == "archon-aws-foundation-assets" and
    ($m.policy.exactDelta.statements | length) == 2 and
    all($m.policy.exactDelta.statements[];
      . as $spec |
      ([$policy.Statement[] | select(.Sid == $spec.sid)]) as $added |
      ([$policy.Statement[] |
        select(.Sid == $spec.resourcesMatchStatement)]) as $source |
      ($added | length) == 1 and
      ($source | length) == 1 and
      $added[0].Effect == "Allow" and
      (($added[0].Action |
        if type == "array" then sort else [.] end) ==
        ($spec.actions | sort)) and
      ($added[0].Resource | type) == "array" and
      (($added[0].Resource | sort) == ($source[0].Resource | sort)) and
      all($added[0].Resource[]; . != "*")) and
    all($m.policy.exactDelta.statements[].actions[];
      . as $action |
      (([$policy.Statement[].Action] | flatten |
        map(select(. == $action))) | length) == 1)
  ' "${foundation_policy}" >/dev/null

test "$(grep -Fc 'cloudformation:DetectStackResourceDrift' "${deploy_role}")" -eq 2
test "$(grep -Fc 'cloudformation:BatchDescribeTypeConfigurations' "${deploy_role}")" -eq 2
for sid in \
  DetectExactStageIamFoundationDrift \
  ReadStageIamDriftDetection \
  ReadAndDetectExactProductionStacks \
  ReadStackDriftDetectionStatus; do
  require_text "${deploy_role}" "- Sid: ${sid}"
done
require_text "${foundation_workflow}" \
  'contracts/aws-foundation-policy-migration-v1.json' \
  '--from-file scripts/validate-aws-foundation-policy.jq' \
  'cloudformation:DetectStackResourceDrift' \
  'cloudformation:BatchDescribeTypeConfigurations' \
  'queue: max'
forbid_text "${foundation_workflow}" \
  '.policy.exactDelta.stackScopedStatement' \
  '.policy.exactDelta.wildcardStatement'
require_text "${foundation_policy_validator}" \
  '($m.policy.exactDelta.statements) as $delta' \
  '$spec.resourcesMatchStatement' \
  'all($delta[];' \
  'all($delta[].actions[];'

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
  'The active application topology is Edge, zero-idle Core and Judge.' \
  'exact three-stack resources' \
  'Before any AWS trust is acquired' \
  '`AWS_DEPLOY_ROLE_ARN` equals the exact foundation-owned' \
  '`archon-datahub-github-<stage>-deploy`' \
  'exactly three bindings for the selected stage' \
  '`Archon-<stage>-Edge` in `us-east-1`' \
  '`Archon-<stage>-Core` in `eu-west-1`' \
  '`Archon-<stage>-Judge` in `eu-west-1`' \
  '`ALLOW_ABSENT=false`' \
  '`ALLOW_ROLE_MIGRATION=false`' \
  'machine-readable authority'
forbid_text "${runbook}" \
  'always-on container cluster is the active topology' \
  'implicit role migration'
require_text "${ci_workflow}" \
  'scripts/aws-cloudformation-drift.sh \' \
  'tests/pipeline/aws-cloudformation-drift-poll.test.sh \' \
  'bash tests/pipeline/aws-cloudformation-drift-poll.test.sh'
require_text "${foundation_workflow}" \
  'scripts/aws-cloudformation-drift.sh \' \
  'globalDeadline: "hard-wall-clock"' \
  'exactStackIncarnation: true'
require_text "${reconciler}" \
  "readonly CFN_DRIFT_HELPER='scripts/aws-cloudformation-drift.sh'" \
  'source "${CFN_DRIFT_HELPER}"' \
  'readonly CFN_DRIFT_MAX_ATTEMPTS=120' \
  'readonly CFN_DRIFT_DELAY_SECONDS=2' \
  'readonly CFN_DRIFT_MAX_API_FAILURES=3' \
  'readonly CFN_DRIFT_PHASE_TIMEOUT_SECONDS=900' \
  'check_drift() (' \
  'trap cleanup_drift_raw EXIT' \
  'detect_and_wait_for_cloudformation_stack_in_sync \' \
  'exact_stack_id="$(jq -er' \
  'detection_timestamp="$(jq -er' \
  'verify_cloudformation_stack_resource_drifts \' \
  'cloudformation_drift_remaining_seconds "${CFN_DRIFT_DEADLINE_EPOCH}"' \
  'stackIncarnationBinding: "exact-stack-id-and-monotonic-detection-lower-bound"' \
  'scripts/aws-cloudformation-drift.sh \'
test "$(grep -Fc 'stackIncarnationBinding: "exact-stack-id-and-monotonic-detection-lower-bound"' "${reconciler}")" -eq 2 ||
  fail 'drift receipt producers must have two exact monotonic bindings'
test "$(grep -Fc '.stackIncarnationBinding == "exact-stack-id-and-monotonic-detection-lower-bound"' "${reconciler}")" -eq 2 ||
  fail 'drift receipt validators must have two exact monotonic bindings'

require_text "${drift_poller}" \
  'cloudformation_drift_remaining_seconds() {' \
  'run_bounded_cloudformation_drift_aws() {' \
  'cloudformation_drift_utc_key() {' \
  'verify_cloudformation_stack_resource_drifts() (' \
  'timeout --foreground --signal=TERM --kill-after=2s' \
  'AWS_MAX_ATTEMPTS=1' \
  '--cli-connect-timeout 5' \
  '--cli-read-timeout 15' \
  'cloudformation detect-stack-drift' \
  'cloudformation describe-stack-drift-detection-status' \
  'cloudformation describe-stack-resource-drifts' \
  'cloudformation describe-stacks' \
  '.StackDriftDetectionId == $detectionId' \
  'ltrimstr($stackPrefix)' \
  '.StackId == $exactStackId' \
  'CFN_DRIFT_FINAL_BINDING_MAX_ATTEMPTS:-5' \
  'CFN_DRIFT_FINAL_BINDING_DELAY_SECONDS:-2' \
  'def leap_year($year):' \
  'month_days($year; $month)' \
  'final_max_attempts > 5' \
  'final_delay_seconds > 2' \
  'if $drift == null then "stale"' \
  'if $actualKey < $detectionKey then "stale"' \
  'elif $drift.StackDriftStatus == "IN_SYNC" then "match"' \
  'elif $drift.StackDriftStatus == "DRIFTED" then "current-drifted"' \
  'else "current-indeterminate" end' \
  'final-stack-binding-stale' \
  'final-stack-current-drifted' \
  'final-stack-current-indeterminate' \
  'final-stack-selection-mismatch' \
  '.StackResourceDriftStatus == "IN_SYNC"' \
  'trap cleanup EXIT' \
  'max_api_failures > 3' \
  'response_bytes > 65536'
require_text "${drift_poller_test}" \
  'progress-success' 'transient-success' 'persistent-error' \
  'perpetual-progress' 'detection-failed' 'drifted' 'missing-count' \
  'missing-timestamp' 'wrong-detection-id' 'wrong-stack-id' \
  'deadline-during-status' 'different-incarnation' 'stale-resource' \
  'subsecond-stale-resource' 'not-checked-resource' \
  'leap-day-success' 'invalid-detection-calendar' 'invalid-resource-calendar' \
  'final-equivalent-utc' 'final-nonzero-equivalent' 'final-stale-then-current' \
  'final-absent-drift-info-then-current' 'final-not-checked-missing-then-current' \
  'final-drifted-stale-then-current' 'final-stale-default' 'final-stale-persistent' \
  'invalid-final-max' 'invalid-final-delay' 'final-api-transient' 'final-api-persistent' \
  'final-newer-in-sync' 'final-newer-subsecond-in-sync' \
  'final-newer-drifted' 'final-newer-unknown' 'final-newer-not-checked' \
  'final-indeterminate-default' \
  'final-unknown-current-then-current' 'final-not-checked-current-then-current' \
  'final-different-incarnation' \
  'final-invalid-calendar' 'final-invalid-second' 'final-invalid-fraction' \
  'final-invalid-drift-status' \
  'final-malformed' 'final-oversize' 'deadline-resource' 'deadline-final' \
  'assert_category' 'assert_sleep_arguments' 'PRIVATE_AWS_MARKER' 'left raw files' \
  'leaked exact stack id' 'leaked detection timestamp'
forbid_text "${reconciler}" \
  'stack-drift-detection-complete' \
  '(.DriftedStackResourceCount // 0) == 0' \
  '.StackResourceDrifts[]?' \
  'exact-stack-id-and-detection-timestamp'
forbid_text "${drift_poller}" 'stack-drift-detection-complete' 'DetectionStatusReason' \
  'final_max_attempts > 10' 'final_delay_seconds > 30' \
  'fromdateiso8601' 'strptime(' 'mktime' \
  'elif $actualKey > $detectionKey then "mismatch"' \
  'final-stack-binding-mismatch'
helper_detect_line="$(grep -nF 'cloudformation detect-stack-drift' "${drift_poller}" | cut -d: -f1)"
helper_status_line="$(grep -nF 'cloudformation describe-stack-drift-detection-status' "${drift_poller}" | cut -d: -f1)"
helper_terminal_line="$(grep -nF '.DetectionStatus == "DETECTION_COMPLETE"' "${drift_poller}" | tail -n 1 | cut -d: -f1)"
helper_publish_line="$(grep -nF 'mv -T -- "${candidate}" "${status_json}"' "${drift_poller}" | cut -d: -f1)"
helper_resource_line="$(grep -nF 'cloudformation describe-stack-resource-drifts' "${drift_poller}" | cut -d: -f1)"
helper_final_line="$(grep -nF 'cloudformation describe-stacks' "${drift_poller}" | cut -d: -f1)"
helper_binding_line="$(grep -nF 'if $actualKey < $detectionKey then "stale"' "${drift_poller}" | cut -d: -f1)"
test "${helper_detect_line}" -lt "${helper_status_line}" || fail 'drift helper must detect before polling'
test "${helper_status_line}" -lt "${helper_terminal_line}" || fail 'drift helper must poll before terminal validation'
test "${helper_terminal_line}" -lt "${helper_publish_line}" || fail 'drift helper must validate before publishing'
test "${helper_publish_line}" -lt "${helper_resource_line}" || fail 'terminal binding must precede resource proof'
test "${helper_resource_line}" -lt "${helper_final_line}" || fail 'resource proof must precede final stack read'
test "${helper_final_line}" -lt "${helper_binding_line}" || fail 'final read must precede timestamp binding'
reconciler_poll_line="$(grep -nF 'detect_and_wait_for_cloudformation_stack_in_sync \' "${reconciler}" | cut -d: -f1)"
reconciler_exact_line="$(grep -nF 'exact_stack_id="$(jq -er' "${reconciler}" | cut -d: -f1)"
reconciler_verify_line="$(grep -nF 'verify_cloudformation_stack_resource_drifts \' "${reconciler}" | cut -d: -f1)"
reconciler_evidence_line="$(grep -nF 'checkedResourceCount: $checkedResourceCount' "${reconciler}" | cut -d: -f1)"
test "${reconciler_poll_line}" -lt "${reconciler_exact_line}" || fail 'poll result must precede exact binding extraction'
test "${reconciler_exact_line}" -lt "${reconciler_verify_line}" || fail 'exact binding must precede resource proof'
test "${reconciler_verify_line}" -lt "${reconciler_evidence_line}" || fail 'resource proof must precede evidence'
require_text "${runbook}" \
  'Bounded CloudFormation drift evidence' \
  'bounded CloudFormation drift polling' \
  'hard 900-second wall-clock deadline' \
  'SDK retries are fixed' \
  'LastCheckTimestamp' \
  'deleted on every' \
  'cloudformation-supported-resources' \
  'all fail closed'
require_text "${reconciler}" \
  'set -Eeuo pipefail' \
  "readonly FOUNDATION_DIAGNOSTIC_SOURCE='scripts/reconcile-aws-foundation.sh'" \
  "foundation_phase='startup'" \
  'report_foundation_error() {' \
  "trap 'report_foundation_error \"\$?\" \"\$LINENO\"' ERR" \
  'shopt -s inherit_errexit' \
  "printf '::error file=%s,line=%s,title=AWS foundation reconciliation failed::phase=%s; exit=%s\\n'" \
  "foundation_phase='preflight:revalidate-master'" \
  "foundation_phase='preflight:validate-template:api-gateway-account'" \
  "foundation_phase='preflight:validate-template:iam-foundation'" \
  "foundation_phase='preflight:validate-template:github-actions-deploy-role'" \
  "foundation_phase='preflight:validate-template:github-actions-foundation-role'" \
  "foundation_phase='preflight:validate-template:governed-canary-roles'" \
  "foundation_phase='preflight:validate-template:bootstrap:staging:eu-west-1'" \
  "foundation_phase='preflight:validate-template:bootstrap:staging:us-east-1'" \
  "foundation_phase='preflight:validate-template:bootstrap:production:eu-west-1'" \
  "foundation_phase='preflight:validate-template:bootstrap:production:us-east-1'" \
  "foundation_phase='preflight:legacy-role'" \
  "foundation_phase='preflight:legacy-stacks'" \
  "foundation_phase='preflight:foundation-stack-role-binding:staging:iam'" \
  "foundation_phase='preflight:foundation-stack-role-binding:staging:deploy'" \
  "foundation_phase='preflight:foundation-stack-role-binding:staging:bootstrap:eu-west-1'" \
  "foundation_phase='preflight:foundation-stack-role-binding:staging:bootstrap:us-east-1'" \
  "foundation_phase='preflight:foundation-stack-role-binding:production:iam'" \
  "foundation_phase='preflight:foundation-stack-role-binding:production:deploy'" \
  "foundation_phase='preflight:foundation-stack-role-binding:production:bootstrap:eu-west-1'" \
  "foundation_phase='preflight:foundation-stack-role-binding:production:bootstrap:us-east-1'" \
  "foundation_phase='preflight:foundation-stack-role-binding:shared-api'" \
  "foundation_phase='preflight:foundation-stack-role-binding:governed-canary'" \
  "foundation_phase='preflight:shared-api-gateway'" \
  "foundation_phase='preflight:application-stack-role-binding:staging:edge'" \
  "foundation_phase='preflight:application-stack-role-binding:staging:core'" \
  "foundation_phase='preflight:application-stack-role-binding:staging:judge'" \
  "foundation_phase='preflight:application-stack-role-binding:production:edge'" \
  "foundation_phase='preflight:application-stack-role-binding:production:core'" \
  "foundation_phase='preflight:application-stack-role-binding:production:judge'" \
  "foundation_phase='preflight:application-stack-role-transition'" \
  "foundation_phase='stage-iam'" \
  "foundation_phase='shared-api-gateway'" \
  "foundation_phase='governed-canary-roles'" \
  "foundation_phase='bootstrap'" \
  "foundation_phase='deploy-roles'" \
  "foundation_phase='drift-verification'" \
  "foundation_phase='evidence'"
forbid_text "${reconciler}" \
  'BASH_COMMAND' \
  'set -x' \
  'printenv' \
  'declare -p'
test "$(grep -Ec "^foundation_phase='[^']+'$" "${reconciler}")" -eq 38 ||
  fail 'reconciler diagnostic phases must be the 38 reviewed public labels'
for migration_runner in \
  "${repository_root}/scripts/run-aws-foundation-policy-migration.sh" \
  "${repository_root}/scripts/run-aws-foundation-cloud-runtime-publisher-policy-migration.sh" \
  "${repository_root}/scripts/run-aws-foundation-core-ami-policy-migration.sh"; do
  revoke_block="$(
    sed -n '/^revoke() {/,/^}/p' "${migration_runner}"
  )"
  test "$(grep -Fc '  revoke_temp_policy' <<<"${revoke_block}")" -eq 1 ||
    fail "${migration_runner} must revoke temporary authority exactly once"
  test "$(grep -Fc '  render_policy_documents' <<<"${revoke_block}")" -eq 1 ||
    fail "${migration_runner} must render receipt policy state exactly once"
  revoke_line="$(
    grep -nF '  revoke_temp_policy' <<<"${revoke_block}" | cut -d: -f1
  )"
  render_line="$(
    grep -nF '  render_policy_documents' <<<"${revoke_block}" | cut -d: -f1
  )"
  [[ "${revoke_line}" =~ ^[1-9][0-9]*$ && "${render_line}" =~ ^[1-9][0-9]*$ ]] ||
    fail "${migration_runner} revoke/render ordering is ambiguous"
  ((revoke_line < render_line)) ||
    fail "${migration_runner} must revoke temporary authority before fallible rendering"
done

for migration_common in \
  "${repository_root}/scripts/aws-foundation-policy-migration-common.sh" \
  "${publisher_migration_common}" \
  "${core_migration_common}"; do
  common_validate_block="$(sed -n '/^validate_common() {/,/^}/p' "${migration_common}")"
  render_block="$(sed -n '/^render_policy_documents() {/,/^}/p' "${migration_common}")"
  recovery_baseline_block="$(
    sed -n '/^verify_recovery_role_baseline() {/,/^}/p' "${migration_common}"
  )"
  test "$(
    grep -Fc \
      '  TARGET_POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${TARGET_POLICY_NAME}"' \
      <<<"${common_validate_block}"
  )" -eq 1 ||
    fail "${migration_common} must derive the target policy ARN during validation"
  test "$(
    grep -Fc \
      '  RECOVERY_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${RECOVERY_ROLE_NAME}"' \
      <<<"${common_validate_block}"
  )" -eq 1 ||
    fail "${migration_common} must derive the recovery role ARN during validation"
  if grep -Eq 'TARGET_POLICY_ARN=|RECOVERY_ROLE_ARN=' <<<"${render_block}"; then
    fail "${migration_common} rendering must not initialize AWS identity bindings"
  fi
  test "$(
    grep -Fc '    --arg roleArn "${RECOVERY_ROLE_ARN}"' \
      <<<"${recovery_baseline_block}"
  )" -eq 1 ||
    fail "${migration_common} must verify the validated recovery role ARN"
done

run_isolated_revoke_path() (
  local label="$1"
  local migration_common="$2"
  local migration_authorization="$3"
  local migration_runner="$4"
  local case_runtime="${renderer_runtime_dir}/revoke-${label}"
  mkdir -p "${case_runtime}"
  chmod 0700 "${case_runtime}"
  export GITHUB_ACTIONS=true
  export RUNNER_TEMP="${case_runtime}"
  export GITHUB_OUTPUT="${case_runtime}/github-output"
  export AWS_ACCOUNT_ID=123456789012
  export CONTROL_PLANE_SHA=0123456789abcdef0123456789abcdef01234567
  export GITHUB_RUN_ATTEMPT=1
  export GITHUB_RUN_ID=1
  : >"${GITHUB_OUTPUT}"
  cd "${repository_root}"

  # Exercise the real common/authorization functions and the exact runner
  # revoke() orchestration. Only AWS, rendering, receipt output, and sleeps are
  # replaced, so the test cannot reach a network or mutate AWS.
  # shellcheck source=/dev/null
  source "${migration_common}"
  # shellcheck source=/dev/null
  source "${migration_authorization}"
  # shellcheck source=/dev/null
  source <(sed -n '/^revoke() {/,/^}/p' "${migration_runner}")

  local -a trace=()
  local temp_present=true
  local delete_calls=0
  local base_only_reads=0
  eval "$(
    declare -f validate_common |
      sed '1s/^validate_common /validate_common_real /'
  )"
  validate_common() {
    validate_common_real
    test "${TARGET_POLICY_ARN}" = \
      "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${TARGET_POLICY_NAME}"
    test "${RECOVERY_ROLE_ARN}" = \
      "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${RECOVERY_ROLE_NAME}"
    trace+=(validate)
  }

  sleep() { :; }
  aws() {
    local service="${1:-}"
    local operation="${2:-}"
    shift 2 || return 97
    case "${service}:${operation}" in
      sts:get-caller-identity)
        trace+=(caller)
        jq -cn \
          --arg account "${AWS_ACCOUNT_ID}" \
          --arg role "${FOUNDATION_ROLE_NAME}" '
            {
              Account: $account,
              Arn: ("arn:aws:sts::" + $account + ":assumed-role/" +
                $role + "/ci-revoke-test"),
              UserId: "synthetic"
            }
          '
        ;;
      iam:list-role-policies)
        [[ " $* " == *" --role-name ${RECOVERY_ROLE_NAME} "* ]]
        if [[ "${temp_present}" == true ]]; then
          trace+=(list-with-temp)
          jq -cn \
            --arg base "${BASE_POLICY_NAME}" \
            --arg temp "${TEMP_POLICY_NAME}" \
            '{PolicyNames: [$base, $temp]}'
        else
          base_only_reads=$((base_only_reads + 1))
          trace+=("list-base-${base_only_reads}")
          jq -cn --arg base "${BASE_POLICY_NAME}" \
            '{PolicyNames: [$base]}'
        fi
        ;;
      iam:delete-role-policy)
        [[ " $* " == *" --role-name ${RECOVERY_ROLE_NAME} "* ]]
        [[ " $* " == *" --policy-name ${TEMP_POLICY_NAME} "* ]]
        test "${temp_present}" == true
        temp_present=false
        delete_calls=$((delete_calls + 1))
        trace+=(delete-temp)
        ;;
      iam:get-role)
        [[ " $* " == *" --role-name ${RECOVERY_ROLE_NAME} "* ]]
        trace+=(get-role)
        jq -cn \
          --arg account "${AWS_ACCOUNT_ID}" \
          --arg roleArn "${RECOVERY_ROLE_ARN}" '
            {
              Role: {
                Arn: $roleArn,
                RoleName:
                  "archon-datahub-github-governed-canary-recovery",
                MaxSessionDuration: 3600,
                Tags: [
                  {Key: "Application", Value: "archon-datahub"},
                  {Key: "Environment", Value: "governed-canary-recovery"},
                  {Key: "ManagedBy", Value: "github-actions"}
                ],
                AssumeRolePolicyDocument: {
                  Version: "2012-10-17",
                  Statement: [{
                    Sid: "GitHubEnvironmentOidcOnly",
                    Effect: "Allow",
                    Action: "sts:AssumeRoleWithWebIdentity",
                    Principal: {
                      Federated: ("arn:aws:iam::" + $account +
                        ":oidc-provider/token.actions.githubusercontent.com")
                    },
                    Condition: {
                      StringEquals: {
                        "token.actions.githubusercontent.com:aud":
                          "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub":
                          "repo:upgradedev/archon-datahub:environment:governed-canary-recovery"
                      }
                    }
                  }]
                }
              }
            }
          '
        ;;
      iam:list-attached-role-policies)
        [[ " $* " == *" --role-name ${RECOVERY_ROLE_NAME} "* ]]
        trace+=(list-attached)
        jq -cn '{AttachedPolicies: []}'
        ;;
      iam:get-role-policy)
        [[ " $* " == *" --role-name ${RECOVERY_ROLE_NAME} "* ]]
        [[ " $* " == *" --policy-name ${BASE_POLICY_NAME} "* ]]
        trace+=(get-base-policy)
        jq -cn \
          --arg account "${AWS_ACCOUNT_ID}" \
          --arg base "${BASE_POLICY_NAME}" '
            {
              RoleName:
                "archon-datahub-github-governed-canary-recovery",
              PolicyName: $base,
              PolicyDocument: {
                Version: "2012-10-17",
                Statement: [{
                  Sid: "ReadExactStagingStack",
                  Effect: "Allow",
                  Action: "cloudformation:DescribeStacks",
                  Resource: ("arn:aws:cloudformation:eu-west-1:" +
                    $account + ":stack/Archon-staging/*")
                }]
              }
            }
          '
        ;;
      *)
        printf '::error::Unexpected fake AWS call in %s: %s:%s\n' \
          "${label}" "${service}" "${operation}" >&2
        return 97
        ;;
    esac
  }

  render_policy_documents() {
    test "${TARGET_POLICY_ARN}" = \
      "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${TARGET_POLICY_NAME}"
    test "${RECOVERY_ROLE_ARN}" = \
      "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${RECOVERY_ROLE_NAME}"
    NEW_POLICY="${WORK_ROOT}/synthetic-new.json"
    OLD_POLICY="${WORK_ROOT}/synthetic-old.json"
    NEW_POLICY_SHA="$(printf 'a%.0s' {1..64})"
    OLD_POLICY_SHA="$(printf 'b%.0s' {1..64})"
    HISTORICAL_POLICY_SHA="$(printf 'c%.0s' {1..64})"
    trace+=(render)
  }
  write_receipt() {
    test "$1" = terminal
    [[ "${NEW_POLICY_SHA}" =~ ^[a-f0-9]{64}$ ]]
    [[ "${OLD_POLICY_SHA}" =~ ^[a-f0-9]{64}$ ]]
    if [[ "${label}" == core ]]; then
      [[ "${HISTORICAL_POLICY_SHA}" =~ ^[a-f0-9]{64}$ ]]
    fi
    trace+=(receipt)
  }

  EXPECTED_STATE=terminal
  export EXPECTED_STATE
  revoke

  test "${temp_present}" == false
  test "${delete_calls}" -eq 1
  test "${base_only_reads}" -eq 4
  local expected_trace="validate caller list-with-temp delete-temp"
  expected_trace+=" list-base-1 list-base-2 list-base-3"
  expected_trace+=" get-role list-base-4 list-attached get-base-policy"
  expected_trace+=" render receipt"
  test "${trace[*]}" = "${expected_trace}" ||
    fail "${label} revoke preamble trace differs: ${trace[*]}"
)

run_isolated_revoke_path assets \
  "${repository_root}/scripts/aws-foundation-policy-migration-common.sh" \
  "${repository_root}/scripts/aws-foundation-policy-migration-authorization.sh" \
  "${repository_root}/scripts/run-aws-foundation-policy-migration.sh"
run_isolated_revoke_path publisher \
  "${publisher_migration_common}" \
  "${publisher_migration_authorization}" \
  "${publisher_migration_runner}"
run_isolated_revoke_path core \
  "${core_migration_common}" \
  "${repository_root}/scripts/aws-foundation-core-ami-policy-migration-authorization.sh" \
  "${repository_root}/scripts/run-aws-foundation-core-ami-policy-migration.sh"

forbid_text "${publisher_migration_common}" \
  'all($addedResources[] as $resource;'
forbid_text "${core_migration_common}" \
  'all(.;'

jq -e '
  .aws.foundationPolicies.identityRoleMigration == {
    baselineCanonicalSha256:
      "afda76cf8cfddd34c876147a4b228dd51b63edc4fd810f6793eb22d462beb553",
    baselineDefaultVersion: "v1",
    contract:
      "contracts/aws-foundation-cloud-runtime-publisher-policy-migration-v1.json",
    exactRoleDelta: [
      "archon-datahub-github-staging-cloud-trial",
      "archon-datahub-github-production-cloud-trial",
      "archon-datahub-cloud-runtime-publish-production"
    ],
    policyName: "archon-aws-foundation-identity",
    targetCanonicalSha256:
      "f8aab593f428ac9d990cefb525d0919241e81c42b09f22d737a97d1fd3dc18a3",
    targetVersion: "v2",
    workflow:
      ".github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration.yml"
  } and
  .aws.cloudRuntimePublisher.roleName ==
    "archon-datahub-cloud-runtime-publish-production" and
  .aws.cloudRuntimePublisher.roleVariable ==
    "AWS_CLOUD_RUNTIME_IMAGE_ROLE_ARN" and
  .aws.cloudRuntimePublisher.condition == "IsProduction" and
  .aws.cloudRuntimePublisher.stackName ==
    "Archon-GitHub-Production-Deploy-Role" and
  .aws.cloudRuntimePublisher.stackOutputs == [
    "CloudRuntimeImagePublisherRoleArn",
    "CloudRuntimeImagePublisherRoleName"
  ] and
  .aws.cloudRuntimePublisher.oidcClaims.workflow ==
    "DataHub Cloud runtime OCI v2" and
  .aws.cloudRuntimePublisher.oidcClaims.workflowRefInIam == false and
  .aws.cloudRuntimePublisher.workflowRequestedSessionSeconds == 1800 and
  .aws.cloudRuntimePublisher.repository ==
    "archon-datahub-cloud-runtime-v2"
' "${contract}" >/dev/null || fail 'Cloud runtime publisher contract differs'

jq -e '
  .schemaVersion ==
    "archon.aws-foundation-cloud-runtime-publisher-policy-migration/v1" and
  .status == "ready-for-migration" and
  .policy.group == "identity" and
  .policy.name == "archon-aws-foundation-identity" and
  .policy.liveBaseline == {
    canonicalSha256:
      "afda76cf8cfddd34c876147a4b228dd51b63edc4fd810f6793eb22d462beb553",
    isDefault: true,
    versionId: "v1"
  } and
  .policy.target == {
    canonicalSha256:
      "f8aab593f428ac9d990cefb525d0919241e81c42b09f22d737a97d1fd3dc18a3",
    expectedVersionId: "v2"
  } and
  (.policy.exactDelta.resourceAdditions[0].resources |
    map(split("/")[-1]) | sort) ==
      (["archon-datahub-github-production-cloud-trial",
        "archon-datahub-github-staging-cloud-trial"] | sort) and
  .policy.exactDelta.newStatements[0].sid ==
    "ReconcileExactCloudRuntimePublisherRole" and
  .policy.exactDelta.newStatements[0].resource ==
    "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-cloud-runtime-publish-production" and
  .authorization.temporaryPolicyName ==
    "archon-foundation-cloud-runtime-publisher-identity-policy-migration" and
  .authorization.ttlSeconds == 1200 and
  .evidence.schemaVersion ==
    "archon.aws-foundation-cloud-runtime-publisher-policy-migration-receipt/v1"
' "${publisher_migration_contract}" >/dev/null ||
  fail 'Publisher identity-policy migration contract differs'

require_text "${deploy_role}" \
  'CloudRuntimeImagePublisherRole:' \
  'Condition: IsProduction' \
  'RoleName: archon-datahub-cloud-runtime-publish-production' \
  'token.actions.githubusercontent.com:workflow: DataHub Cloud runtime OCI v2' \
  'PolicyName: archon-datahub-cloud-runtime-ecr-publish' \
  'CreateOnlyExactTaggedRepository' \
  'aws:RequestTag/archon:component: datahub-cloud-runtime-v2' \
  'aws:RequestTag/archon:owner: github-actions' \
  'PublishInspectAndBoundedCleanupExactRepository' \
  'CloudRuntimeImagePublisherRoleArn:' \
  'CloudRuntimeImagePublisherRoleName:'
forbid_text "${deploy_role}" 'token.actions.githubusercontent.com:workflow_ref'

require_text "${foundation_policy}" \
  '"Sid": "ReconcileExactCloudRuntimePublisherRole"' \
  'role/archon-datahub-cloud-runtime-publish-production' \
  'role/archon-datahub-github-staging-cloud-trial' \
  'role/archon-datahub-github-production-cloud-trial'

require_text "${cloud_runtime_workflow}" \
  'name: DataHub Cloud runtime OCI v2' \
  'WORKFLOW_REF: ${{ github.workflow_ref }}' \
  'upgradedev/archon-datahub/.github/workflows/datahub-cloud-runtime-image.yml@refs/heads/master' \
  'role-to-assume: ${{ vars.AWS_CLOUD_RUNTIME_IMAGE_ROLE_ARN }}' \
  'allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}' \
  'role-duration-seconds: 1800' \
  'mask-aws-account-id: true' \
  'unset-current-credentials: true'

require_text "${publisher_migration_entry}" \
  'MIGRATE EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY' \
  'aws-foundation-cloud-runtime-publisher-policy-migration-driver.yml'
require_text "${publisher_migration_driver}" \
  'RECOVER EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY MIGRATION' \
  'run-aws-foundation-cloud-runtime-publisher-policy-migration.sh' \
  'archon.aws-foundation-cloud-runtime-publisher-policy-migration-receipt/v1'
require_text "${publisher_migration_cleanup}" \
  'Migrate AWS foundation cloud runtime publisher identity policy' \
  'RECOVER EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY MIGRATION' \
  'SEAL EXACT MIGRATED CLOUD RUNTIME PUBLISHER IDENTITY POLICY' \
  'cleanup-rollback' \
  'cleanup-revoke' \
  'cleanup-migrated'
require_text "${publisher_migration_common}" \
  '--stdout-group identity' \
  'afda76cf8cfddd34c876147a4b228dd51b63edc4fd810f6793eb22d462beb553' \
  'f8aab593f428ac9d990cefb525d0919241e81c42b09f22d737a97d1fd3dc18a3' \
  'ReconcileExactCloudRuntimePublisherRole'
require_text "${publisher_migration_runner}" \
  'archon.aws-foundation-cloud-runtime-publisher-policy-migration-receipt/v1' \
  'archon-aws-foundation-identity'

require_text "${reconciler}" \
  'verify_cloud_runtime_publisher() {' \
  'token.actions.githubusercontent.com:workflow' \
  'CloudRuntimeImagePublisherRoleArn' \
  'cloud_runtime_publisher_role_arn=' \
  'cloud_runtime_publisher_binding_sha=' \
  'OPERATIONAL_ROLE_BINDING_SHA["cloud-runtime-publisher"]'
require_text "${foundation_workflow}" \
  'contracts/aws-foundation-cloud-runtime-publisher-policy-migration-v1.json' \
  'scripts/run-aws-foundation-cloud-runtime-publisher-policy-migration.sh' \
  'CLOUD_RUNTIME_PUBLISHER_ROLE_ARN: ${{ steps.reconcile.outputs.cloud_runtime_publisher_role_arn }}' \
  'Set production AWS_CLOUD_RUNTIME_IMAGE_ROLE_ARN'
require_text "${runbook}" \
  'Identity-policy migration and Cloud runtime publisher handoff' \
  'MIGRATE EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY' \
  'token.actions.githubusercontent.com:workflow' \
  'Safe dispatch order for one exact signed master SHA'

require_text "${deploy_role}" \
  'GitHubDataHubCloudTrialRoleName:' \
  'Value: !Ref GitHubDataHubCloudTrialRole'
require_text "${reconciler}" \
  '(.aws.applicationStackRolePreflight | length) == 6' \
  '"datahub-cloud-trial-${stage}"' \
  'datahub_cloud_trial_staging_role_arn=' \
  'datahub_cloud_trial_production_role_arn=' \
  'OPERATIONAL_ROLE_ARN["${kind}"]="${role_arn}"'
test "$(grep -Fc '"GitHubDataHubCloudTrialRoleArn",' "${reconciler}")" -eq 2 ||
  fail "trial role ARN output must be allowlisted for both stage stacks"
test "$(grep -Fc '"GitHubDataHubCloudTrialRoleName",' "${reconciler}")" -eq 2 ||
  fail "trial role name output must be allowlisted for both stage stacks"
for role_kind in \
  judge-staging datahub-cloud-trial-staging \
  judge-production datahub-cloud-trial-production \
  cloud-runtime-publisher posture-observer runtime-read paging-test; do
  grep -Fq "\"${role_kind}\"" "${reconciler}" ||
    fail "operational role receipt is missing ${role_kind}"
done
require_text "${foundation_workflow}" \
  'DATAHUB_CLOUD_TRIAL_STAGING_ROLE_ARN: ${{ steps.reconcile.outputs.datahub_cloud_trial_staging_role_arn }}' \
  'DATAHUB_CLOUD_TRIAL_PRODUCTION_ROLE_ARN: ${{ steps.reconcile.outputs.datahub_cloud_trial_production_role_arn }}' \
  'Set staging AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN' \
  'Set production AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN'
