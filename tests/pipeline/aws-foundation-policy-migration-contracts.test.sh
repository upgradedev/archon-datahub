#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
entry="${repository_root}/.github/workflows/aws-foundation-policy-migration.yml"
driver_workflow="${repository_root}/.github/workflows/aws-foundation-policy-migration-driver.yml"
cleanup="${repository_root}/.github/workflows/aws-foundation-policy-migration-cleanup.yml"
contract="${repository_root}/contracts/aws-foundation-policy-migration-v1.json"
foundation_contract="${repository_root}/contracts/aws-foundation-v1.json"
foundation_workflow="${repository_root}/.github/workflows/aws-foundation.yml"
foundation_policy="${repository_root}/infra/aws/foundation/github-actions-foundation-policy.json"
deploy_role="${repository_root}/infra/aws/foundation/github-actions-deploy-role.yml"
canary_roles="${repository_root}/infra/aws/foundation/governed-canary-roles.yml"
renderer="${repository_root}/scripts/render-aws-foundation-policy.mjs"
main_driver="${repository_root}/scripts/run-aws-foundation-policy-migration.sh"
common="${repository_root}/scripts/aws-foundation-policy-migration-common.sh"
authorization="${repository_root}/scripts/aws-foundation-policy-migration-authorization.sh"
state="${repository_root}/scripts/aws-foundation-policy-migration-state.sh"
environment_verifier="${repository_root}/scripts/verify-github-environment-protection.sh"
behavior="${repository_root}/tests/pipeline/aws-foundation-policy-migration-driver.test.sh"
ci_workflow="${repository_root}/.github/workflows/ci.yml"

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
  "${entry}" \
  "${driver_workflow}" \
  "${cleanup}" \
  "${contract}" \
  "${foundation_contract}" \
  "${foundation_workflow}" \
  "${foundation_policy}" \
  "${deploy_role}" \
  "${canary_roles}" \
  "${renderer}" \
  "${main_driver}" \
  "${common}" \
  "${authorization}" \
  "${state}" \
  "${environment_verifier}" \
  "${behavior}" \
  "${ci_workflow}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must not be a symlink"
done

for script in \
  "${main_driver}" \
  "${common}" \
  "${authorization}" \
  "${state}" \
  "${environment_verifier}"; do
  bash -n "${script}"
done

jq --exit-status '
  (keys | sort) == [
    "authorization",
    "evidence",
    "implementation",
    "phases",
    "policy",
    "recovery",
    "schemaVersion",
    "sourceFailure",
    "status",
    "workflow"
  ] and
  .schemaVersion == "archon.aws-foundation-policy-migration/v1" and
  .status == "ready-for-migration" and
  .sourceFailure == {
    awsMutationsBeforeFailure: "reconciliation-completed-postchecks-passed",
    diagnostic: "missing-drift-dependency-permissions",
    failureArtifact: "not-authored-command-outside-sanitized-wrapper",
    headSha: "06680d074c4d2a4bc18a64b9c217c137c3bdcf5a",
    phase: "drift-verification",
    runAttempt: 1,
    runId: 30586169834
  } and
  .workflow == {
    branch: "master",
    cleanup: ".github/workflows/aws-foundation-policy-migration-cleanup.yml",
    cleanupConfirmation: "RECOVER EXACT FOUNDATION CONTROL POLICY MIGRATION",
    confirmation: "MIGRATE EXACT FOUNDATION CONTROL POLICY",
    driver: ".github/workflows/aws-foundation-policy-migration-driver.yml",
    entry: ".github/workflows/aws-foundation-policy-migration.yml",
    exactHeadRequired: true,
    innerConcurrencyGroup: "archon-governed-canary-mutation-recovery",
    outerConcurrencyGroup: "archon-aws-control-plane",
    ownerActorOnly: true,
    queue: "max",
    exactParentAttemptJobsRequired: true,
    automaticCleanupCurrentHeadIndependent: true
  } and
  .implementation == {
    driver: "scripts/run-aws-foundation-policy-migration.sh",
    environmentVerifier: "scripts/verify-github-environment-protection.sh",
    libraries: [
      "scripts/aws-foundation-policy-migration-authorization.sh",
      "scripts/aws-foundation-policy-migration-common.sh",
      "scripts/aws-foundation-policy-migration-state.sh"
    ]
  } and
  .policy.initialVersionCount == 1 and
  .policy.successfulVersionCount == 2 and
  .policy.retainPreviousDefaultForRollback == true and
  .policy.exactDelta == {
    stackScopedActions: ["cloudformation:DetectStackResourceDrift"],
    stackScopedStatement: "ReconcileExactFoundationStacks",
    wildcardActions: ["cloudformation:BatchDescribeTypeConfigurations"],
    wildcardStatement: "InspectFoundationTemplates"
  } and
  .authorization.ttlSeconds == 1200 and
  .authorization.absenceReadCount == 3 and
  .authorization.managedPolicyActions == [
    "iam:CreatePolicyVersion",
    "iam:DeletePolicyVersion",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicyVersions",
    "iam:SetDefaultPolicyVersion"
  ] and
  .authorization.rollbackManagedPolicyActions == [
    "iam:DeletePolicyVersion",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicyVersions",
    "iam:SetDefaultPolicyVersion"
  ] and
  .authorization.selfPersistenceActionsAllowed == false and
  .authorization.canonicalReadbackRequired == true and
  .authorization.mandatoryRevocation == true and
  .phases == [
    "prepare-and-authorize",
    "create-and-verify-nondefault-version",
    "single-default-switch",
    "postverify-and-revoke"
  ] and
  .recovery == {
    automaticFollowerOnNonSuccess: true,
    deleteOnlyNewNondefaultVersion: true,
    freshRollbackOnlyAuthorization: true,
    mandatoryAuthorizationRevocation: true,
    manualDispatch: true,
    manualDispatchMode: "cleanup-rollback",
    parentOutcomeClassification: {
      migrateSucceeded: "cleanup-migrated",
      prepareNotSucceeded: "cleanup-revoke",
      prepareSucceededWithoutSuccessfulMigrationOrRollback:
        "cleanup-rollback",
      rollbackSucceeded: "cleanup-revoke"
    },
    revokeOnlyPreservesExactTerminalState: true,
    rollbackToPreviousDefault: true
  } and
  .evidence == {
    artifactFiles: ["SHA256SUMS", "migration.json"],
    artifactRetentionDays: 90,
    attestationRequired: true,
    canonicalJson: true,
    checksumSealed: true,
    schemaVersion: "archon.aws-foundation-policy-migration-receipt/v1",
    sensitiveIdentifiersAllowed: false
  }
' "${contract}" >/dev/null

jq --exit-status \
  --slurpfile migration "${contract}" '
    .aws.foundationPolicies.migrationContract ==
      "contracts/aws-foundation-policy-migration-v1.json" and
    $migration[0].policy.sourceBundle ==
      .aws.foundationPolicies.sourceBundle and
    $migration[0].policy.renderer ==
      .aws.foundationPolicies.renderer
  ' "${foundation_contract}" >/dev/null

workflow_triggers() {
  awk '
    /^on:[[:space:]]*$/ { inside=1; next }
    inside && /^[^[:space:]]/ { exit }
    inside && /^  [A-Za-z0-9_]+:[[:space:]]*$/ {
      key=$1
      sub(/:$/, "", key)
      print key
    }
  ' "$1" | LC_ALL=C sort
}

test "$(workflow_triggers "${entry}")" = "workflow_dispatch"
test "$(workflow_triggers "${driver_workflow}")" = "workflow_call"
test "$(workflow_triggers "${cleanup}")" = \
  $'workflow_dispatch\nworkflow_run'

require_text "${entry}" \
  'group: archon-aws-control-plane' \
  'queue: max' \
  'cancel-in-progress: false' \
  "github.actor == github.repository_owner" \
  "github.triggering_actor == github.repository_owner" \
  'MIGRATE EXACT FOUNDATION CONTROL POLICY' \
  'scripts/verify-github-control-plane.sh' \
  'uses: ./.github/workflows/aws-foundation-policy-migration-driver.yml'
require_text "${driver_workflow}" \
  'group: archon-governed-canary-mutation-recovery' \
  'queue: max' \
  'cancel-in-progress: false' \
  'name: aws-foundation' \
  'name: governed-canary-recovery' \
  'actions: read' \
  'deployments: read' \
  'bash scripts/verify-github-environment-protection.sh' \
  'Revalidate recovery environment immediately before OIDC' \
  'Revalidate foundation environment immediately before OIDC' \
  'Revalidate trusted revocation source after approval' \
  '.commit.verification.verified == true' \
  '.commit.verification.reason == "valid"' \
  'unset-current-credentials: true' \
  'if: always()' \
  'AUTHORIZATION_MODE:' \
  'bash scripts/run-aws-foundation-policy-migration.sh prepare' \
  'bash scripts/run-aws-foundation-policy-migration.sh migrate' \
  'bash scripts/run-aws-foundation-policy-migration.sh rollback' \
  'bash scripts/run-aws-foundation-policy-migration.sh revoke' \
  'Clear AWS credentials before evidence handling' \
  'printf '\''%s=\n'\'' "${variable}" >>"${GITHUB_ENV}"' \
  'test -z "${!variable:-}"' \
  'actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26' \
  'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
  'if-no-files-found: error' \
  'retention-days: 90'
test "$(grep -Ec '^      actions: read$' "${driver_workflow}")" -eq 4 ||
  fail "driver must grant actions: read to exactly four environment jobs"
test "$(grep -Ec '^      deployments: read$' "${driver_workflow}")" -eq 4 ||
  fail "driver must grant deployments: read to exactly four environment jobs"
require_text "${environment_verifier}" \
  '[[ "${GITHUB_ACTIONS:-}" == "true" ]]' \
  '[[ "${GITHUB_REPOSITORY}" == "upgradedev/archon-datahub" ]]' \
  'aws-foundation | governed-canary-recovery' \
  '.can_admins_bypass == false' \
  '(.protection_rules | length) == 2' \
  '.prevent_self_review == false' \
  '(.reviewers | length) == 1' \
  '.reviewers[0].type == "User"' \
  '.reviewers[0].reviewer.login == $owner' \
  '.total_count == 1' \
  '{name: "master", type: "branch"}'
require_text "${cleanup}" \
  'group: archon-aws-control-plane' \
  'queue: max' \
  'github.event.workflow_run.conclusion !=' \
  '.github/workflows/aws-foundation-policy-migration.yml' \
  'RECOVER EXACT FOUNDATION CONTROL POLICY MIGRATION' \
  'cleanup-migrated' \
  'cleanup-revoke' \
  'cleanup-rollback' \
  'needs.validate.outputs.cleanup_operation' \
  'exact parent-job conclusion' \
  'actions/runs/${TRIGGER_RUN_ID}/attempts/${TRIGGER_RUN_ATTEMPT}/jobs' \
  'uses: ./.github/workflows/aws-foundation-policy-migration-driver.yml'

for workflow in "${entry}" "${driver_workflow}" "${cleanup}"; do
  forbid_text "${workflow}" \
    'contents: write' \
    'checks: write' \
    'deployments: write' \
    'issues: write' \
    'packages: write' \
    'pull-requests: write' \
    'security-events: write' \
    'secrets: inherit'
  while IFS= read -r ref; do
    [[ "${ref}" == ./* ]] && continue
    [[ "${ref}" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]] ||
      fail "${workflow#${repository_root}/} has non-SHA action ref: ${ref}"
  done < <(
    sed -nE \
      's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+).*/\2/p' \
      "${workflow}"
  )
done

require_text "${main_driver}" \
  'set -Eeuo pipefail' \
  'prepare|migrate|rollback|revoke' \
  'test "${count}" -eq 2 || {' \
  'create-policy-version' \
  '--no-set-as-default' \
  'set-default-policy-version' \
  'sha256sum --check --strict SHA256SUMS' \
  'archon.aws-foundation-policy-migration-receipt/v1'
require_text "${common}" \
  'AWS foundation policy migration is CI-only' \
  'jq -cS' \
  'cloudformation:DetectStackResourceDrift' \
  'cloudformation:BatchDescribeTypeConfigurations' \
  'archon-aws-foundation-control' \
  'archon-datahub-github-governed-canary-recovery'
require_text "${authorization}" \
  'DateLessThan' \
  '"aws:CurrentTime"' \
  'iam:CreatePolicyVersion' \
  'iam:DeletePolicyVersion' \
  'iam:GetRolePolicy' \
  'put-role-policy' \
  'get-role-policy' \
  'delete-role-policy' \
  'ABSENCE_CONFIRMATIONS'
require_text "${state}" \
  'list-policy-versions' \
  'get-policy-version' \
  'wait_for_rollback_pending_state rollback-before-switch new' \
  'require_rollback_pending_state rollback-before-delete old' \
  'delete-policy-version' \
  'Unexpected managed-policy version count'
for script in \
  "${main_driver}" \
  "${common}" \
  "${authorization}" \
  "${state}" \
  "${environment_verifier}"; do
  forbid_text "${script}" \
    'set -x' \
    'set +e' \
    '|| true' \
    'printenv' \
    'declare -p' \
    'BASH_COMMAND' \
    'AdministratorAccess' \
    'aws iam pass-role ' \
    'aws iam attach-role-policy ' \
    'aws iam create-role ' \
    'aws iam delete-role '
done
forbid_text "${main_driver}" '--set-as-default' '< <(require_'
forbid_text "${authorization}" \
  '"Resource": "*"'
forbid_text "${canary_roles}" \
  'archon-foundation-control-policy-migration' \
  'iam:CreatePolicyVersion' \
  'iam:DeletePolicyVersion' \
  'iam:SetDefaultPolicyVersion'

jq --exit-status \
  --slurpfile migration "${contract}" '
    $migration[0] as $m |
    def statements($sid):
      [.Statement[] | select(.Sid == $sid)];
    def actions:
      [.Statement[].Action] | flatten;
    ($m.policy.exactDelta.stackScopedStatement) as $stackSid |
    ($m.policy.exactDelta.wildcardStatement) as $wildcardSid |
    (statements($stackSid) | length) == 1 and
    (statements($wildcardSid) | length) == 1 and
    all(statements($stackSid)[0].Resource[]; . != "*") and
    statements($wildcardSid)[0].Resource == "*" and
    ([actions[] |
      select(. == "cloudformation:DetectStackResourceDrift")] |
      length) == 1 and
    ([actions[] |
      select(. == "cloudformation:BatchDescribeTypeConfigurations")] |
      length) == 1
  ' "${foundation_policy}" >/dev/null

test "$(grep -Fc 'cloudformation:DetectStackResourceDrift' "${deploy_role}")" -eq 2
test "$(grep -Fc 'cloudformation:BatchDescribeTypeConfigurations' "${deploy_role}")" -eq 2

extract_sid_block() {
  local sid="$1"
  awk -v sid="${sid}" '
    $0 ~ "^[[:space:]]+- Sid: " sid "[[:space:]]*$" {
      inside=1
    }
    inside &&
      $0 ~ "^[[:space:]]+- Sid: " &&
      $0 !~ "^[[:space:]]+- Sid: " sid "[[:space:]]*$" {
      exit
    }
    inside { print }
  ' "${deploy_role}"
}

assert_sid_block() {
  local sid="$1"
  local expected_block="$2"
  local actual
  actual="$(extract_sid_block "${sid}")"
  test "${actual}" = "${expected_block}" ||
    fail "deploy role statement ${sid} differs from its exact action/resource scope"
}

assert_sid_block DetectExactStageIamFoundationDrift \
'              - Sid: DetectExactStageIamFoundationDrift
                Effect: Allow
                Action:
                  - cloudformation:DetectStackDrift
                  - cloudformation:DetectStackResourceDrift
                  - cloudformation:DescribeStackResourceDrifts
                Resource: !Sub arn:${AWS::Partition}:cloudformation:eu-west-1:${AWS::AccountId}:stack/${IamFoundationStackName}/*'
assert_sid_block ReadStageIamDriftDetection \
'              - Sid: ReadStageIamDriftDetection
                Effect: Allow
                Action:
                  - cloudformation:BatchDescribeTypeConfigurations
                  - cloudformation:DescribeStackDriftDetectionStatus
                Resource: "*"'
assert_sid_block ReadAndDetectExactProductionStacks \
'              - Sid: ReadAndDetectExactProductionStacks
                Effect: Allow
                Action:
                  - cloudformation:DescribeStacks
                  - cloudformation:DetectStackDrift
                  - cloudformation:DetectStackResourceDrift
                Resource:
                  - !Sub arn:${AWS::Partition}:cloudformation:eu-west-1:${AWS::AccountId}:stack/Archon-Registry/*
                  - !Sub arn:${AWS::Partition}:cloudformation:eu-west-1:${AWS::AccountId}:stack/Archon-production/*
                  - !Sub arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/Archon-production-Edge/*'
assert_sid_block ReadStackDriftDetectionStatus \
'              - Sid: ReadStackDriftDetectionStatus
                Effect: Allow
                Action:
                  - cloudformation:BatchDescribeTypeConfigurations
                  - cloudformation:DescribeStackDriftDetectionStatus
                Resource: "*"'

control_rendered="$(node "${renderer}" \
  --input "${foundation_policy}" \
  --account 123456789012 \
  --stdout-group control)"
jq -e '
  ([.Statement[].Action] | flatten |
    index("cloudformation:DetectStackResourceDrift")) != null and
  ([.Statement[].Action] | flatten |
    index("cloudformation:BatchDescribeTypeConfigurations")) != null
' <<<"${control_rendered}" >/dev/null
for group in assets identity attachments; do
  rendered="$(node "${renderer}" \
    --input "${foundation_policy}" \
    --account 123456789012 \
    --stdout-group "${group}")"
  jq -e '
    ([.Statement[].Action] | flatten |
      index("cloudformation:DetectStackResourceDrift") | not) and
    ([.Statement[].Action] | flatten |
      index("cloudformation:BatchDescribeTypeConfigurations") | not)
  ' <<<"${rendered}" >/dev/null
done

require_text "${repository_root}/docs/AWS_FOUNDATION.md" \
  'Existing foundation-policy version migration' \
  '`cloudformation:DetectStackResourceDrift`' \
  '`cloudformation:BatchDescribeTypeConfigurations`' \
  '`MIGRATE EXACT FOUNDATION CONTROL POLICY`' \
  'fresh rollback-only grant' \
  '`queue: max`' \
  'excludes account' \
  'raw IAM documents'

require_text "${ci_workflow}" \
  'tests/pipeline/aws-foundation-policy-migration-contracts.test.sh' \
  'tests/pipeline/aws-foundation-policy-migration-driver.test.sh' \
  'scripts/run-aws-foundation-policy-migration.sh' \
  'scripts/aws-foundation-policy-migration-common.sh' \
  'scripts/aws-foundation-policy-migration-authorization.sh' \
  'scripts/aws-foundation-policy-migration-state.sh' \
  'scripts/verify-github-environment-protection.sh'