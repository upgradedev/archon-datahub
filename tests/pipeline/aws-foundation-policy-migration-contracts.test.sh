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
  "${ci_workflow}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must not be a symlink"
done

for script in "${main_driver}" "${common}" "${authorization}" "${state}"; do
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
    queue: "max"
  } and
  .implementation == {
    driver: "scripts/run-aws-foundation-policy-migration.sh",
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

entry_trigger="$(sed -n '/^on:/,/^permissions:/p' "${entry}" | sed '$d')"
driver_trigger="$(sed -n '/^on:/,/^permissions:/p' "${driver_workflow}" | sed '$d')"
cleanup_trigger="$(sed -n '/^on:/,/^permissions:/p' "${cleanup}" | sed '$d')"
grep -Fq '  workflow_dispatch:' <<<"${entry_trigger}"
grep -Fq '  workflow_call:' <<<"${driver_trigger}"
grep -Fq '  workflow_run:' <<<"${cleanup_trigger}"
grep -Fq '  workflow_dispatch:' <<<"${cleanup_trigger}"
for trigger in push: pull_request: schedule: cron:; do
  if grep -Fq "${trigger}" <<<"${entry_trigger}${driver_trigger}${cleanup_trigger}"; then
    fail "migration control plane contains forbidden trigger ${trigger}"
  fi
done

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
  'unset-current-credentials: true' \
  'if: always()' \
  'AUTHORIZATION_MODE:' \
  'bash scripts/run-aws-foundation-policy-migration.sh prepare' \
  'bash scripts/run-aws-foundation-policy-migration.sh migrate' \
  'bash scripts/run-aws-foundation-policy-migration.sh rollback' \
  'bash scripts/run-aws-foundation-policy-migration.sh revoke' \
  'Clear AWS credentials before evidence handling' \
  'actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26' \
  'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
  'if-no-files-found: error' \
  'retention-days: 90'
require_text "${cleanup}" \
  'group: archon-aws-control-plane' \
  'queue: max' \
  'github.event.workflow_run.conclusion !=' \
  '.github/workflows/aws-foundation-policy-migration.yml' \
  'RECOVER EXACT FOUNDATION CONTROL POLICY MIGRATION' \
  'operation: cleanup' \
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
  if grep -E '^[[:space:]]*uses: [^@]+@(main|master|v[0-9]+)' "${workflow}"; then
    fail "${workflow#${repository_root}/} contains a mutable action reference"
  fi
done

require_text "${main_driver}" \
  'set -Eeuo pipefail' \
  'prepare|migrate|rollback|revoke' \
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
  'require_rollback_pending_state rollback-before-switch new' \
  'require_rollback_pending_state rollback-before-delete old' \
  'delete-policy-version' \
  'Unexpected managed-policy version count'
for script in "${main_driver}" "${common}" "${authorization}" "${state}"; do
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
forbid_text "${main_driver}" '--set-as-default'
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
  'scripts/run-aws-foundation-policy-migration.sh' \
  'scripts/aws-foundation-policy-migration-common.sh' \
  'scripts/aws-foundation-policy-migration-authorization.sh' \
  'scripts/aws-foundation-policy-migration-state.sh'