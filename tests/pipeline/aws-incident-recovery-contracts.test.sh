#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
entry="${repository_root}/.github/workflows/aws-incident-recovery.yml"
driver_workflow="${repository_root}/.github/workflows/aws-incident-recovery-driver.yml"
cleanup_workflow="${repository_root}/.github/workflows/aws-incident-recovery-cleanup.yml"
foundation_workflow="${repository_root}/.github/workflows/aws-foundation.yml"
deploy_workflow="${repository_root}/.github/workflows/deploy.yml"
canary_workflow="${repository_root}/.github/workflows/governed-canary.yml"
canary_recovery_workflow="${repository_root}/.github/workflows/governed-canary-recovery.yml"
contract="${repository_root}/contracts/aws-incident-recovery-v1.json"
foundation_contract="${repository_root}/contracts/aws-foundation-v1.json"
canary_roles="${repository_root}/infra/aws/foundation/governed-canary-roles.yml"
driver="${repository_root}/scripts/run-aws-incident-recovery.sh"
validator="${repository_root}/scripts/aws-incident-recovery.mjs"
reconciler="${repository_root}/scripts/reconcile-aws-foundation.sh"
ci="${repository_root}/.github/workflows/ci.yml"
behavior_test="${repository_root}/tests/pipeline/aws-incident-recovery-driver.test.sh"
validator_test="${repository_root}/tests/pipeline/aws-incident-recovery-validator.test.mjs"

fail() { echo "::error::$*" >&2; exit 1; }
require_text() {
  local path="$1"; shift
  local value
  for value in "$@"; do
    grep -Fq -- "${value}" "${path}" || fail "${path#${repository_root}/} is missing: ${value}"
  done
}
forbid_text() {
  local path="$1"; shift
  local value
  for value in "$@"; do
    if grep -Fq -- "${value}" "${path}"; then
      fail "${path#${repository_root}/} contains forbidden text: ${value}"
    fi
  done
}
require_count() {
  local expected="$1" path="$2" value="$3" actual
  actual="$(grep -Foc -- "${value}" "${path}" || true)"
  test "${actual}" = "${expected}" || fail "${path#${repository_root}/}: expected ${expected} occurrences of ${value}, found ${actual}"
}

for path in "${entry}" "${driver_workflow}" "${cleanup_workflow}" \
  "${foundation_workflow}" "${deploy_workflow}" "${canary_workflow}" \
  "${canary_recovery_workflow}" "${contract}" "${foundation_contract}" \
  "${canary_roles}" "${driver}" "${validator}" "${reconciler}" "${ci}" \
  "${behavior_test}" "${validator_test}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must be a regular file"
done

jq --exit-status '
  .schemaVersion == "archon.aws-incident-recovery/v1" and
  .repository == "upgradedev/archon-datahub" and
  .defaultBranch == "master" and
  .status == "implemented-not-executed" and
  .controlPlane.inputs == ["expected_head_sha", "confirmation"] and
  .controlPlane.secretForwarding == "none" and
  .controlPlane.approvalEnvironments == {
    deleteOnce: "governed-canary-recovery",
    prepareAndRevoke: "aws-foundation"
  } and
  .controlPlane.concurrency.entryAndCleanup == "archon-aws-control-plane" and
  .controlPlane.concurrency.reusableDriver == "archon-governed-canary-mutation-recovery" and
  .controlPlane.concurrency.foundationJob == "archon-governed-canary-mutation-recovery" and
  .controlPlane.concurrency.lockOrder == [
    "archon-aws-control-plane",
    "archon-governed-canary-mutation-recovery"
  ] and
  .controlPlane.concurrency.cancelInProgress == false and
  .incident.runId == "30546241677" and
  .incident.runAttempt == "1" and
  .incident.headSha == "aea65845e3a9456403a7fb6e9f338e4c14c0b781" and
  .incident.artifact.id == "8760846578" and
  .incident.artifact.digest == "sha256:7aa20586b970ac938fba9299e0c3c2538482b92086db811ea583f84bd3b02e24" and
  .incident.artifact.inventory == ["SHA256SUMS", "cfn-failure.json"] and
  .incident.artifact.checksumManifestSha256 == "9ecfdff27c6de11ab7403ad75780a7fae3339efe05684c6b3ec3185be6a52703" and
  .incident.artifact.failurePayloadSha256 == "187d4cf683a61a778feec2051f1ef5c99b60cc58344edbf1a7d0189f28c67442" and
  .target.region == "eu-west-1" and
  .target.stackName == "Archon-Staging-IAM-Foundation" and
  .target.sourceTemplateSemanticSha256 == "80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825" and
  .target.preconditions.resourceStatuses.allowed == [
    "CREATE_FAILED-without-PhysicalResourceId",
    "DELETE_COMPLETE"
  ] and
  .recoveryRole.stackTemplateSourceSha256 == "0ab7fc740588232d25c16f92ccf636e45a80b7d4c1b7d8f462b853ea3c9e75c4" and
  .recoveryRole.baselinePolicyUnchanged == true and
  .recoveryRole.foundationRolePolicyBroadening == "forbidden" and
  .recoveryRole.attachedManagedPolicies == "forbidden" and
  .recoveryRole.temporaryPolicy.onlyMutatingAction == "cloudformation:DeleteStack" and
  .recoveryRole.temporaryPolicy.maximumTtlSeconds == 1800 and
  .delete == {
    callCount: 1,
    clientRequestToken: "deterministic-from-incident-attempt-and-control-plane-sha",
    deletionMode: "STANDARD",
    deploymentConfigOverride: false,
    forceDelete: false,
    retainResources: false,
    roleOverride: false,
    stackArgument: "sealed-full-stack-id",
    targetInput: false
  } and
  .revocation.deleteFailureHandling == "success-or-exact-NoSuchEntity-only" and
  .revocation.absenceConfirmations == 3 and
  .revocation.independentRetryTriggers == {
    schedule: "forbidden",
    successfulRun: "forbidden",
    workflowDispatch: true,
    workflowRunConclusions: [
      "action_required",
      "cancelled",
      "failure",
      "stale",
      "timed_out"
    ]
  } and
  .postverification.stackNameHasNoActiveStack == true and
  .normalFoundation.autoRecovery == "forbidden" and
  .normalFoundation.reconcilerDeleteStack == "forbidden" and
  .tests == {
    contract: "tests/pipeline/aws-incident-recovery-contracts.test.sh",
    driver: "tests/pipeline/aws-incident-recovery-driver.test.sh",
    validator: "tests/pipeline/aws-incident-recovery-validator.test.mjs"
  }
' "${contract}" >/dev/null

jq --exit-status '
  .evidence.failureDiagnostics.autoRecovery == "forbidden" and
  .evidence.failureDiagnostics.explicitIncidentRecoveryContract ==
    "contracts/aws-incident-recovery-v1.json" and
  .evidence.failureDiagnostics.explicitIncidentRecoveryStatus ==
    "implemented-not-executed"
' "${foundation_contract}" >/dev/null

require_count 2 "${entry}" '        type: string'
require_text "${entry}" \
  'group: archon-aws-control-plane' \
  'cancel-in-progress: false' \
  'uses: ./.github/workflows/aws-incident-recovery-driver.yml' \
  "inputs.confirmation == 'DELETE SEALED STAGING IAM INCIDENT'"
forbid_text "${entry}" 'secrets: inherit' 'stack_name:' 'stack_id:' 'target:'

require_text "${driver_workflow}" \
  'workflow_call:' \
  'group: archon-governed-canary-mutation-recovery' \
  'cancel-in-progress: false' \
  'name: aws-foundation' \
  'name: governed-canary-recovery' \
  'artifact-ids: "8760846578"' \
  'merge-multiple: true' \
  'run-id: "30546241677"' \
  'if: always()' \
  'run: bash scripts/run-aws-incident-recovery.sh delete-once' \
  'run: bash scripts/run-aws-incident-recovery.sh cleanup'
forbid_text "${driver_workflow}" 'secrets: inherit'

require_text "${cleanup_workflow}" \
  'workflow_run:' \
  'workflow_dispatch:' \
  "github.event.workflow_run.conclusion == 'action_required'" \
  "github.event.workflow_run.conclusion == 'cancelled'" \
  "github.event.workflow_run.conclusion == 'failure'" \
  "github.event.workflow_run.conclusion == 'stale'" \
  "github.event.workflow_run.conclusion == 'timed_out'" \
  'group: archon-aws-control-plane' \
  'cancel-in-progress: false'
forbid_text "${cleanup_workflow}" 'schedule:' 'cron:' "conclusion == 'success'" 'secrets: inherit'

require_text "${foundation_workflow}" \
  'group: archon-aws-control-plane' \
  'group: archon-governed-canary-mutation-recovery' \
  'cancel-in-progress: false'
require_text "${deploy_workflow}" \
  'group: archon-aws-control-plane' \
  '/actions/workflows/governed-canary.yml/dispatches'
require_text "${canary_workflow}" 'group: archon-governed-canary-mutation-recovery'
require_text "${canary_recovery_workflow}" 'group: archon-governed-canary-mutation-recovery'

require_text "${driver}" \
  'AWS incident recovery is CI-only' \
  'exec 3>&1' \
  "printf '::add-mask::%s\\n' \"\$1\" >&3" \
  'readonly IAM_PROPAGATION_ATTEMPTS="12"' \
  'readonly IAM_ABSENCE_CONFIRMATIONS="3"' \
  'iam list-attached-role-policies' \
  '.AttachedPolicies == []' \
  'iam put-role-policy' \
  'iam delete-role-policy' \
  'NoSuchEntity' \
  'consecutive_absent' \
  'cloudformation:RoleArn' \
  'original-id-delete-complete-and-no-active-name'
require_count 3 "${driver}" 'mask_value "${stack_id}"'
require_count 1 "${driver}" 'aws cloudformation delete-stack'
require_count 1 "${driver}" 'aws iam put-role-policy'
require_count 1 "${driver}" 'aws iam delete-role-policy'
forbid_text "${driver}" \
  'echo "::add-mask::' \
  '|| true' \
  '--force' \
  'FORCE_DELETE_STACK' \
  '--retain-resources' \
  '--role-arn' \
  '--deployment-config'
forbid_text "${cleanup_workflow}" 'cloudformation delete-stack' 'delete-stack'
forbid_text "${reconciler}" 'cloudformation delete-stack' 'delete-stack' 'continue-update-rollback'

test "$(sha256sum "${canary_roles}" | awk '{print $1}')" = \
  '0ab7fc740588232d25c16f92ccf636e45a80b7d4c1b7d8f462b853ea3c9e75c4' || \
  fail 'governed-canary role source changed'

require_text "${ci}" \
  'scripts/run-aws-incident-recovery.sh' \
  'scripts/aws-incident-recovery.mjs' \
  'tests/pipeline/aws-incident-recovery-contracts.test.sh' \
  'tests/pipeline/aws-incident-recovery-driver.test.sh' \
  'node --test tests/pipeline/aws-incident-recovery-validator.test.mjs' \
  'bash tests/pipeline/aws-incident-recovery-contracts.test.sh' \
  'bash tests/pipeline/aws-incident-recovery-driver.test.sh'