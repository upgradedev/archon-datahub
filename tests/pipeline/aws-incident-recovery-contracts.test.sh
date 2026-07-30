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
fixture_workflow="${repository_root}/.github/workflows/datahub-canary-fixture.yml"
contract="${repository_root}/contracts/aws-incident-recovery-v1.json"
foundation_contract="${repository_root}/contracts/aws-foundation-v1.json"
canary_roles="${repository_root}/infra/aws/foundation/governed-canary-roles.yml"
driver="${repository_root}/scripts/run-aws-incident-recovery.sh"
validator="${repository_root}/scripts/aws-incident-recovery.mjs"
reconciler="${repository_root}/scripts/reconcile-aws-foundation.sh"
ci="${repository_root}/.github/workflows/ci.yml"
behavior_test="${repository_root}/tests/pipeline/aws-incident-recovery-driver.test.sh"
validator_test="${repository_root}/tests/pipeline/aws-incident-recovery-validator.test.mjs"
runbook="${repository_root}/docs/AWS_INCIDENT_RECOVERY.md"

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
  "${canary_recovery_workflow}" "${fixture_workflow}" "${contract}" "${foundation_contract}" \
  "${canary_roles}" "${driver}" "${validator}" "${reconciler}" "${ci}" \
  "${behavior_test}" "${validator_test}" "${runbook}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must be a regular file"
done

jq --exit-status '
  .schemaVersion == "archon.aws-incident-recovery/v1" and
  .repository == "upgradedev/archon-datahub" and
  .defaultBranch == "master" and
    .status == "attempted-delete-not-executed-cleanup-proof-pending" and
  .execution == {
    cleanupRun: {
      canonicalAbsenceProof: "pending",
      result: "failure",
      runId: "30567949203"
    },
    deleteStackExecuted: false,
    recoveryRun: {
      deleteStack: "skipped",
      result: "prepare-build-plan-failed",
      runId: "30567769601"
    },
    temporaryPolicyAbsent: "not-proven",
    temporaryPolicyInstalled: "not-proven"
  } and
  .controlPlane.inputs == ["expected_head_sha", "confirmation"] and
  .controlPlane.secretForwarding == "none" and
  .controlPlane.runbook == "docs/AWS_INCIDENT_RECOVERY.md" and
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
    .revocation.preDeleteInventoryRequired == true and
  .revocation.deleteOnlyWhenTemporaryPolicyPresent == true and
  .revocation.baseOnlyDeleteCallCount == 0 and
  .revocation.temporaryPolicyPresentDeleteCallCount == 1 and
  .revocation.deleteResponseAuthoritative == false and
  .revocation.canonicalPostcondition ==
    "three-consecutive-exact-baseline-only-inventories" and
  .revocation.unexpectedInventoryWithoutTemporaryPolicy ==
    "fail-without-delete" and
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
  .validator.cliFailureCodes == [
    "AWS_RECOVERY_ARTIFACT_VALIDATION_FAILED",
    "AWS_RECOVERY_INCIDENT_RECORD_MISMATCH",
    "AWS_RECOVERY_INCIDENT_RECORD_NOT_UNIQUE",
    "AWS_RECOVERY_INVALID_INVOCATION",
    "AWS_RECOVERY_PLAN_VALIDATION_FAILED",
    "AWS_RECOVERY_RESOURCE_CREATE_FAILED_PHYSICAL_ID",
    "AWS_RECOVERY_RESOURCE_STATE_EMPTY",
    "AWS_RECOVERY_RESOURCE_STATE_UNAVAILABLE",
    "AWS_RECOVERY_RESOURCE_UNSUPPORTED_STATUS",
    "AWS_RECOVERY_STACK_AUTHORITY_INVALID",
    "AWS_RECOVERY_STACK_ID_INVALID",
    "AWS_RECOVERY_STACK_NESTING_INVALID",
    "AWS_RECOVERY_STACK_STATUS_INVALID",
    "AWS_RECOVERY_STACK_TAGS_INVALID",
    "AWS_RECOVERY_STACK_TERMINATION_PROTECTION_INVALID",
    "AWS_RECOVERY_TEMPLATE_IDENTITY_INVALID",
    "AWS_RECOVERY_TTL_INVALID",
    "AWS_RECOVERY_VALIDATOR_FAILED"
  ] and
  .validator.fallbackCliFailureCode == "AWS_RECOVERY_VALIDATOR_FAILED" and
  .validator.rawErrorMessages == false and
  .validator.rawPaths == false and
  .validator.rawValues == false and
  .evidence.uploadRequiresEvidenceProducerSuccess == true and
  .evidence.failedCleanupWithoutEvidenceUpload == true and
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
  'description: "Exact internal operation: recover or cleanup"' \
  'group: archon-governed-canary-mutation-recovery' \
  'cancel-in-progress: false' \
  'name: aws-foundation' \
  'name: governed-canary-recovery' \
  'artifact-ids: "8760846578"' \
  'merge-multiple: true' \
  'run-id: "30546241677"' \
  'if: always()' \
  'run: bash scripts/run-aws-incident-recovery.sh delete-once' \
  'run: bash scripts/run-aws-incident-recovery.sh cleanup' \
  "(steps.recovery.outcome == 'success' ||" \
  "steps.cleanup.outcome == 'success' ||" \
  "steps.final_cleanup.outcome == 'success')"
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

entry_trigger="$(sed -n '/^on:/,/^permissions:/p' "${entry}" | sed '$d')"
driver_trigger="$(sed -n '/^on:/,/^permissions:/p' "${driver_workflow}" | sed '$d')"
cleanup_trigger="$(sed -n '/^on:/,/^permissions:/p' "${cleanup_workflow}" | sed '$d')"
grep -Fq '  workflow_dispatch:' <<<"${entry_trigger}" || fail 'entry must be manual-only'
grep -Fq '  workflow_call:' <<<"${driver_trigger}" || fail 'driver must be callable-only'
grep -Fq '  workflow_run:' <<<"${cleanup_trigger}" || fail 'cleanup workflow_run trigger is missing'
grep -Fq '  workflow_dispatch:' <<<"${cleanup_trigger}" || fail 'cleanup manual trigger is missing'
for forbidden in '  push:' '  pull_request:' '  schedule:' '  workflow_call:'; do
  grep -Fq "${forbidden}" <<<"${entry_trigger}" && fail "entry has forbidden trigger ${forbidden}"
done
for forbidden in '  push:' '  pull_request:' '  schedule:' '  workflow_dispatch:' '  workflow_run:'; do
  grep -Fq "${forbidden}" <<<"${driver_trigger}" && fail "driver has forbidden trigger ${forbidden}"
done
for forbidden in '  push:' '  pull_request:' '  schedule:' '  workflow_call:'; do
  grep -Fq "${forbidden}" <<<"${cleanup_trigger}" && fail "cleanup has forbidden trigger ${forbidden}"
done

entry_lock="$(sed -n '/^concurrency:/,/^jobs:/p' "${entry}" | sed '$d')"
driver_lock="$(sed -n '/^concurrency:/,/^env:/p' "${driver_workflow}" | sed '$d')"
foundation_outer_lock="$(sed -n '/^concurrency:/,/^env:/p' "${foundation_workflow}" | sed '$d')"
foundation_inner_lock="$(sed -n '/^  foundation:/,/^    runs-on:/p' "${foundation_workflow}" | sed '$d')"
cleanup_outer_lock="$(sed -n '/^  cleanup:/,/^    permissions:/p' "${cleanup_workflow}" | sed '$d')"
for blob in "${entry_lock}" "${foundation_outer_lock}" "${cleanup_outer_lock}"; do
  grep -Fq 'group: archon-aws-control-plane' <<<"${blob}" || fail 'outer lock is out of scope'
  grep -Fq 'cancel-in-progress: false' <<<"${blob}" || fail 'outer lock must not cancel'
done
for blob in "${driver_lock}" "${foundation_inner_lock}"; do
  grep -Fq 'group: archon-governed-canary-mutation-recovery' <<<"${blob}" || fail 'inner lock is out of scope'
  grep -Fq 'cancel-in-progress: false' <<<"${blob}" || fail 'inner lock must not cancel'
done
require_text "${deploy_workflow}" \
  'group: archon-aws-control-plane' \
  '/actions/workflows/governed-canary.yml/dispatches'
for workflow in "${fixture_workflow}" "${canary_workflow}" "${canary_recovery_workflow}"; do
  lock="$(sed -n '/^concurrency:/,/^env:/p' "${workflow}" | sed '$d')"
  grep -Fq 'group: archon-governed-canary-mutation-recovery' <<<"${lock}" || fail "${workflow#${repository_root}/} inner lock differs"
  grep -Fq 'cancel-in-progress: false' <<<"${lock}" || fail "${workflow#${repository_root}/} lock must not cancel"
done

for workflow in "${entry}" "${driver_workflow}" "${cleanup_workflow}"; do
  while IFS= read -r action; do
    [[ "${action}" == ./* ]] && continue
    ref="${action##*@}"
    ref="${ref%% *}"
    [[ "${ref}" =~ ^[0-9a-f]{40}$ ]] || fail "${workflow#${repository_root}/} has a non-SHA action pin: ${action}"
  done < <(sed -nE 's/^[[:space:]]*(- )?uses:[[:space:]]+([^#[:space:]]+).*/\2/p' "${workflow}")
done
require_text "${cleanup_workflow}" \
  'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
require_text "${driver_workflow}" \
  'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
  'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020' \
  'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' \
  'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
  'actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26' \
  'aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c' \
  'PREPARED_PLAN_DIGEST: ${{ needs.prepare.outputs.plan_digest }}' \
  'PREPARED_POLICY_SHA256: ${{ needs.prepare.outputs.policy_sha256 }}' \
  'PREPARED_STACK_ID_SHA256: ${{ needs.prepare.outputs.stack_id_sha256 }}' \
  '[[ "${PREPARED_PLAN_DIGEST}" =~ ^sha256:[a-f0-9]{64}$ ]]'
for workflow in "${entry}" "${driver_workflow}" "${cleanup_workflow}"; do
  forbid_text "${workflow}" \
    'contents: write' 'checks: write' 'deployments: write' 'issues: write' \
    'packages: write' 'pull-requests: write' 'security-events: write'
done
for section in \
  "$(sed -n '/^  recover:/,$p' "${entry}")" \
  "$(sed -n '/^  cleanup:/,$p' "${cleanup_workflow}")" \
  "$(sed -n '/^  revoke-and-postverify:/,/^  cleanup:/p' "${driver_workflow}")" \
  "$(sed -n '/^  cleanup:/,$p' "${driver_workflow}")"; do
  grep -Fq 'actions: read' <<<"${section}" || fail 'caller/called permissions omit actions:read'
  grep -Fq 'attestations: write' <<<"${section}" || fail 'caller/called permissions omit attestations:write'
  grep -Fq 'contents: read' <<<"${section}" || fail 'caller/called permissions omit contents:read'
  grep -Fq 'id-token: write' <<<"${section}" || fail 'caller/called permissions omit id-token:write'
done
for section in \
  "$(sed -n '/^  prepare:/,/^  delete-once:/p' "${driver_workflow}")" \
  "$(sed -n '/^  delete-once:/,/^  revoke-and-postverify:/p' "${driver_workflow}")"; do
  grep -Fq 'contents: read' <<<"${section}" || fail 'prepare/delete permissions omit contents:read'
  grep -Fq 'id-token: write' <<<"${section}" || fail 'prepare/delete permissions omit id-token:write'
done

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
  'Unable to inspect recovery-role inline policies before revocation' \
  'local delete_required=false' \
  'any(.PolicyNames[]; . == $temp)' \
  'consecutive_absent' \
  'original-id-delete-complete-and-no-active-name' \
  '--deletion-mode STANDARD'
require_text "${validator}" \
  'cloudformation:RoleArn' \
  'Null: { "cloudformation:RoleArn": "true" }' \
  'CLI_FAILURE_CODE_ALLOWLIST' \
  'error instanceof PlanInvariantError' \
  'error instanceof CliFailure' \
  'AWS_RECOVERY_STACK_STATUS_INVALID' \
  'AWS_RECOVERY_RESOURCE_CREATE_FAILED_PHYSICAL_ID' \
  'sanitizedCliFailureCode(error)'
forbid_text "${validator}" \
  'error.message' 'error.stack' 'error.path' 'JSON.stringify(error' \
  'process.stderr.write(error' 'console.error('
require_text "${validator_test}" \
  'spawnSync' \
  'PRIVATE_RECOVERY_VALUE' \
  'PRIVATE_PLAN_INVARIANT' \
  'CLI_FAILURE_CODES.STACK_STATUS_INVALID' \
  'CLI_FAILURE_CODES.RESOURCE_CREATE_FAILED_PHYSICAL_ID' \
  'assert.equal(result.stderr'
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
  '--deployment-config' \
  'NoSuchEntity' \
  'delete-role-policy.error'
cleanup_function="$(sed -n '/^cleanup()/,/^}/p' "${driver}")"
if grep -Fq 'delete-stack' <<<"${cleanup_function}"; then fail 'cleanup mode can call DeleteStack'; fi
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
require_text "${runbook}" \
  'Status: **attempted; `DeleteStack` not executed; cleanup proof pending**' \
  'Recovery run `30567769601` failed during prepare/build-plan' \
  'Cleanup run `30567949203` also failed' \
  'PutRolePolicy' \
  'eventually consistent' \
  'lists inline policies before mutation' \
  'The opaque request response is never treated as proof' \
  'Upload runs only when at least'
