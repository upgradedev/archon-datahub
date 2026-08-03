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
foundation_runbook="${repository_root}/docs/AWS_FOUNDATION.md"

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
  "${behavior_test}" "${validator_test}" "${runbook}" "${foundation_runbook}"; do
  test -f "${path}" || fail "missing ${path#${repository_root}/}"
  test ! -L "${path}" || fail "${path#${repository_root}/} must be a regular file"
done

jq --exit-status '
  .schemaVersion == "archon.aws-incident-recovery/v1" and
  .repository == "upgradedev/archon-datahub" and
  .defaultBranch == "master" and
  .status == "recovered-delete-complete-cleanup-proven" and
  .execution.recoveryRun == {
    artifact: {
      id: "8771158101",
      name: "aws-incident-recovery-30571830902-1",
      zipDigest: "sha256:f21cb3207f1ea91320ce732aa0592bfb014b5fd649bf907fd54f51cfb4003878"
    },
    canonicalAbsenceProof: "proven",
    deleteStack: "skipped",
    diagnosticCode: "AWS_RECOVERY_INCIDENT_RECORD_MISMATCH",
    headSha: "dd9b6f8c4c23bed290871c89a505ec12422d8caa",
    mandatoryRevocation: "success",
    putRolePolicy: "not-reached",
    result: "prepare-incident-record-mismatch",
    runAttempt: "1",
    runId: "30571830902"
  } and
  .execution.classifiedRecoveryRun == {
    artifact: {
      id: "8773039467",
      name: "aws-incident-recovery-30576390064-1",
      zipDigest: "sha256:5fea23ffcd4e0d4d323b129644320cc8569746dd417c56fe472e5ef3d580f20e"
    },
    canonicalAbsenceProof: "proven",
    deleteStack: "skipped",
    diagnosticCode: "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID",
    headSha: "9b9ed35e4c5a5bf0bfed4aa0b049ff654ad2d0b9",
    mandatoryRevocation: "success",
    putRolePolicy: "not-reached",
    result: "prepare-classified-delete-complete-no-physical-id",
    runAttempt: "1",
    runId: "30576390064"
  } and
  .execution.authorizationReadbackRun == {
    artifact: {
      evidenceScope: "cleanup-only",
      expiresAt: "2026-10-28T20:32:58Z",
      id: "8774187155",
      name: "aws-incident-recovery-30579644527-1",
      sizeBytes: 930,
      uploadedFileCount: 3,
      zipDigest: "sha256:f2ab1912324c75a2e1e04ea2ce4c8726905521eef38825cb656631667a2884a8"
    },
    canonicalAbsenceProof: "proven",
    canonicalPolicyReadback: "not-proven",
    deleteStack: "skipped",
    githubAttestation: "not-created",
    headSha: "bce219b0a03a5d3a7e162edf81866d00848aaac9",
    mandatoryRevocation: "success",
    putRolePolicy: "request-succeeded",
    result: "prepare-policy-readback-framing-mismatch",
    runAttempt: "1",
    runId: "30579644527",
    validator: "success"
  } and
  .execution.successfulRecoveryRun == {
    artifact: {
      createdAt: "2026-07-30T21:19:37Z",
      evidenceScope: "recovery-and-cleanup",
      expiresAt: "2026-10-28T21:15:52Z",
      id: "8775321544",
      name: "aws-incident-recovery-30582684638-1",
      sizeBytes: 2085,
      uploadedFileCount: 6,
      zipDigest: "sha256:dddf3d887781c18d2b1578c8083e450c41ba120753206b5f2f80b50031eee155"
    },
    canonicalAbsenceProof: "proven",
    canonicalPolicyReadback: "proven",
    cleanupFollower: {
      result: "skipped-on-success",
      runId: "30582939537"
    },
    completedAt: "2026-07-30T21:19:41Z",
    deleteStack: "executed-once",
    deletionMode: "STANDARD",
    githubAttestation: {
      id: "38051531",
      subject: "recovery.json",
      subjectDigest: "sha256:44f15d0c362cd16f7fa11a111956bceffa0afc7c6fd2cd5c0aca8747a0dc97ef",
      url: "https://github.com/upgradedev/archon-datahub/attestations/38051531"
    },
    headSha: "8b7451da65d1bf1ed14b17e0c1f0cc5d43d6cf40",
    mandatoryRevocation: "success",
    preflightGates: {
      ci: { result: "success", runId: "30582157198" },
      codeql: { result: "success", runId: "30582157151" },
      productionSupplyChain: { result: "success", runId: "30582494521" },
      workflowSecurity: { result: "success", runId: "30582157207" }
    },
    putRolePolicy: "request-succeeded",
    result: "success",
    runAttempt: "1",
    runId: "30582684638",
    stackDeletionProof: "original-id-delete-complete-and-no-active-name",
    validator: "success"
  } and
  .execution.cleanupRun == {
    artifact: {
      attestationUrl: "https://github.com/upgradedev/archon-datahub/attestations/38026442",
      cleanupPayloadSha256: "8cb752c3418f8587b5fb2a48fc19048babdb45db1570df5b9022831d774495d2",
      id: "8771042311",
      name: "aws-incident-recovery-cleanup-30571619440-1",
      zipDigest: "sha256:df4a796511f3afd850b5c7819b4562735fdec33e5f1fa1c2a286a5556a4739e0"
    },
    canonicalAbsenceProof: "proven",
    headSha: "dd9b6f8c4c23bed290871c89a505ec12422d8caa",
    result: "success",
    runAttempt: "1",
    runId: "30571619440"
  } and
  .execution.temporaryPolicyInstalledDuringSuccessfulRun == true and
  .execution.temporaryPolicyPresentAfterRun == false and
  .execution.temporaryPolicyAbsent == "proven" and
  .execution.deleteStackExecuted == true and
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
  .target.preconditions.resourceStatuses.paginationToken == "forbidden" and
  .target.preconditions.incidentResourceCurrentState == {
    acceptanceChange: "narrow-reviewed-after-classified-run-30576390064",
    acceptedClasses: [
      "CREATE_FAILED-without-PhysicalResourceId",
      "exact-logical-id-and-type-DELETE_COMPLETE-without-PhysicalResourceId"
    ],
    diagnosticOnlyRejectedClasses: [
      "DELETE_COMPLETE-with-PhysicalResourceId"
    ],
    rejectionPoint: "before-PutRolePolicy"
  } and
  .recoveryRole.stackTemplateSourceSha256 == "0c636d2af933c03b7752334fd4998141355564696ba08c81e06bda8bb459df73" and
  .recoveryRole.baselinePolicyUnchanged == true and
  .recoveryRole.foundationRolePolicyBroadening == "forbidden" and
  .recoveryRole.attachedManagedPolicies == "forbidden" and
  .recoveryRole.temporaryPolicy.onlyMutatingAction == "cloudformation:DeleteStack" and
  .recoveryRole.temporaryPolicy.maximumTtlSeconds == 1800 and
  .plan.canonicalPolicyDigestBytes ==
    "sorted-compact-json-utf8-without-trailing-newline" and
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
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID",
    "AWS_RECOVERY_INCIDENT_RECORD_NOT_UNIQUE",
    "AWS_RECOVERY_INCIDENT_RESOURCE_TYPE_MISMATCH",
    "AWS_RECOVERY_INVALID_INVOCATION",
    "AWS_RECOVERY_PLAN_VALIDATION_FAILED",
    "AWS_RECOVERY_RESOURCE_CREATE_FAILED_PHYSICAL_ID",
    "AWS_RECOVERY_RESOURCE_STATE_EMPTY",
    "AWS_RECOVERY_RESOURCE_STATE_PAGINATED",
    "AWS_RECOVERY_RESOURCE_STATE_UNAVAILABLE",
    "AWS_RECOVERY_RESOURCE_SUMMARY_SHAPE_INVALID",
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
  .validator.diagnosticOnlyCodes == [
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID",
    "AWS_RECOVERY_INCIDENT_RESOURCE_TYPE_MISMATCH",
    "AWS_RECOVERY_RESOURCE_STATE_PAGINATED",
    "AWS_RECOVERY_RESOURCE_SUMMARY_SHAPE_INVALID"
  ] and
  .validator.diagnosticOnlySemantics ==
    "remaining-nonaccepted-classes-fail-closed-before-authorization" and
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
    "recovered-delete-complete-cleanup-proven"
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
  'deployment-evidence-${{ inputs.stage }}-${{ inputs.release_sha }}-${{ github.run_id }}'
forbid_text "${deploy_workflow}" \
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
  'observed_policy_canonical="$(' \
  "jq -ceS '.PolicyDocument | select(type == \"object\")'" \
  "printf '%s' \"\${observed_policy_canonical}\" | sha256sum" \
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
require_text "${behavior_test}" \
  'policy digest domains must distinguish the trailing newline' \
  'canonical IAM readback must hash the same no-newline bytes as the validator' \
  'for rejection in mismatch malformed wrong-shape newline-domain' \
  'must exhaust bounded policy-readback attempts' \
  'validator and IAM readback canonical bytes differ' \
  'canonicalJson' \
  'cmp -s'
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
  'delete-role-policy.error' \
  "jq -cS '.PolicyDocument'"
cleanup_function="$(sed -n '/^cleanup()/,/^}/p' "${driver}")"
if grep -Fq 'delete-stack' <<<"${cleanup_function}"; then fail 'cleanup mode can call DeleteStack'; fi
forbid_text "${cleanup_workflow}" 'cloudformation delete-stack' 'delete-stack'
forbid_text "${reconciler}" 'cloudformation delete-stack' 'delete-stack' 'continue-update-rollback'

test "$(sha256sum "${canary_roles}" | awk '{print $1}')" = \
  '0c636d2af933c03b7752334fd4998141355564696ba08c81e06bda8bb459df73' || \
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
  'Status: **recovered; `DeleteStack` executed once; deletion and cleanup proofs successful**' \
  '`recovered-delete-complete-cleanup-proven`' \
  'Successful recovery run | `30582684638`' \
  'CI `30582157198`; CodeQL `30582157151`' \
  'Workflow Security `30582157207`; Production Supply Chain `30582494521`' \
  'Exactly one `STANDARD` `DeleteStack`' \
  '`sha256:dddf3d887781c18d2b1578c8083e450c41ba120753206b5f2f80b50031eee155`' \
  '`44f15d0c362cd16f7fa11a111956bceffa0afc7c6fd2cd5c0aca8747a0dc97ef`' \
  'https://github.com/upgradedev/archon-datahub/attestations/38051531' \
  'Run `30582939537` skipped on successful source recovery' \
  'do not dispatch' \
  'now-absent target must make any accidental rerun fail before authorization' \
  'GitHub attestation `38051531` binds only canonical `recovery.json`' \
  'cleanup files are retained evidence, not separately attested' \
  'ResourceStatus` as the resource' \
  '`ROLLBACK_COMPLETE`' \
  '`DELETE_SKIPPED`' \
  '`AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID`' \
  '`AWS_RECOVERY_RESOURCE_STATE_PAGINATED`' \
  'eventually consistent' \
  'lists inline policies before mutation' \
  'The opaque request response is never treated as proof' \
  'Upload runs only when at least'
forbid_text "${validator}" \
  'AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID'
forbid_text "${driver}" \
  '--no-paginate' \
  '--max-items' \
  '--max-results' \
  '--next-token' \
  '--starting-token'

require_text "${foundation_runbook}" \
  '`recovered-delete-complete-cleanup-proven`' \
  'Exact-master run `30582684638`' \
  'exactly one `STANDARD` `DeleteStack`' \
  'Artifact `8775321544` and GitHub' \
  'attestation `38051531`' \
  'cleanup follower' \
  '`30582939537` skipped on success' \
  'ordinary idempotent foundation workflow'
