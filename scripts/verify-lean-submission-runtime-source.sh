#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 deployment|availability SOURCE_DIR OUTPUT_DIR RELEASE_SHA RUN_ID RUN_ATTEMPT ARTIFACT_ID ARTIFACT_NAME ARTIFACT_DIGEST" >&2
  exit 64
}

[[ "$#" -eq 9 ]] || usage
mode="$1"
source_dir="$2"
output_dir="$3"
release_sha="$4"
run_id="$5"
run_attempt="$6"
artifact_id="$7"
artifact_name="$8"
artifact_digest="$9"

[[ "${mode}" =~ ^(deployment|availability)$ ]] || usage
[[ "${release_sha}" =~ ^[0-9a-f]{40}$ ]] || usage
for value in "${run_id}" "${run_attempt}" "${artifact_id}"; do
  [[ "${value}" =~ ^[1-9][0-9]{0,19}$ ]] || usage
done
[[ "${artifact_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || usage
[[ "${GITHUB_REPOSITORY:-}" == upgradedev/archon-datahub ]] || {
  echo "::error::runtime evidence verifier is repository-bound" >&2
  exit 1
}
[[ "${GITHUB_REF:-refs/heads/master}" == refs/heads/master ]] || {
  echo "::error::runtime evidence must bind master" >&2
  exit 1
}
command -v gh >/dev/null
command -v jq >/dev/null
command -v node >/dev/null

test -d "${source_dir}"
test ! -L "${source_dir}"
test ! -e "${output_dir}"
mkdir --mode=0700 "${output_dir}"
if find "${source_dir}" -type l -print -quit | grep -q .; then
  echo "::error::runtime evidence contains a symbolic link" >&2
  exit 1
fi
test -z "$(find "${source_dir}" -type f -size +2097152c -print -quit)"

mapfile -t actual_files < <(
  find "${source_dir}" -type f -printf '%P\n' | LC_ALL=C sort
)
case "${mode}" in
  deployment)
    expected_name="deployment-evidence-production-${release_sha}-${run_id}"
    expected_files=(deployment-evidence.json observation.json)
    evidence_file="deployment-evidence.json"
    predicate_type="https://github.com/upgradedev/archon-datahub/attestations/aws-deployment/v2"
    signer_workflow=".github/workflows/deploy.yml"
    ;;
  availability)
    expected_name="production-availability-${release_sha}-${run_id}"
    expected_files=(evidence.json observation.json)
    evidence_file="evidence.json"
    predicate_type="https://github.com/upgradedev/archon-datahub/attestations/production-availability/v2"
    signer_workflow=".github/workflows/availability.yml"
    ;;
esac

test "${artifact_name}" = "${expected_name}" || {
  echo "::error::runtime artifact name is not exact" >&2
  exit 1
}
test "${#actual_files[@]}" -eq "${#expected_files[@]}"
diff -u \
  <(printf '%s\n' "${actual_files[@]}") \
  <(printf '%s\n' "${expected_files[@]}") >/dev/null
for file in "${expected_files[@]}"; do
  test -f "${source_dir}/${file}"
  test ! -L "${source_dir}/${file}"
done

evidence="${source_dir}/${evidence_file}"
observation="${source_dir}/observation.json"
case "${mode}" in
  deployment)
    jq -cnS \
      --arg stage production \
      --arg releaseSha "${release_sha}" \
      --argjson ciRunId "$(jq -er '.ciRunId | select(type == "number" and . >= 1)' "${evidence}")" \
      --argjson deploymentRunId "${run_id}" \
      --arg webArtifactDigest "$(jq -er .promotion.webArtifactDigest "${evidence}")" \
      --arg lambdaArtifactDigest "$(jq -er .promotion.lambdaArtifactDigest "${evidence}")" \
      --arg cloudRuntimeReleaseDigest "$(jq -er .promotion.cloudRuntimeReleaseDigest "${evidence}")" \
      --arg coreCapabilityDigest "$(jq -er .promotion.coreCapabilityDigest "${evidence}")" \
      --arg coreImageManifestDigest "$(jq -er .promotion.coreImageManifestDigest "${evidence}")" \
      --arg cloudImageDigest "$(jq -er .runtime.cloudImageDigest "${observation}")" \
      '{$stage,$releaseSha,$ciRunId,$deploymentRunId,$webArtifactDigest,
        $lambdaArtifactDigest,$cloudRuntimeReleaseDigest,$coreCapabilityDigest,
        $coreImageManifestDigest,$cloudImageDigest}' \
      >"${output_dir}/expectations.json"
    node scripts/validate-lean-production-evidence.mjs pair \
      "${evidence}" "${observation}" "${output_dir}/expectations.json" \
      "${output_dir}/evidence.canonical.json" \
      "${output_dir}/observation.canonical.json"
    application_url="$(jq -er .applicationUrl "${output_dir}/evidence.canonical.json")"
    ;;
  availability)
    node scripts/validate-lean-production-evidence.mjs stable \
      "${observation}" "${output_dir}/observation.stable.json"
    jq -e --arg release "${release_sha}" '
      (keys | sort) == ([
        "checks","observedAt","profileResponseDigest","rawIdentifiersRetained",
        "releaseSha","result","schemaVersion"
      ] | sort) and
      .schemaVersion == "archon.production-availability/v2" and
      .releaseSha == $release and
      (.observedAt | fromdateiso8601) and
      .checks == {
        publicSpa:true,
        runtimeProfiles:true,
        securityHeaders:true,
        leanAwsControls:true,
        coreIdle:true
      } and
      (.profileResponseDigest | test("^sha256:[0-9a-f]{64}$")) and
      .rawIdentifiersRetained == false and
      .result == "passed"
    ' "${evidence}" >/dev/null
    test "$(jq -er .releaseSha "${observation}")" = "${release_sha}"
    jq -cS . "${evidence}" >"${output_dir}/evidence.canonical.json"
    jq -cS . "${observation}" >"${output_dir}/observation.canonical.json"
    application_url=null
    ;;
esac

raw_attestation="${output_dir}/attestation.raw.json"
gh attestation verify "${evidence}" \
  --repo "${GITHUB_REPOSITORY}" \
  --signer-workflow "github.com/${GITHUB_REPOSITORY}/${signer_workflow}" \
  --signer-digest "${release_sha}" \
  --source-digest "${release_sha}" \
  --source-ref refs/heads/master \
  --predicate-type "${predicate_type}" \
  --deny-self-hosted-runners \
  --format json >"${raw_attestation}"
subject_sha="$(sha256sum "${evidence}" | awk '{print $1}')"
canonical_predicate="$(jq -cS . "${evidence}")"
jq -ceS \
  --arg predicateType "${predicate_type}" \
  --arg subjectName "${evidence_file}" \
  --arg subjectSha "${subject_sha}" \
  --argjson expectedPredicate "${canonical_predicate}" '
    [
      .[] |
      select(
        .verificationResult.statement.predicateType == $predicateType and
        .verificationResult.statement.predicate == $expectedPredicate and
        any(.verificationResult.statement.subject[];
          .name == $subjectName and .digest.sha256 == $subjectSha)
      ) |
      {
        subject:{name:$subjectName,digest:("sha256:" + $subjectSha)},
        statement:.verificationResult.statement
      }
    ] |
    unique_by(.statement) |
    if length == 1 then .[0]
    else error("expected one exact runtime evidence attestation") end
  ' "${raw_attestation}" >"${output_dir}/verification-set.json"
rm -- "${raw_attestation}"
verification_digest="sha256:$(
  sha256sum "${output_dir}/verification-set.json" | awk '{print $1}'
)"
predicate_digest="sha256:${subject_sha}"

jq -cnS \
  --arg workflowPath "${signer_workflow}" \
  --argjson runId "${run_id}" \
  --argjson runAttempt "${run_attempt}" \
  --argjson artifactId "${artifact_id}" \
  --arg artifactName "${artifact_name}" \
  --arg artifactDigest "${artifact_digest}" \
  --arg predicateType "${predicate_type}" \
  --arg predicateDigest "${predicate_digest}" '
    {$workflowPath,$runId,$runAttempt,$artifactId,$artifactName,$artifactDigest,
     $predicateType,$predicateDigest}
  ' >"${output_dir}/binding.json"

jq -cnS \
  --arg schemaVersion archon.submission-lean-runtime-source/v2 \
  --arg mode "${mode}" \
  --arg releaseSha "${release_sha}" \
  --argjson runId "${run_id}" \
  --arg applicationUrl "${application_url}" \
  --arg verificationDigest "${verification_digest}" \
  --arg evidenceDigest "${predicate_digest}" \
  --arg observationDigest "sha256:$(sha256sum "${observation}" | awk '{print $1}')" \
  --arg cloudImageDigest "$(jq -er .runtime.cloudImageDigest "${observation}")" '
    {
      $schemaVersion,$mode,$releaseSha,$runId,
      applicationUrl:(if $applicationUrl == "null" then null else $applicationUrl end),
      topology:{
        stacks:["Archon-production-Core","Archon-production-Edge","Archon-production-Judge"],
        coreIdle:true,
        legacyAlwaysOnRuntimeAbsent:true
      },
      runtime:{
        cloudImageDigest:$cloudImageDigest,
        cloudImageDigestBound:true,
        coreMode:"ephemeral-optional-live-session"
      },
      evidence:{
        deploymentOrAvailabilityDigest:$evidenceDigest,
        observationDigest:$observationDigest,
        attestationVerificationDigest:$verificationDigest
      },
      sanitized:true,
      secretMaterialRetained:false
    }
  ' >"${output_dir}/runtime-source.json"

test "$(jq -er .schemaVersion "${output_dir}/runtime-source.json")" = \
  archon.submission-lean-runtime-source/v2
printf '%s\n' "${verification_digest}" >"${output_dir}/verification.digest"