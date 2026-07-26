#!/usr/bin/env bash
set -euo pipefail

# Verify one exact, same-repository submission-readiness source bundle.
# This script is intentionally CI-only: callers must provide a GitHub token and an
# output directory below RUNNER_TEMP. It never accepts a local archive or claims path.

required_environment=(
  GH_TOKEN
  GITHUB_REPOSITORY
  PREDICATE_DIGEST
  RELEASE_SHA
  RUNNER_TEMP
  SOURCE_ARTIFACT_DIGEST
  SOURCE_ARTIFACT_ID
  SOURCE_ARTIFACT_NAME
  SOURCE_PRODUCER_RUN_ATTEMPT
  SOURCE_RUN_ATTEMPT
  SOURCE_RUN_ID
  SOURCE_WORKFLOW_PATH
  VERIFIED_OUTPUT_DIR
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "::error::Missing required verifier environment: ${name}"
    exit 1
  fi
done

[[ "${GITHUB_REPOSITORY}" == "upgradedev/archon-datahub" ]]
[[ "${RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${SOURCE_WORKFLOW_PATH}" == ".github/workflows/submission-evidence.yml" ]]
[[ "${SOURCE_RUN_ID}" =~ ^[1-9][0-9]*$ ]]
[[ "${SOURCE_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]
[[ "${SOURCE_PRODUCER_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]
(( SOURCE_PRODUCER_RUN_ATTEMPT <= SOURCE_RUN_ATTEMPT ))
[[ "${SOURCE_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]
[[ "${SOURCE_ARTIFACT_NAME}" == \
  "submission-evidence-${RELEASE_SHA}-${SOURCE_PRODUCER_RUN_ATTEMPT}" ]]
[[ "${SOURCE_ARTIFACT_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "${PREDICATE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
case "${VERIFIED_OUTPUT_DIR}" in
  "${RUNNER_TEMP}"/*) ;;
  *)
    echo "::error::VERIFIED_OUTPUT_DIR must resolve below RUNNER_TEMP"
    exit 1
    ;;
esac
[[ "${VERIFIED_OUTPUT_DIR}" != *"/../"* ]]
test ! -e "${VERIFIED_OUTPUT_DIR}"

api() {
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "$@"
}

default_sha="$(
  api "/repos/${GITHUB_REPOSITORY}/git/ref/heads/master" --jq '.object.sha'
)"
if [[ "${default_sha}" != "${RELEASE_SHA}" ]]; then
  echo "::error::release_sha is not the current exact master commit"
  exit 1
fi

source_run_json="$(
  api "/repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}"
)"
jq -e \
  --arg path "${SOURCE_WORKFLOW_PATH}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg sha "${RELEASE_SHA}" \
  --argjson attempt "${SOURCE_RUN_ATTEMPT}" \
  --argjson runId "${SOURCE_RUN_ID}" '
    .id == $runId and
    .run_attempt == $attempt and
    .path == $path and
    .head_sha == $sha and
    .head_branch == "master" and
    .head_repository.full_name == $repository and
    .repository.full_name == $repository and
    (.event == "workflow_dispatch" or .event == "workflow_call") and
    .status == "completed" and
    .conclusion == "success"
  ' <<<"${source_run_json}" >/dev/null || {
  echo "::error::source run is not the exact successful same-repository master run"
  exit 1
}

artifact_json="$(
  api "/repos/${GITHUB_REPOSITORY}/actions/artifacts/${SOURCE_ARTIFACT_ID}"
)"
jq -e \
  --arg digest "${SOURCE_ARTIFACT_DIGEST}" \
  --arg name "${SOURCE_ARTIFACT_NAME}" \
  --arg sha "${RELEASE_SHA}" \
  --argjson artifactId "${SOURCE_ARTIFACT_ID}" \
  --argjson runId "${SOURCE_RUN_ID}" '
    .id == $artifactId and
    .name == $name and
    .digest == $digest and
    .expired == false and
    (.size_in_bytes | type) == "number" and
    .size_in_bytes > 0 and
    .size_in_bytes <= 52428800 and
    .workflow_run.id == $runId and
    .workflow_run.head_sha == $sha
  ' <<<"${artifact_json}" >/dev/null || {
  echo "::error::source artifact metadata does not match the exact binding"
  exit 1
}

work_dir="${RUNNER_TEMP}/submission-source-${SOURCE_ARTIFACT_ID}-${SOURCE_RUN_ATTEMPT}"
test ! -e "${work_dir}"
mkdir --mode=0700 "${work_dir}"
archive="${work_dir}/source.zip"
extract_dir="${work_dir}/extract"
verification_dir="${work_dir}/attestation"
mkdir --mode=0700 "${extract_dir}" "${verification_dir}"

api "/repos/${GITHUB_REPOSITORY}/actions/artifacts/${SOURCE_ARTIFACT_ID}/zip" \
  >"${archive}"
actual_archive_digest="sha256:$(sha256sum "${archive}" | awk '{print $1}')"
if [[ "${actual_archive_digest}" != "${SOURCE_ARTIFACT_DIGEST}" ]]; then
  echo "::error::downloaded artifact bytes do not match source_artifact_digest"
  exit 1
fi

# Bound canonical paths, entry types, and expanded bytes from the ZIP central
# directory before extraction. Post-extraction checks remain defense in depth.
python3 - "${archive}" <<'PY'
import posixpath
import stat
import sys
import zipfile

archive = sys.argv[1]
seen: set[str] = set()
total_size = 0
with zipfile.ZipFile(archive) as bundle:
    entries = bundle.infolist()
    if not 1 <= len(entries) <= 1024:
        raise SystemExit("artifact must contain 1..1024 entries")
    for entry in entries:
        raw = entry.filename
        if (
            not raw
            or raw.startswith("/")
            or "\\" in raw
            or "\x00" in raw
        ):
            raise SystemExit(f"unsafe ZIP path: {raw!r}")
        canonical = posixpath.normpath(raw.rstrip("/"))
        expected = canonical + "/" if entry.is_dir() else canonical
        if canonical in ("", ".", "..") or raw != expected:
            raise SystemExit(f"non-canonical ZIP path: {raw!r}")
        if canonical in seen:
            raise SystemExit(f"duplicate canonical ZIP path: {canonical!r}")
        seen.add(canonical)
        mode_type = stat.S_IFMT(entry.external_attr >> 16)
        if entry.is_dir():
            if mode_type not in (0, stat.S_IFDIR):
                raise SystemExit(f"invalid directory entry type: {raw!r}")
            continue
        if mode_type not in (0, stat.S_IFREG):
            raise SystemExit(f"non-regular ZIP entry: {raw!r}")
        if entry.flag_bits & 0x1:
            raise SystemExit(f"encrypted ZIP entry: {raw!r}")
        if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise SystemExit(f"unsupported compression: {raw!r}")
        if entry.file_size > 10 * 1024 * 1024:
            raise SystemExit(f"ZIP entry exceeds 10 MiB: {raw!r}")
        total_size += entry.file_size
        if total_size > 64 * 1024 * 1024:
            raise SystemExit("ZIP exceeds 64 MiB total extracted size")
        if (
            entry.file_size > 1024 * 1024
            and entry.file_size / max(1, entry.compress_size) > 200
        ):
            raise SystemExit(f"excessive compression ratio: {raw!r}")
PY

mapfile -t archive_entries < <(unzip -Z1 "${archive}")
test "${#archive_entries[@]}" -gt 0
test "${#archive_entries[@]}" -le 1024 || {
  echo "::error::source artifact exceeds the 1024-entry limit"
  exit 1
}
if printf '%s\n' "${archive_entries[@]}" |
  grep -E '(^/|\\|(^|/)\.\.?(/|$)|//)' >/dev/null; then
  echo "::error::source artifact contains an unsafe path"
  exit 1
fi
if unzip -Z1 "${archive}" | sort | uniq -d | grep -q .; then
  echo "::error::source artifact contains duplicate archive entries"
  exit 1
fi
unzip -q "${archive}" -d "${extract_dir}"
if find "${extract_dir}" -type l -print -quit | grep -q .; then
  echo "::error::source artifact contains a symlink"
  exit 1
fi
if find "${extract_dir}" -type f -size +10485760c -print -quit | grep -q .; then
  echo "::error::source artifact contains a file larger than 10 MiB"
  exit 1
fi
extracted_bytes="$(
  find "${extract_dir}" -type f -printf '%s\n' |
    awk '{ total += $1 } END { print total + 0 }'
)"
[[ "${extracted_bytes}" =~ ^[0-9]+$ ]]
test "${extracted_bytes}" -le 67108864 || {
  echo "::error::source artifact exceeds the 64 MiB extracted-size limit"
  exit 1
}

claims="${extract_dir}/claims.json"
predicate="${extract_dir}/predicate.json"
inventory="${extract_dir}/SHA256SUMS"
for required_file in "${claims}" "${predicate}" "${inventory}"; do
  test -f "${required_file}"
  test ! -L "${required_file}"
done

if ! awk '
  BEGIN { ok = 1 }
  !/^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._\/-]*$/ { ok = 0 }
  $2 == "SHA256SUMS" || $2 ~ /(^|\/)\.\.(\/|$)/ { ok = 0 }
  { if (seen[$2]++) ok = 0 }
  END { exit(ok ? 0 : 1) }
' "${inventory}"; then
  echo "::error::SHA256SUMS is malformed, unsafe, or contains duplicate paths"
  exit 1
fi
(
  cd "${extract_dir}"
  sha256sum --check --strict SHA256SUMS
)
find "${extract_dir}" -type f -printf '%P\n' |
  grep -v '^SHA256SUMS$' |
  LC_ALL=C sort >"${work_dir}/actual-files.txt"
awk '{print $2}' "${inventory}" |
  LC_ALL=C sort >"${work_dir}/inventoried-files.txt"
if ! diff -u "${work_dir}/actual-files.txt" "${work_dir}/inventoried-files.txt"; then
  echo "::error::SHA256SUMS must cover every source artifact file exactly once"
  exit 1
fi

jq -e \
  --arg release "${RELEASE_SHA}" \
  --arg repository "${GITHUB_REPOSITORY}" '
    (keys | sort) ==
      ["bonuses", "proofs", "releaseSha", "repository", "schemaVersion"] and
    .schemaVersion == "archon.submission-readiness-claims/v1" and
    .repository == $repository and
    .releaseSha == $release and
    (.proofs | type) == "array" and
    (.bonuses | type) == "array" and
    ([.proofs[].id, .bonuses[].id] | index("SQ11")) == null and
    all(
      .proofs[];
      (keys | sort) ==
        ["criterion", "evidence", "id", "receipt", "status"] and
      .status == "verified" and
      (.evidence | type) == "string" and
      (.evidence | length) > 0 and
      (.evidence | length) <= 2000 and
      (.receipt | keys | sort) == ["digest", "name"] and
      (.receipt.name | type) == "string" and
      (.receipt.name | test(
        "^receipts/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}\\.json$"
      )) and
      (.receipt.name | contains("..") | not) and
      (.receipt.name | contains("//") | not) and
      (.receipt.name | test("(^|/)\\.(/|$)") | not) and
      (.receipt.digest | test("^sha256:[0-9a-f]{64}$")) and
      (
        (.id == "D4" and .criterion == "use-of-datahub") or
        (.id == "U3" and .criterion == "real-world-usefulness") or
        (
          (
            .id == "SQ3" or .id == "SQ4" or .id == "SQ5" or
            .id == "SQ6" or .id == "SQ7" or .id == "SQ8" or
            .id == "SQ9" or .id == "SQ10"
          ) and
          .criterion == "submission-quality"
        )
      )
    ) and
    all(
      .bonuses[];
      (keys | sort) == ["evidence", "id", "receipt", "status"] and
      (.id == "BONUS-OSS" or .id == "BONUS-FEEDBACK") and
      .status == "verified" and
      (.evidence | type) == "string" and
      (.evidence | length) > 0 and
      (.evidence | length) <= 2000 and
      (.receipt | keys | sort) == ["digest", "name"] and
      (.receipt.name | type) == "string" and
      (.receipt.name | test(
        "^receipts/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}\\.json$"
      )) and
      (.receipt.name | contains("..") | not) and
      (.receipt.name | contains("//") | not) and
      (.receipt.name | test("(^|/)\\.(/|$)") | not) and
      (.receipt.digest | test("^sha256:[0-9a-f]{64}$"))
    ) and
    ([.proofs[].id] | length) == ([.proofs[].id] | unique | length) and
    ([.bonuses[].id] | length) == ([.bonuses[].id] | unique | length) and
    (
      [
        "D4", "U3", "SQ3", "SQ4", "SQ5", "SQ6", "SQ7", "SQ8", "SQ10"
      ] - [.proofs[].id] |
      length
    ) == 0 and
    (
      [.proofs[].receipt.name, .bonuses[].receipt.name] |
      length
    ) == (
      [.proofs[].receipt.name, .bonuses[].receipt.name] |
      unique |
      length
    )
  ' "${claims}" >/dev/null || {
  echo "::error::claims.json violates the exact readiness claims contract"
  exit 1
}

receipt_directory="${extract_dir}/receipts"
test -d "${receipt_directory}"
test ! -L "${receipt_directory}"
while IFS= read -r retained_receipt; do
  test -f "${retained_receipt}"
  test ! -L "${retained_receipt}"
  if jq -e '.id == "SQ11"' "${retained_receipt}" >/dev/null; then
    echo "::error::pre-submit readiness source must not contain an SQ11 receipt"
    exit 1
  fi
done < <(
  find "${receipt_directory}" \
    -maxdepth 1 \
    -type f \
    -name '*.json' |
    LC_ALL=C sort
)

while IFS=$'\t' read -r receipt_name receipt_digest; do
  [[ "${receipt_name}" =~ ^receipts/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}\.json$ ]]
  [[ "${receipt_name}" != *".."* ]]
  [[ "${receipt_name}" != *"//"* ]]
  [[ ! "${receipt_name}" =~ (^|/)\.(/|$) ]]
  [[ "${receipt_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
  receipt_path="${extract_dir}/${receipt_name}"
  test -f "${receipt_path}"
  test ! -L "${receipt_path}"
  actual_receipt_digest="sha256:$(sha256sum "${receipt_path}" | awk '{print $1}')"
  if [[ "${actual_receipt_digest}" != "${receipt_digest}" ]]; then
    echo "::error::receipt digest mismatch for ${receipt_name}"
    exit 1
  fi
done < <(
  jq -r '
    [.proofs[], .bonuses[]] |
    sort_by(.id)[] |
    [.receipt.name, .receipt.digest] |
    @tsv
  ' "${claims}"
)

# Re-run the proof-specific schemas and semantic contracts in the protected
# consumer. This rejects digest-correct but meaningless JSON, stale operational
# observations, wrong URLs/languages/licenses/durations, cross-proof drift, and
# any source workflow/artifact/predicate mapping outside the reviewed registry.
registry="scripts/submission-evidence-registry.json"
semantic_validator="scripts/validate-submission-proof-receipts.py"
notice="NOTICE.md"
for contract in "${registry}" "${semantic_validator}" "${notice}"; do
  test -f "${contract}"
  test ! -L "${contract}"
done
semantic_validation="${work_dir}/semantic-validation.json"
python3 "${semantic_validator}" validate-bundle \
  --registry "${registry}" \
  --receipt-dir "${extract_dir}/receipts" \
  --claims "${claims}" \
  --notice "${notice}" \
  --repository "${GITHUB_REPOSITORY}" \
  --release-sha "${RELEASE_SHA}" \
  >"${semantic_validation}"
test -f "${extract_dir}/semantic-validation.json"
test ! -L "${extract_dir}/semantic-validation.json"
cmp --silent \
  "${semantic_validation}" \
  "${extract_dir}/semantic-validation.json" || {
  echo "::error::producer semantic-validation projection is not reproducible"
  exit 1
}

# The aggregate producer is not a trust oracle for its retained gh output. Run
# fresh cryptographic verification for every exact upstream envelope/support
# subject in this protected verifier. This script runs both before approval and
# again after approval; only deterministic matching-statement projections are
# retained.
fresh_upstream_dir="${work_dir}/fresh-upstream-attestation"
mkdir --mode=0700 "${fresh_upstream_dir}"
while IFS= read -r receipt_path; do
  proof_id="$(jq -er '.id' "${receipt_path}")"
  source_json="$(
    jq -ce --arg proofId "${proof_id}" '
      [
        .sources[] |
        select(.proofIds | index($proofId))
      ] |
      if length == 1 then .[0]
      else error("proof must map to exactly one upstream source")
      end
    ' "${registry}"
  )"
  source_key="$(jq -er '.key' <<<"${source_json}")"
  source_workflow="$(jq -er '.workflowPath' <<<"${source_json}")"
  source_predicate_type="$(jq -er '.predicateType' <<<"${source_json}")"
  source_predicate_file="$(jq -er '.predicateFile' <<<"${source_json}")"
  source_subject_inventory="$(jq -er '.subjectInventory' <<<"${source_json}")"
  [[ "${source_key}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
  [[ "${source_workflow}" =~ ^\.github/workflows/[a-z0-9-]+\.yml$ ]]
  [[ "${source_predicate_file}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
  [[ "${source_subject_inventory}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
  retained_predicate="$(
    printf '%s/upstream-subjects/%s/%s' \
      "${extract_dir}" \
      "${source_key}" \
      "${source_predicate_file}"
  )"
  test -f "${retained_predicate}"
  test ! -L "${retained_predicate}"
  expected_upstream_predicate="$(jq -cS . "${retained_predicate}")"
  retained_subject_inventory="$(
    printf '%s/upstream-subjects/%s/%s' \
      "${extract_dir}" \
      "${source_key}" \
      "${source_subject_inventory}"
  )"
  test -f "${retained_subject_inventory}"
  test ! -L "${retained_subject_inventory}"
  expected_upstream_subjects="$(
    jq -Rn '
      [
        inputs |
        capture(
          "^(?<sha>[0-9a-f]{64})  (?<name>[A-Za-z0-9][A-Za-z0-9._/-]*)$"
        ) |
        {
          name: .name,
          digest: {sha256: .sha}
        }
      ] |
      sort_by(.name)
    ' <"${retained_subject_inventory}"
  )"
  receipt_predicate_type="$(
    jq -er '.source.attestation.predicateType' "${receipt_path}"
  )"
  receipt_predicate_digest="$(
    jq -er '.source.attestation.predicateDigest' "${receipt_path}"
  )"
  test "${receipt_predicate_type}" = "${source_predicate_type}"
  test "sha256:$(
    sha256sum "${retained_predicate}" | awk '{print $1}'
  )" = "${receipt_predicate_digest}"
  source_signer="github.com/${GITHUB_REPOSITORY}/${source_workflow}"
  mkdir --mode=0700 -p "${fresh_upstream_dir}/${source_key}"

  while IFS=$'\t' read -r role subject_name subject_digest; do
    [[ "${role}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
    [[ "${subject_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]
    [[ "${subject_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
    if grep -Eq '(^|/)\.\.?(/|$)|//' <<<"${subject_name}"; then
      echo "::error::Unsafe retained upstream subject name"
      exit 1
    fi
    upstream_subject="${extract_dir}/upstream-subjects/${source_key}/${subject_name}"
    test -f "${upstream_subject}"
    test ! -L "${upstream_subject}"
    actual_subject_digest="sha256:$(
      sha256sum "${upstream_subject}" | awk '{print $1}'
    )"
    test "${actual_subject_digest}" = "${subject_digest}"
    raw_verification="${work_dir}/fresh-${proof_id}-${role}.json"
    projection="${fresh_upstream_dir}/${source_key}/${proof_id}--${role}.json"
    test ! -e "${raw_verification}"
    test ! -e "${projection}"
    gh attestation verify "${upstream_subject}" \
      --repo "${GITHUB_REPOSITORY}" \
      --signer-workflow "${source_signer}" \
      --signer-digest "${RELEASE_SHA}" \
      --source-digest "${RELEASE_SHA}" \
      --source-ref refs/heads/master \
      --predicate-type "${source_predicate_type}" \
      --deny-self-hosted-runners \
      --format json >"${raw_verification}"
    jq -ceS \
      --arg predicateDigest "${receipt_predicate_digest}" \
      --arg predicateType "${source_predicate_type}" \
      --arg proofId "${proof_id}" \
      --arg releaseSha "${RELEASE_SHA}" \
      --arg repository "${GITHUB_REPOSITORY}" \
      --arg role "${role}" \
      --arg signerWorkflow "${source_signer}" \
      --arg subjectDigest "${subject_digest}" \
      --arg subjectName "${subject_name}" \
      --argjson expectedPredicate "${expected_upstream_predicate}" \
      --argjson expectedSubjects "${expected_upstream_subjects}" '
        [
          .[] |
          select(
            .verificationResult.statement.predicateType == $predicateType and
            .verificationResult.statement.predicate == $expectedPredicate and
            (
              .verificationResult.statement.subject |
              sort_by(.name)
            ) == $expectedSubjects and
            any(
              .verificationResult.statement.subject[];
              .name == $subjectName and
              .digest.sha256 ==
                ($subjectDigest | ltrimstr("sha256:"))
            )
          ) |
          {
            schemaVersion:
              "archon.fresh-upstream-attestation-verification/v1",
            repository: $repository,
            releaseSha: $releaseSha,
            proofId: $proofId,
            role: $role,
            signerWorkflow: $signerWorkflow,
            subject: {
              name: $subjectName,
              digest: $subjectDigest
            },
            predicate: {
              type: $predicateType,
              digest: $predicateDigest
            },
            statement: .verificationResult.statement
          }
        ] |
        if length == 1 then .[0]
        else error("exactly one fresh upstream statement must match")
        end
      ' "${raw_verification}" >"${projection}"
  done < <(
    jq -er '
      .source.attestation.subjects[] |
      [.role, .name, .digest] |
      @tsv
    ' "${receipt_path}"
  )
done < <(
  find "${extract_dir}/receipts" \
    -maxdepth 1 \
    -type f \
    -name '*.json' |
    LC_ALL=C sort
)
fresh_upstream_count="$(
  find "${fresh_upstream_dir}" -type f -name '*.json' |
    wc -l |
    awk '{print $1}'
)"
[[ "${fresh_upstream_count}" =~ ^[1-9][0-9]*$ ]]
fresh_upstream_set_digest="sha256:$(
  find "${fresh_upstream_dir}" -type f -name '*.json' -printf '%P\n' |
    LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' \
        "$(sha256sum "${fresh_upstream_dir}/${relative}" | awk '{print $1}')" \
        "${relative}"
    done |
    sha256sum |
    awk '{print $1}'
)"
jq -cnS \
  --arg digest "${fresh_upstream_set_digest}" \
  --arg releaseSha "${RELEASE_SHA}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --argjson subjectCount "${fresh_upstream_count}" '
    {
      schemaVersion:
        "archon.fresh-upstream-attestation-verification-set/v1",
      repository: $repository,
      releaseSha: $releaseSha,
      subjectCount: $subjectCount,
      verificationSetDigest: $digest
    }
  ' >"${fresh_upstream_dir}/binding.json"

claims_digest="sha256:$(sha256sum "${claims}" | awk '{print $1}')"
inventory_digest="sha256:$(sha256sum "${inventory}" | awk '{print $1}')"
receipt_set_digest="sha256:$(
  jq -cS '
    [.proofs[], .bonuses[]] |
    map({id, receipt}) |
    sort_by(.id)
  ' "${claims}" |
    sha256sum |
    awk '{print $1}'
)"
jq -e \
  --arg artifactName "${SOURCE_ARTIFACT_NAME}" \
  --arg claimsDigest "${claims_digest}" \
  --arg receiptSetDigest "${receipt_set_digest}" \
  --arg release "${RELEASE_SHA}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg workflowPath "${SOURCE_WORKFLOW_PATH}" \
  --argjson runAttempt "${SOURCE_PRODUCER_RUN_ATTEMPT}" \
  --argjson runId "${SOURCE_RUN_ID}" '
    (keys | sort) == [
      "artifactName",
      "claimsDigest",
      "receiptSetDigest",
      "releaseSha",
      "repository",
      "schemaVersion",
      "source"
    ] and
    .schemaVersion == "archon.submission-readiness-predicate/v1" and
    .repository == $repository and
    .releaseSha == $release and
    .source == {
      workflowPath: $workflowPath,
      runId: $runId,
      runAttempt: $runAttempt
    } and
    .artifactName == $artifactName and
    .claimsDigest == $claimsDigest and
    .receiptSetDigest == $receiptSetDigest
  ' "${predicate}" >/dev/null || {
  echo "::error::predicate.json is not bound to the exact claims/source context"
  exit 1
}
actual_predicate_digest="sha256:$(sha256sum "${predicate}" | awk '{print $1}')"
if [[ "${actual_predicate_digest}" != "${PREDICATE_DIGEST}" ]]; then
  echo "::error::predicate.json does not match predicate_digest"
  exit 1
fi

signer="github.com/${GITHUB_REPOSITORY}/${SOURCE_WORKFLOW_PATH}"
predicate_type="https://archon.datahub.dev/attestations/submission-readiness/v1"
expected_predicate="$(jq -cS . "${predicate}")"
for subject_name in claims.json SHA256SUMS; do
  subject="${extract_dir}/${subject_name}"
  verification="${verification_dir}/${subject_name}.json"
  raw_verification="${verification_dir}/${subject_name}.raw.json"
  gh attestation verify "${subject}" \
    --repo "${GITHUB_REPOSITORY}" \
    --signer-workflow "${signer}" \
    --signer-digest "${RELEASE_SHA}" \
    --source-digest "${RELEASE_SHA}" \
    --source-ref refs/heads/master \
    --predicate-type "${predicate_type}" \
    --deny-self-hosted-runners \
    --format json >"${raw_verification}"
  subject_sha="$(sha256sum "${subject}" | awk '{print $1}')"
  jq -ceS \
    --arg claimsSha "$(sha256sum "${claims}" | awk '{print $1}')" \
    --arg inventorySha "$(sha256sum "${inventory}" | awk '{print $1}')" \
    --arg predicateType "${predicate_type}" \
    --arg subjectSha "${subject_sha}" \
    --arg subjectName "${subject_name}" \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg releaseSha "${RELEASE_SHA}" \
    --arg signerWorkflow "${signer}" \
    --arg predicateDigest "${PREDICATE_DIGEST}" \
    --argjson expectedPredicate "${expected_predicate}" '
      [
        .[] |
        select(
          .verificationResult.statement.predicateType == $predicateType and
          .verificationResult.statement.predicate == $expectedPredicate and
          (
            .verificationResult.statement.subject |
            map(.digest.sha256) |
            sort
          ) == ([$claimsSha, $inventorySha] | sort) and
          any(
            .verificationResult.statement.subject[];
            .digest.sha256 == $subjectSha
          )
        ) |
        {
          schemaVersion:
            "archon.aggregate-attestation-verification/v1",
          repository: $repository,
          releaseSha: $releaseSha,
          signerWorkflow: $signerWorkflow,
          subject: {
            name: $subjectName,
            digest: ("sha256:" + $subjectSha)
          },
          predicate: {
            type: $predicateType,
            digest: $predicateDigest
          },
          statement: .verificationResult.statement
        }
      ] |
      if length == 1 then .[0]
      else error("exactly one aggregate attestation must match")
      end
    ' "${raw_verification}" >"${verification}" || {
    echo "::error::attestation does not bind ${subject_name} to predicate.json"
    exit 1
  }
done

mkdir --mode=0700 "${VERIFIED_OUTPUT_DIR}"
cp -R "${extract_dir}" "${VERIFIED_OUTPUT_DIR}/source"
mkdir --mode=0700 "${VERIFIED_OUTPUT_DIR}/verification"
cp "${verification_dir}/claims.json.json" \
  "${VERIFIED_OUTPUT_DIR}/verification/claims-attestation.json"
cp "${verification_dir}/SHA256SUMS.json" \
  "${VERIFIED_OUTPUT_DIR}/verification/inventory-attestation.json"
cp -R "${fresh_upstream_dir}" \
  "${VERIFIED_OUTPUT_DIR}/verification/upstream"

source_binding="${VERIFIED_OUTPUT_DIR}/source-binding.json"
jq -cnS \
  --arg artifactDigest "${SOURCE_ARTIFACT_DIGEST}" \
  --arg artifactName "${SOURCE_ARTIFACT_NAME}" \
  --arg claimsDigest "${claims_digest}" \
  --arg inventoryDigest "${inventory_digest}" \
  --arg predicateDigest "${PREDICATE_DIGEST}" \
  --arg predicateType "${predicate_type}" \
  --arg receiptSetDigest "${receipt_set_digest}" \
  --arg releaseSha "${RELEASE_SHA}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg workflowPath "${SOURCE_WORKFLOW_PATH}" \
  --arg claimsAttestationDigest "$(
    sha256sum "${verification_dir}/claims.json.json" | awk '{print $1}'
  )" \
  --arg inventoryAttestationDigest "$(
    sha256sum "${verification_dir}/SHA256SUMS.json" | awk '{print $1}'
  )" \
  --arg upstreamVerificationSetDigest "${fresh_upstream_set_digest}" \
  --argjson artifactId "${SOURCE_ARTIFACT_ID}" \
  --argjson attestationRunAttempt "${SOURCE_RUN_ATTEMPT}" \
  --argjson producerRunAttempt "${SOURCE_PRODUCER_RUN_ATTEMPT}" \
  --argjson runId "${SOURCE_RUN_ID}" \
  --argjson upstreamSubjectCount "${fresh_upstream_count}" '
    {
      schemaVersion: "archon.submission-readiness-source-binding/v1",
      repository: $repository,
      releaseSha: $releaseSha,
      source: {
        workflowPath: $workflowPath,
        runId: $runId,
        producerRunAttempt: $producerRunAttempt,
        attestationRunAttempt: $attestationRunAttempt
      },
      artifact: {
        name: $artifactName,
        id: $artifactId,
        digest: $artifactDigest
      },
      predicate: {
        type: $predicateType,
        digest: $predicateDigest
      },
      claimsDigest: $claimsDigest,
      inventoryDigest: $inventoryDigest,
      receiptSetDigest: $receiptSetDigest,
      verification: {
        claimsAttestationDigest:
          ("sha256:" + $claimsAttestationDigest),
        inventoryAttestationDigest:
          ("sha256:" + $inventoryAttestationDigest),
        upstreamVerificationSetDigest: $upstreamVerificationSetDigest,
        upstreamSubjectCount: $upstreamSubjectCount
      }
    }
  ' >"${source_binding}"

(
  cd "${VERIFIED_OUTPUT_DIR}"
  find . -type f -printf '%P\n' |
    LC_ALL=C sort |
    while IFS= read -r relative; do
      sha256sum "${relative}"
    done >"${work_dir}/VERIFIED-SHA256SUMS"
  mv "${work_dir}/VERIFIED-SHA256SUMS" VERIFIED-SHA256SUMS
)
