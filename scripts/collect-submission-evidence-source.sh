#!/usr/bin/env bash
set -euo pipefail

# CI-only collector for one hard-registered source. The caller supplies only an
# exact source key and run ID. Workflow path, artifact name, predicate type,
# schemas, proof IDs, and subject inventory come exclusively from the reviewed
# registry in the exact release checkout.

required_environment=(
  GH_TOKEN
  GITHUB_ACTIONS
  GITHUB_REPOSITORY
  RELEASE_SHA
  RUNNER_TEMP
  SOURCE_KEY
  SOURCE_RUN_ID
  SUBMISSION_EVIDENCE_DIR
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "::error::Missing required source collector environment: ${name}"
    exit 1
  fi
done

test "${GITHUB_ACTIONS}" = "true"
test "${GITHUB_REPOSITORY}" = "upgradedev/archon-datahub"
[[ "${RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${SOURCE_KEY}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
[[ "${SOURCE_RUN_ID}" =~ ^[1-9][0-9]*$ ]]
case "${SUBMISSION_EVIDENCE_DIR}" in
  "${RUNNER_TEMP}"/*) ;;
  *)
    echo "::error::SUBMISSION_EVIDENCE_DIR must be below RUNNER_TEMP"
    exit 1
    ;;
esac
test -d "${SUBMISSION_EVIDENCE_DIR}"
test ! -L "${SUBMISSION_EVIDENCE_DIR}"

registry="scripts/submission-evidence-registry.json"
validator="scripts/validate-submission-proof-receipts.py"
notice="NOTICE.md"
for contract in "${registry}" "${validator}" "${notice}"; do
  test -f "${contract}"
  test ! -L "${contract}"
done
python3 "${validator}" validate-registry --registry "${registry}" >/dev/null

source_json="$(
  jq -ce --arg key "${SOURCE_KEY}" '
    [
      .sources[] |
      select(.key == $key)
    ] |
    if length == 1 then .[0]
    else error("source key is not registered exactly once")
    end
  ' "${registry}"
)"
workflow_path="$(jq -er '.workflowPath' <<<"${source_json}")"
artifact_template="$(jq -er '.artifactNameTemplate' <<<"${source_json}")"
predicate_type="$(jq -er '.predicateType' <<<"${source_json}")"
predicate_file="$(jq -er '.predicateFile' <<<"${source_json}")"
subject_inventory="$(jq -er '.subjectInventory' <<<"${source_json}")"
source_mode="$(jq -er '.mode' <<<"${source_json}")"
[[ "${workflow_path}" =~ ^\.github/workflows/[a-z0-9-]+\.yml$ ]]
[[ "${predicate_file}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
[[ "${subject_inventory}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
case "${source_mode}" in
  native-live-v4|standard-v1) ;;
  *)
    echo "::error::Unregistered source mode"
    exit 1
    ;;
esac

api() {
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "$@"
}

default_sha="$(
  api "/repos/${GITHUB_REPOSITORY}/git/ref/heads/master" --jq '.object.sha'
)"
test "${default_sha}" = "${RELEASE_SHA}" || {
  echo "::error::submission evidence can only target the current exact master"
  exit 1
}

run_json="$(api "/repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}")"
jq -e \
  --arg path "${workflow_path}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg release "${RELEASE_SHA}" \
  --argjson runId "${SOURCE_RUN_ID}" '
    .id == $runId and
    .path == $path and
    .head_sha == $release and
    .head_branch == "master" and
    .head_repository.full_name == $repository and
    .repository.full_name == $repository and
    (.event == "workflow_dispatch" or .event == "workflow_call") and
    (.run_attempt | type) == "number" and
    .run_attempt > 0 and
    .status == "completed" and
    .conclusion == "success"
  ' <<<"${run_json}" >/dev/null || {
  echo "::error::${SOURCE_KEY} is not the exact successful same-repository release run"
  exit 1
}
run_attempt="$(jq -er '.run_attempt' <<<"${run_json}")"
artifact_name="${artifact_template//\{releaseSha\}/${RELEASE_SHA}}"
artifact_name="${artifact_name//\{runAttempt\}/${run_attempt}}"
[[ "${artifact_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$ ]]

artifacts_json="$(
  api \
    "/repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}/artifacts?per_page=100&name=${artifact_name}"
)"
artifact_json="$(
  jq -ce \
    --arg name "${artifact_name}" \
    --arg release "${RELEASE_SHA}" \
    --argjson runId "${SOURCE_RUN_ID}" '
      [
        .artifacts[] |
        select(
          .name == $name and
          .expired == false and
          .workflow_run.id == $runId and
          .workflow_run.head_sha == $release and
          (.id | type) == "number" and
          .id > 0 and
          (.digest | test("^sha256:[0-9a-f]{64}$")) and
          (.size_in_bytes | type) == "number" and
          .size_in_bytes > 0 and
          .size_in_bytes <= 52428800
        )
      ] |
      if length == 1 then .[0]
      else error("exactly one unexpired registered artifact is required")
      end
    ' <<<"${artifacts_json}"
)"
artifact_id="$(jq -er '.id' <<<"${artifact_json}")"
artifact_digest="$(jq -er '.digest' <<<"${artifact_json}")"

work_dir="${RUNNER_TEMP}/submission-upstream-${SOURCE_KEY}-${SOURCE_RUN_ID}-${run_attempt}"
test ! -e "${work_dir}"
mkdir --mode=0700 "${work_dir}"
archive="${work_dir}/source.zip"
source_dir="${work_dir}/source"
attestation_dir="${work_dir}/attestation"
mkdir --mode=0700 "${source_dir}" "${attestation_dir}"
api "/repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip" \
  >"${archive}"
actual_artifact_digest="sha256:$(sha256sum "${archive}" | awk '{print $1}')"
test "${actual_artifact_digest}" = "${artifact_digest}" || {
  echo "::error::${SOURCE_KEY} downloaded bytes differ from GitHub artifact metadata"
  exit 1
}

# Validate central-directory metadata before unzip can allocate extracted bytes.
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
    if not 1 <= len(entries) <= 512:
        raise SystemExit("artifact must contain 1..512 entries")
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
test "${#archive_entries[@]}" -le 512
if printf '%s\n' "${archive_entries[@]}" |
  grep -E '(^/|\\|(^|/)\.\.?(/|$)|//)' >/dev/null; then
  echo "::error::${SOURCE_KEY} contains an unsafe archive path"
  exit 1
fi
test "$(
  printf '%s\n' "${archive_entries[@]}" |
    LC_ALL=C sort |
    uniq -d |
    wc -l
)" = "0" || {
  echo "::error::${SOURCE_KEY} contains duplicate archive entries"
  exit 1
}
unzip -q "${archive}" -d "${source_dir}"
test -z "$(find "${source_dir}" -type l -print -quit)"
test -z "$(find "${source_dir}" -type f -size +10485760c -print -quit)"
extracted_bytes="$(
  find "${source_dir}" -type f -printf '%s\n' |
    awk '{ total += $1 } END { print total + 0 }'
)"
[[ "${extracted_bytes}" =~ ^[0-9]+$ ]]
test "${extracted_bytes}" -le 67108864 || {
  echo "::error::${SOURCE_KEY} exceeds the 64 MiB extracted-size limit"
  exit 1
}
test -f "${source_dir}/${predicate_file}"
test ! -L "${source_dir}/${predicate_file}"
test -f "${source_dir}/${subject_inventory}"
test ! -L "${source_dir}/${subject_inventory}"

if ! awk '
  BEGIN { ok = 1 }
  !/^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._\/-]*$/ { ok = 0 }
  $2 ~ /(^|\/)\.\.(\/|$)/ || $2 ~ /\/\// { ok = 0 }
  { if (seen[$2]++) ok = 0 }
  END { exit(ok ? 0 : 1) }
' "${source_dir}/${subject_inventory}"; then
  echo "::error::${SOURCE_KEY} subject inventory is malformed or unsafe"
  exit 1
fi
(
  cd "${source_dir}"
  sha256sum --check --strict "${subject_inventory}"
)

find "${source_dir}" -type f -printf '%P\n' |
  LC_ALL=C sort >"${work_dir}/actual-files.txt"
awk '{print $2}' "${source_dir}/${subject_inventory}" |
  LC_ALL=C sort >"${work_dir}/subject-files.txt"
if test "${source_mode}" = "native-live-v4"; then
  {
    cat "${work_dir}/subject-files.txt"
    printf '%s\n' "${predicate_file}" "${subject_inventory}"
  } |
    LC_ALL=C sort >"${work_dir}/expected-files.txt"
else
  {
    cat "${work_dir}/subject-files.txt"
    printf '%s\n' "${subject_inventory}"
  } |
    LC_ALL=C sort >"${work_dir}/expected-files.txt"
fi
if ! diff -u "${work_dir}/expected-files.txt" "${work_dir}/actual-files.txt"; then
  echo "::error::${SOURCE_KEY} inventory must cover the exact artifact file set"
  exit 1
fi

predicate_digest="$(
  printf 'sha256:%s' "$(
    sha256sum "${source_dir}/${predicate_file}" | awk '{print $1}'
  )"
)"
expected_predicate="$(jq -cS . "${source_dir}/${predicate_file}")"
signer="github.com/${GITHUB_REPOSITORY}/${workflow_path}"
mapfile -t proof_ids < <(jq -er '.proofIds[]' <<<"${source_json}")
test "${#proof_ids[@]}" -gt 0
verification_output="${SUBMISSION_EVIDENCE_DIR}/upstream-verification/${SOURCE_KEY}"
subject_output="${SUBMISSION_EVIDENCE_DIR}/upstream-subjects/${SOURCE_KEY}"
test ! -e "${verification_output}"
test ! -e "${subject_output}"
mkdir --mode=0700 -p "${verification_output}" "${subject_output}"
while read -r expected_sha inventoried_name; do
  [[ "${expected_sha}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${inventoried_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]
  retained_inventoried="${subject_output}/${inventoried_name}"
  mkdir --mode=0700 -p "$(dirname "${retained_inventoried}")"
  cp "${source_dir}/${inventoried_name}" "${retained_inventoried}"
  test "$(sha256sum "${retained_inventoried}" | awk '{print $1}')" = \
    "${expected_sha}"
done <"${source_dir}/${subject_inventory}"
cp "${source_dir}/${subject_inventory}" \
  "${subject_output}/${subject_inventory}"
retained_predicate="${subject_output}/${predicate_file}"
if test -e "${retained_predicate}"; then
  cmp --silent "${source_dir}/${predicate_file}" "${retained_predicate}"
else
  cp "${source_dir}/${predicate_file}" "${retained_predicate}"
fi
expected_attested_subjects="$(
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
  ' <"${source_dir}/${subject_inventory}"
)"
subject_set_digest="sha256:$(
  LC_ALL=C sort -k2,2 "${source_dir}/${subject_inventory}" |
    sha256sum |
    awk '{print $1}'
)"

subject_rows="${work_dir}/registered-subjects.tsv"
if test "${source_mode}" = "standard-v1"; then
  jq -er '
    .proofIds[] as $proofId |
    ([$proofId, "proof-envelope", ("proofs/" + $proofId + ".json")] | @tsv),
    (
      .supportSubjects[$proofId][] |
      [$proofId, .role, .name] |
      @tsv
    )
  ' <<<"${source_json}" >"${subject_rows}"
else
  jq -er '
    .proofIds[] as $proofId |
    .supportSubjects[$proofId][] |
    [$proofId, .role, .name] |
    @tsv
  ' <<<"${source_json}" >"${subject_rows}"
fi
test -s "${subject_rows}"
test "$(
  cut -f1,2 "${subject_rows}" |
    LC_ALL=C sort |
    uniq -d |
    wc -l
)" = "0"

while IFS=$'\t' read -r proof_id role subject_name; do
  [[ "${proof_id}" =~ ^[A-Z0-9]+(-[A-Z0-9]+)*$ ]]
  [[ "${role}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
  [[ "${subject_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]
  if grep -Eq '(^|/)\.\.?(/|$)|//' <<<"${subject_name}"; then
    echo "::error::Unsafe registered subject name"
    exit 1
  fi
  subject="${source_dir}/${subject_name}"
  test -f "${subject}"
  test ! -L "${subject}"
  retained_subject="${subject_output}/${subject_name}"
  mkdir --mode=0700 -p "$(dirname "${retained_subject}")"
  if test -e "${retained_subject}"; then
    cmp --silent "${subject}" "${retained_subject}"
  else
    cp "${subject}" "${retained_subject}"
  fi
  verification="${attestation_dir}/${proof_id}--${role}.json"
  raw_verification="${attestation_dir}/${proof_id}--${role}.raw.json"
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
    --arg predicateDigest "${predicate_digest}" \
    --arg predicateType "${predicate_type}" \
    --arg proofId "${proof_id}" \
    --arg releaseSha "${RELEASE_SHA}" \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg role "${role}" \
    --arg subjectName "${subject_name}" \
    --arg subjectSha "${subject_sha}" \
    --argjson expectedPredicate "${expected_predicate}" \
    --argjson expectedSubjects "${expected_attested_subjects}" '
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
            .digest.sha256 == $subjectSha
          )
        ) |
        {
          schemaVersion:
            "archon.upstream-attestation-verification/v1",
          repository: $repository,
          releaseSha: $releaseSha,
          proofId: $proofId,
          role: $role,
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
      else error("exactly one upstream attestation must match")
      end
  ' "${raw_verification}" >"${verification}" || {
    echo "::error::${SOURCE_KEY}/${proof_id}/${role} lacks one exact matching attestation"
    exit 1
  }
  cp "${verification}" \
    "${verification_output}/${proof_id}--${role}.json"
done <"${subject_rows}"

verification_set_digest="sha256:$(
  find "${verification_output}" \
    -maxdepth 1 \
    -type f \
    -name '*--*.json' \
    -printf '%f\n' |
    LC_ALL=C sort |
    while IFS= read -r name; do
      printf '%s  %s\n' \
        "$(sha256sum "${verification_output}/${name}" | awk '{print $1}')" \
        "${name}"
    done |
    sha256sum |
    awk '{print $1}'
)"
receipt_dir="${SUBMISSION_EVIDENCE_DIR}/receipts"
mkdir --mode=0700 -p "${receipt_dir}"
python3 "${validator}" derive \
  --registry "${registry}" \
  --source-key "${SOURCE_KEY}" \
  --source-dir "${source_dir}" \
  --receipt-dir "${receipt_dir}" \
  --repository "${GITHUB_REPOSITORY}" \
  --release-sha "${RELEASE_SHA}" \
  --run-id "${SOURCE_RUN_ID}" \
  --run-attempt "${run_attempt}" \
  --artifact-id "${artifact_id}" \
  --artifact-name "${artifact_name}" \
  --artifact-digest "${artifact_digest}" \
  --predicate-digest "${predicate_digest}" \
  --subject-set-digest "${subject_set_digest}" \
  --verification-set-digest "${verification_set_digest}" \
  --notice "${notice}"

jq -cnS \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg releaseSha "${RELEASE_SHA}" \
  --arg key "${SOURCE_KEY}" \
  --arg workflowPath "${workflow_path}" \
  --arg artifactName "${artifact_name}" \
  --arg artifactDigest "${artifact_digest}" \
  --arg predicateType "${predicate_type}" \
  --arg predicateDigest "${predicate_digest}" \
  --arg verificationSetDigest "${verification_set_digest}" \
  --arg subjectSetDigest "${subject_set_digest}" \
  --argjson runId "${SOURCE_RUN_ID}" \
  --argjson runAttempt "${run_attempt}" \
  --argjson artifactId "${artifact_id}" \
  --argjson proofIds "$(printf '%s\n' "${proof_ids[@]}" | jq -Rsc 'split("\n")[:-1]')" '
    {
      schemaVersion: "archon.submission-upstream-binding/v1",
      repository: $repository,
      releaseSha: $releaseSha,
      sourceKey: $key,
      source: {
        workflowPath: $workflowPath,
        runId: $runId,
        runAttempt: $runAttempt
      },
      artifact: {
        id: $artifactId,
        name: $artifactName,
        digest: $artifactDigest
      },
      attestation: {
        predicateType: $predicateType,
        predicateDigest: $predicateDigest,
        verificationSetDigest: $verificationSetDigest,
        subjectSetDigest: $subjectSetDigest
      },
      proofIds: $proofIds
    }
  ' >"${verification_output}/binding.json"
