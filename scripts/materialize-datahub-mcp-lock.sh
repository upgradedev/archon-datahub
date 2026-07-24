#!/usr/bin/env bash
set -euo pipefail

# Materialize only the immutable, upstream-authored v0.6.0 project and lock selected by
# the repository-owned lock contract. Both CI and the credentialed live proof use this
# path; neither is allowed to resolve a floating `uvx` dependency graph.

readonly contract="${ARCHON_DATAHUB_MCP_LOCK_CONTRACT:-.github/locks/datahub-mcp-v0.6.0.json}"
readonly destination="${1:-}"

if [[ -z "${destination}" || "${destination}" != /* ]]; then
  echo "usage: $0 ABSOLUTE_DESTINATION" >&2
  exit 64
fi

jq --exit-status '
  .schemaVersion == "archon.datahub-mcp-lock/v1" and
  .package.name == "mcp-server-datahub" and
  .package.version == "0.6.0" and
  .package.wheel.filename ==
    "mcp_server_datahub-0.6.0-py3-none-any.whl" and
  .package.wheel.url ==
    "https://files.pythonhosted.org/packages/fb/5a/5573927ea69ff2a93b1957d6f128b9aacbee50df0b35e6410678d3b62d0b/mcp_server_datahub-0.6.0-py3-none-any.whl" and
  .package.wheel.sha256 ==
    "2679dcfafc0ae12724efbf0fc6a73014f9085a4e1303cba9b1e41776dab8f001" and
  .package.wheel.size == 119016 and
  .package.pypiProvenance.url ==
    "https://pypi.org/integrity/mcp-server-datahub/0.6.0/mcp_server_datahub-0.6.0-py3-none-any.whl/provenance" and
  .package.pypiProvenance.publisher == {
    environment: "pypi",
    kind: "GitHub",
    repository: "acryldata/mcp-server-datahub",
    workflow: "wheels.yml"
  } and
  ([.package.pypiProvenance.statementSha256,
    .package.pypiProvenance.signatureSha256,
    .package.pypiProvenance.certificateSha256] |
    all(test("^[0-9a-f]{64}$"))) and
  .package.pypiProvenance.rekorLogIndex == "1568734253" and
  .package.pypiProvenance.integratedTime == "1779123580" and
  .runtime.pythonVersion == "3.11.15" and
  .runtime.uvVersion == "0.11.31" and
  .source.repository ==
    "https://github.com/acryldata/mcp-server-datahub.git" and
  .source.commit == "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9" and
  .source.tree == "37f04067731b7340020e711fb6075dfd8a1a0cfd" and
  .source.tag == "v0.6.0" and
  .source.githubCommitSignatureVerified == true and
  ([.source.commit, .source.tree, .files[].gitBlob] |
    all(test("^[0-9a-f]{40}$"))) and
  ([.package.wheel.sha256, .files[].sha256] |
    all(test("^[0-9a-f]{64}$"))) and
  ([.files[].size] | all(type == "number" and . > 0))
' "${contract}" >/dev/null

readonly repository="$(jq -er '.source.repository' "${contract}")"
readonly commit="$(jq -er '.source.commit' "${contract}")"
readonly tree="$(jq -er '.source.tree' "${contract}")"

if [[ -e "${destination}" ]]; then
  echo "destination already exists: ${destination}" >&2
  exit 65
fi

mkdir -p "${destination}"
git -C "${destination}" init --quiet
git -C "${destination}" remote add origin "${repository}"
git -C "${destination}" \
  -c protocol.file.allow=never \
  fetch --quiet --no-tags --depth=1 origin "${commit}"
git -C "${destination}" checkout --quiet --detach FETCH_HEAD

test "$(git -C "${destination}" rev-parse HEAD)" = "${commit}"
test "$(git -C "${destination}" rev-parse 'HEAD^{tree}')" = "${tree}"
test -z "$(git -C "${destination}" submodule status)"

for path in pyproject.toml uv.lock; do
  expected_blob="$(jq -er --arg path "${path}" \
    '.files[$path].gitBlob' "${contract}")"
  expected_sha="$(jq -er --arg path "${path}" \
    '.files[$path].sha256' "${contract}")"
  expected_size="$(jq -er --arg path "${path}" \
    '.files[$path].size' "${contract}")"
  materialized="${destination}/${path}"

  test -f "${materialized}"
  test ! -L "${materialized}"
  test "$(git -C "${destination}" rev-parse "HEAD:${path}")" = \
    "${expected_blob}"
  test "$(sha256sum "${materialized}" | awk '{print $1}')" = \
    "${expected_sha}"
  test "$(stat --format='%s' "${materialized}")" = "${expected_size}"
done

test "$(uv --version | awk '{print $2}')" = \
  "$(jq -er '.runtime.uvVersion' "${contract}")"
uv lock --project "${destination}" --check

# PyPI's trusted-publisher provenance binds the exact wheel digest to the official
# acryldata GitHub release workflow. Pin the DSSE statement, signature, Fulcio
# certificate, and Rekor entry as well as validating the semantic subject/publisher.
readonly provenance_url="$(
  jq -er '.package.pypiProvenance.url' "${contract}"
)"
readonly provenance_dir="${destination}/.archon-evidence"
readonly provenance="${provenance_dir}/pypi-provenance.json"
mkdir -p "${provenance_dir}"
curl --fail --silent --show-error --location \
  -H 'Accept: application/vnd.pypi.integrity.v1+json' \
  --output "${provenance}" \
  "${provenance_url}"
test -f "${provenance}"
test ! -L "${provenance}"
jq --exit-status \
  --arg wheel "$(jq -er '.package.wheel.filename' "${contract}")" \
  --arg wheelSha "$(jq -er '.package.wheel.sha256' "${contract}")" \
  --arg rekorLogIndex "$(
    jq -er '.package.pypiProvenance.rekorLogIndex' "${contract}"
  )" \
  --arg integratedTime "$(
    jq -er '.package.pypiProvenance.integratedTime' "${contract}"
  )" '
    .version == 1 and
    (.attestation_bundles | length) == 1 and
    .attestation_bundles[0].publisher == {
      environment: "pypi",
      kind: "GitHub",
      repository: "acryldata/mcp-server-datahub",
      workflow: "wheels.yml"
    } and
    (.attestation_bundles[0].attestations | length) == 1 and
    (
      .attestation_bundles[0].attestations[0]
        .verification_material.transparency_entries |
      length
    ) == 1 and
    (
      .attestation_bundles[0].attestations[0]
        .verification_material.transparency_entries[0].logIndex |
      tostring
    ) == $rekorLogIndex and
    (
      .attestation_bundles[0].attestations[0]
        .verification_material.transparency_entries[0].integratedTime |
      tostring
    ) == $integratedTime and
    (
      .attestation_bundles[0].attestations[0].envelope.statement |
      @base64d |
      fromjson
    ) == {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{
        name: $wheel,
        digest: {sha256: $wheelSha}
      }],
      predicateType: "https://docs.pypi.org/attestations/publish/v1",
      predicate: null
    }
  ' "${provenance}" >/dev/null
test "$(
  jq -er '.attestation_bundles[0].attestations[0].envelope.statement' \
    "${provenance}" |
    base64 --decode |
    sha256sum |
    awk '{print $1}'
)" = "$(jq -er '.package.pypiProvenance.statementSha256' "${contract}")"
test "$(
  jq -er '.attestation_bundles[0].attestations[0].envelope.signature' \
    "${provenance}" |
    base64 --decode |
    sha256sum |
    awk '{print $1}'
)" = "$(jq -er '.package.pypiProvenance.signatureSha256' "${contract}")"
test "$(
  jq -er '
    .attestation_bundles[0].attestations[0]
      .verification_material.certificate
  ' "${provenance}" |
    base64 --decode |
    sha256sum |
    awk '{print $1}'
)" = "$(jq -er '.package.pypiProvenance.certificateSha256' "${contract}")"

# Do not build the upstream project: its open-ended PEP 517 requirements would create a
# second, floating build graph. Sync only uv.lock's transitive closure, then install the
# official PyPI wheel by the committed SHA-256 with resolution and builds disabled.
readonly python_version="$(jq -er '.runtime.pythonVersion' "${contract}")"
readonly package_name="$(jq -er '.package.name' "${contract}")"
readonly package_version="$(jq -er '.package.version' "${contract}")"
readonly wheel_url="$(jq -er '.package.wheel.url' "${contract}")"
readonly wheel_sha="$(jq -er '.package.wheel.sha256' "${contract}")"
readonly wheel_requirement="$(mktemp)"
trap 'rm -f "${wheel_requirement}"' EXIT

uv sync \
  --project "${destination}" \
  --locked \
  --no-dev \
  --no-install-project \
  --no-build \
  --python "${python_version}"
printf '%s @ %s --hash=sha256:%s\n' \
  "${package_name}" \
  "${wheel_url}" \
  "${wheel_sha}" >"${wheel_requirement}"
uv pip install \
  --python "${destination}/.venv/bin/python" \
  --no-deps \
  --no-build \
  --require-hashes \
  --requirement "${wheel_requirement}"
test -x "${destination}/.venv/bin/mcp-server-datahub"
test "$(
  uv pip show \
    --python "${destination}/.venv/bin/python" \
    "${package_name}" |
    awk '$1 == "Version:" {print $2}'
)" = "${package_version}"
