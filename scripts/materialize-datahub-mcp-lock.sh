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
  .schemaVersion == "archon.datahub-mcp-lock/v2" and
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
  .sourceBuildPolicy.allowed == [{
    name: "pyperclip",
    version: "1.9.0",
    registry: "https://pypi.org/simple",
    sdist: {
      filename: "pyperclip-1.9.0.tar.gz",
      url:
        "https://files.pythonhosted.org/packages/30/23/2f0a3efc4d6a32f3b63cdff36cd398d9701d26cda58e3ab97ac79fb5e60d/pyperclip-1.9.0.tar.gz",
      sha256:
        "b7de0142ddc81bfc5c7507eea19da920b92252b548b96186caf94a5e2527d310",
      size: 20961
    }
  }] and
  .sourceBuildPolicy.buildBackend == {
    name: "setuptools",
    version: "83.0.0",
    wheel: {
      filename: "setuptools-83.0.0-py3-none-any.whl",
      url:
        "https://files.pythonhosted.org/packages/5d/40/e1e72872c6354b306daef1703549e8e83b4d43cfea356311bf722a043752/setuptools-83.0.0-py3-none-any.whl",
      sha256:
        "29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3",
      size: 1008090
    }
  } and
  .source.repository ==
    "https://github.com/acryldata/mcp-server-datahub.git" and
  .source.commit == "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9" and
  .source.tree == "37f04067731b7340020e711fb6075dfd8a1a0cfd" and
  .source.tag == "v0.6.0" and
  .source.githubCommitSignatureVerified == true and
  ([.source.commit, .source.tree, .files[].gitBlob] |
    all(test("^[0-9a-f]{40}$"))) and
  ([
    .package.wheel.sha256,
    .sourceBuildPolicy.allowed[].sdist.sha256,
    .sourceBuildPolicy.buildBackend.wheel.sha256,
    .files[].sha256
  ] |
    all(test("^[0-9a-f]{64}$"))) and
  ([
    .package.wheel.size,
    .sourceBuildPolicy.allowed[].sdist.size,
    .sourceBuildPolicy.buildBackend.wheel.size,
    .files[].size
  ] | all(type == "number" and . > 0))
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

# Fail closed if the committed upstream lock introduces another source-only
# dependency. Every package that publishes wheels is passed to --no-build-package;
# the sole exception must match the repository-owned name, version, registry, URL,
# digest, and size contract exactly.
readonly provenance_dir="${destination}/.archon-evidence"
readonly no_build_packages="${provenance_dir}/no-build-packages.txt"
mkdir -p "${provenance_dir}"
python3 - "${destination}/uv.lock" "${contract}" \
  >"${no_build_packages}" <<'PY'
import json
import sys
import tomllib

lock_path, contract_path = sys.argv[1:]
with open(lock_path, "rb") as handle:
    lock = tomllib.load(handle)
with open(contract_path, encoding="utf-8") as handle:
    contract = json.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


project_name = contract["package"]["name"]
allowed = contract["sourceBuildPolicy"]["allowed"]
require(len(allowed) == 1, "exactly one source-build exception is required")
observed = []
no_build = set()

for package in lock["package"]:
    name = package["name"]
    source = package.get("source", {})
    if "editable" in source:
        require(name == project_name, f"unexpected editable package: {name}")
        require(
            source == {"editable": "."},
            f"unexpected editable source for {name}",
        )
        continue
    if package.get("wheels"):
        no_build.add(name)
        continue
    observed.append(
        {
            "name": name,
            "version": package["version"],
            "registry": source["registry"],
            "sdist": {
                "filename": package["sdist"]["url"].rsplit("/", 1)[-1],
                "url": package["sdist"]["url"],
                "sha256": package["sdist"]["hash"].removeprefix("sha256:"),
                "size": package["sdist"]["size"],
            },
        }
    )

require(
    observed == allowed,
    "wheel-less dependency set does not match the committed exception",
)
for name in sorted(no_build):
    print(name)
PY
test -s "${no_build_packages}"
test ! -L "${no_build_packages}"

# Inspect and retain the one allowed sdist before its setup.py is executed. The
# upstream archive is hash/size-bound and must be a simple legacy-setuptools tree;
# no package-controlled PEP 517 graph is accepted.
readonly allowed_sdist="${provenance_dir}/pyperclip-1.9.0.tar.gz"
readonly allowed_sdist_url="$(
  jq -er '.sourceBuildPolicy.allowed[0].sdist.url' "${contract}"
)"
curl --fail --silent --show-error --location \
  --output "${allowed_sdist}" \
  "${allowed_sdist_url}"
test -f "${allowed_sdist}"
test ! -L "${allowed_sdist}"
test "$(sha256sum "${allowed_sdist}" | awk '{print $1}')" = \
  "$(jq -er '.sourceBuildPolicy.allowed[0].sdist.sha256' "${contract}")"
test "$(stat --format='%s' "${allowed_sdist}")" = \
  "$(jq -er '.sourceBuildPolicy.allowed[0].sdist.size' "${contract}")"
tar -tzf "${allowed_sdist}" |
  awk '
    !/^pyperclip-1[.]9[.]0\/[^\\]*$/ { exit 1 }
    /(^|\/)[.][.]?(\/|$)/ { exit 1 }
    /\/setup[.]py$/ { setup_py += 1 }
    /\/pyproject[.]toml$/ { pyproject += 1 }
    END { exit !(setup_py == 1 && pyproject == 0) }
  '

# Pin the legacy setuptools build environment to one non-vulnerable wheel. uv
# verifies the supplied hash and applies this constraint only to isolated build
# dependencies; no floating setuptools resolution is permitted.
readonly build_constraints="${provenance_dir}/build-constraints.txt"
readonly backend_name="$(
  jq -er '.sourceBuildPolicy.buildBackend.name' "${contract}"
)"
readonly backend_version="$(
  jq -er '.sourceBuildPolicy.buildBackend.version' "${contract}"
)"
readonly backend_url="$(
  jq -er '.sourceBuildPolicy.buildBackend.wheel.url' "${contract}"
)"
readonly backend_sha="$(
  jq -er '.sourceBuildPolicy.buildBackend.wheel.sha256' "${contract}"
)"
readonly backend_filename="$(
  jq -er '.sourceBuildPolicy.buildBackend.wheel.filename' "${contract}"
)"
readonly backend_wheel="${provenance_dir}/${backend_filename}"
curl --fail --silent --show-error --location \
  --output "${backend_wheel}" \
  "${backend_url}"
test -f "${backend_wheel}"
test ! -L "${backend_wheel}"
test "$(sha256sum "${backend_wheel}" | awk '{print $1}')" = "${backend_sha}"
test "$(stat --format='%s' "${backend_wheel}")" = \
  "$(jq -er '.sourceBuildPolicy.buildBackend.wheel.size' "${contract}")"
printf '%s==%s --hash=sha256:%s\n' \
  "${backend_name}" \
  "${backend_version}" \
  "${backend_sha}" >"${build_constraints}"
test -s "${build_constraints}"
test ! -L "${build_constraints}"

# uv 0.11.31 supports project build constraints but not the later
# `uv sync --build-constraint` CLI spelling. Add a CI-local, digest-recorded
# overlay to the already hash-verified upstream pyproject. The direct PyPI wheel
# URL carries the committed SHA-256, so the isolated legacy build cannot resolve
# a floating setuptools distribution.
readonly upstream_pyproject="${destination}/pyproject.toml"
readonly upstream_pyproject_sha="$(
  jq -er '.files["pyproject.toml"].sha256' "${contract}"
)"
readonly pristine_upstream_pyproject="${provenance_dir}/upstream-pyproject.toml"
cp -- "${upstream_pyproject}" "${pristine_upstream_pyproject}"
test -f "${pristine_upstream_pyproject}"
test ! -L "${pristine_upstream_pyproject}"
test "$(sha256sum "${pristine_upstream_pyproject}" | awk '{print $1}')" = \
  "${upstream_pyproject_sha}"
readonly build_constraint_requirement="$(
  printf '%s @ %s#sha256=%s' \
    "${backend_name}" \
    "${backend_url}" \
    "${backend_sha}"
)"
readonly build_constraint_overlay="${provenance_dir}/build-constraint-overlay.json"
python3 - \
  "${upstream_pyproject}" \
  "${build_constraint_requirement}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
requirement = sys.argv[2]
if not path.is_file() or path.is_symlink():
    raise SystemExit("upstream pyproject must be one regular file")
text = path.read_text(encoding="utf-8")
marker = "[tool.uv]\n"
if text.count(marker) != 1:
    raise SystemExit("upstream pyproject must contain one [tool.uv] table")
if "build-constraint-dependencies" in text:
    raise SystemExit("upstream pyproject already defines build constraints")
entry = f"build-constraint-dependencies = [{json.dumps(requirement)}]\n"
path.write_text(text.replace(marker, marker + entry, 1), encoding="utf-8")
PY
test -f "${upstream_pyproject}"
test ! -L "${upstream_pyproject}"
readonly overlaid_pyproject_sha="$(
  sha256sum "${upstream_pyproject}" | awk '{print $1}'
)"
test "${overlaid_pyproject_sha}" != "${upstream_pyproject_sha}"
jq -cnS \
  --arg upstreamPyprojectSha256 "${upstream_pyproject_sha}" \
  --arg overlaidPyprojectSha256 "${overlaid_pyproject_sha}" \
  --arg requirement "${build_constraint_requirement}" '
    {
      schemaVersion: "archon.datahub-mcp-build-constraint-overlay/v1",
      upstreamPyprojectSha256: $upstreamPyprojectSha256,
      overlaidPyprojectSha256: $overlaidPyprojectSha256,
      requirement: $requirement
    }
  ' >"${build_constraint_overlay}"
test -s "${build_constraint_overlay}"
test ! -L "${build_constraint_overlay}"

# PyPI's trusted-publisher provenance binds the exact wheel digest to the official
# acryldata GitHub release workflow. Pin the DSSE statement, signature, Fulcio
# certificate, and Rekor entry as well as validating the semantic subject/publisher.
readonly provenance_url="$(
  jq -er '.package.pypiProvenance.url' "${contract}"
)"
readonly provenance="${provenance_dir}/pypi-provenance.json"
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

# Do not build the upstream project. Sync only uv.lock's transitive closure, allow the
# one contract-bound legacy sdist with its hash-pinned backend, and prohibit source
# builds for every other locked dependency. Then install the official MCP PyPI wheel
# by the committed SHA-256 with resolution and builds disabled.
readonly python_version="$(jq -er '.runtime.pythonVersion' "${contract}")"
readonly package_name="$(jq -er '.package.name' "${contract}")"
readonly package_version="$(jq -er '.package.version' "${contract}")"
readonly wheel_url="$(jq -er '.package.wheel.url' "${contract}")"
readonly wheel_sha="$(jq -er '.package.wheel.sha256' "${contract}")"
readonly wheel_requirement="$(mktemp)"
trap 'rm -f "${wheel_requirement}"' EXIT

no_build_args=()
while IFS= read -r dependency; do
  test -n "${dependency}"
  no_build_args+=(--no-build-package "${dependency}")
done <"${no_build_packages}"
test "${#no_build_args[@]}" -gt 20

# The pristine lock was checked before the build-only overlay was added. Frozen
# mode consumes that exact lock without attempting to rewrite it, while still
# applying the workspace-root build constraint to the one allowed sdist.
uv sync \
  --project "${destination}" \
  --frozen \
  --no-dev \
  --no-install-project \
  --no-cache \
  "${no_build_args[@]}" \
  --python "${python_version}"

# Restore the byte-identical upstream project metadata immediately after the
# isolated build. All downstream audit/export commands therefore run with the
# original, lock-current project while the overlay remains in retained evidence.
readonly restored_upstream_pyproject="${destination}/.pyproject.toml.restore"
cp -- "${pristine_upstream_pyproject}" "${restored_upstream_pyproject}"
test -f "${restored_upstream_pyproject}"
test ! -L "${restored_upstream_pyproject}"
test "$(sha256sum "${restored_upstream_pyproject}" | awk '{print $1}')" = \
  "${upstream_pyproject_sha}"
mv -- "${restored_upstream_pyproject}" "${upstream_pyproject}"
test "$(sha256sum "${upstream_pyproject}" | awk '{print $1}')" = \
  "${upstream_pyproject_sha}"

printf '%s @ %s --hash=sha256:%s\n' \
  "${package_name}" \
  "${wheel_url}" \
  "${wheel_sha}" >"${wheel_requirement}"
uv pip install \
  --python "${destination}/.venv/bin/python" \
  --no-deps \
  --no-build \
  --no-cache \
  --require-hashes \
  --requirement "${wheel_requirement}"
test -x "${destination}/.venv/bin/mcp-server-datahub"
test "$(
  uv pip show \
    --python "${destination}/.venv/bin/python" \
    "${package_name}" |
    awk '$1 == "Version:" {print $2}'
)" = "${package_version}"
