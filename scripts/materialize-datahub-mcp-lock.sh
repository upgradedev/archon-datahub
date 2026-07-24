#!/usr/bin/env bash
set -euo pipefail

# Preserve the exact upstream v0.6.0 source lock for provenance, then derive the
# runtime lock in CI under one repository-owned, time-bounded resolution policy.
# Runtime installation is wheel-only; package-controlled source never executes.

readonly contract="${ARCHON_DATAHUB_MCP_LOCK_CONTRACT:-.github/locks/datahub-mcp-v0.6.0.json}"
readonly destination="${1:-}"
readonly allow_unsealed="${ARCHON_ALLOW_UNSEALED_RESOLVED_LOCK:-false}"
readonly zero_sha256="$(
  printf '0%.0s' {1..64}
)"

if [[ -z "${destination}" || "${destination}" != /* ]]; then
  echo "usage: $0 ABSOLUTE_DESTINATION" >&2
  exit 64
fi
test -f "${contract}"
test ! -L "${contract}"
if [[ "${allow_unsealed}" != "true" && "${allow_unsealed}" != "false" ]]; then
  echo "ARCHON_ALLOW_UNSEALED_RESOLVED_LOCK must be true or false" >&2
  exit 64
fi

jq --exit-status '
    .schemaVersion == "archon.datahub-mcp-lock/v3" and
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
    (
      .resolution |
      .registry == "https://pypi.org/simple" and
      .strategy == "highest" and
      .upgrade == "all" and
      .excludeNewer == "2026-07-23T03:00:00Z" and
      .sourceBuilds == "deny" and
      .projectMode == "virtual-static-metadata" and
      (.resolvedLockSha256 | test("^[0-9a-f]{64}$")) and
      (keys | sort) == [
        "excludeNewer",
        "projectMode",
        "registry",
        "resolvedLockSha256",
        "sourceBuilds",
        "strategy",
        "upgrade"
      ]
    ) and
    .upstreamLockProvenance.wheelLessDependency == {
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
    } and
    .upstreamLockProvenance.historicalBuildBackend == {
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
      .upstreamLockProvenance.wheelLessDependency.sdist.sha256,
      .upstreamLockProvenance.historicalBuildBackend.wheel.sha256,
      .files[].sha256
    ] |
      all(test("^[0-9a-f]{64}$"))) and
    ([
      .package.wheel.size,
      .upstreamLockProvenance.wheelLessDependency.sdist.size,
      .upstreamLockProvenance.historicalBuildBackend.wheel.size,
      .files[].size
    ] |
      all(type == "number" and . > 0))
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

readonly evidence_dir="${destination}/.archon-evidence"
readonly upstream_pyproject="${evidence_dir}/upstream-pyproject.toml"
readonly upstream_lock="${evidence_dir}/upstream-uv.lock"
readonly resolved_pyproject="${evidence_dir}/resolved-pyproject.toml"
readonly project_overlay="${evidence_dir}/project-overlay.json"
readonly resolved_lock="${evidence_dir}/resolved-uv.lock"
readonly wheel_graph="${evidence_dir}/wheel-only-graph.json"
readonly lock_binding="${evidence_dir}/resolved-lock-binding.json"
mkdir -p "${evidence_dir}"
cp -- "${destination}/pyproject.toml" "${upstream_pyproject}"
cp -- "${destination}/uv.lock" "${upstream_lock}"
test -f "${upstream_pyproject}"
test ! -L "${upstream_pyproject}"
test -f "${upstream_lock}"
test ! -L "${upstream_lock}"
test "$(sha256sum "${upstream_pyproject}" | awk '{print $1}')" = \
  "$(jq -er '.files["pyproject.toml"].sha256' "${contract}")"
test "$(sha256sum "${upstream_lock}" | awk '{print $1}')" = \
  "$(jq -er '.files["uv.lock"].sha256' "${contract}")"

# Validate the authenticated upstream TOML documents without asking uv to resolve
# the dynamic editable project. The Git tree/blob/SHA/size checks above establish
# exact authorship; this structural check establishes that the retained lock is
# the source project's graph without invoking its build backend.
python3 - \
  "${upstream_pyproject}" \
  "${upstream_lock}" \
  "$(jq -er '.package.name' "${contract}")" \
  "$(jq -er '.package.version' "${contract}")" <<'PY'
import sys
import tomllib

pyproject_path, lock_path, expected_name, expected_version = sys.argv[1:]
with open(pyproject_path, "rb") as handle:
    pyproject = tomllib.load(handle)
with open(lock_path, "rb") as handle:
    lock = tomllib.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


project = pyproject.get("project", {})
require(project.get("name") == expected_name, "upstream project name changed")
require(project.get("dynamic") == ["version"], "upstream version source changed")
require(project.get("requires-python") == ">=3.11", "upstream Python range changed")
require(
    lock.get("requires-python") == project["requires-python"],
    "upstream project and lock Python ranges differ",
)
packages = lock.get("package")
require(isinstance(packages, list) and len(packages) > 10, "upstream lock graph missing")
roots = [package for package in packages if package.get("name") == expected_name]
require(len(roots) == 1, "upstream lock project root is ambiguous")
require(roots[0].get("version") == expected_version, "upstream lock version changed")
require(
    roots[0].get("source") == {"editable": "."},
    "upstream lock root is not the authenticated checkout",
)
PY

# Convert only the already hash-verified project metadata into a virtual project
# with a static version. uv therefore resolves its declared runtime dependencies
# without invoking the upstream setuptools/setuptools-scm build backend. The
# official, provenance-bound wheel is installed separately after the sync.
python3 - \
  "${destination}/pyproject.toml" \
  "$(jq -er '.package.version' "${contract}")" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
if not path.is_file() or path.is_symlink():
    raise SystemExit("upstream pyproject must be one regular file")
text = path.read_text(encoding="utf-8")
dynamic = 'dynamic = ["version"]'
tool_uv = "[tool.uv]\n"
if text.count(dynamic) != 1:
    raise SystemExit("upstream dynamic version marker changed")
if text.count(tool_uv) != 1:
    raise SystemExit("upstream [tool.uv] table changed")
if "\npackage =" in text:
    raise SystemExit("upstream project already declares tool.uv.package")
text = text.replace(dynamic, f'version = "{version}"', 1)
text = text.replace(tool_uv, tool_uv + "package = false\n", 1)
path.write_text(text, encoding="utf-8")
PY
test -f "${destination}/pyproject.toml"
test ! -L "${destination}/pyproject.toml"
cp -- "${destination}/pyproject.toml" "${resolved_pyproject}"
test -f "${resolved_pyproject}"
test ! -L "${resolved_pyproject}"
readonly upstream_pyproject_sha="$(
  jq -er '.files["pyproject.toml"].sha256' "${contract}"
)"
readonly resolved_pyproject_sha="$(
  sha256sum "${resolved_pyproject}" | awk '{print $1}'
)"
test "${resolved_pyproject_sha}" != "${upstream_pyproject_sha}"
jq -cnS \
  --arg upstreamPyprojectSha256 "${upstream_pyproject_sha}" \
  --arg resolvedPyprojectSha256 "${resolved_pyproject_sha}" \
  --arg version "$(jq -er '.package.version' "${contract}")" '
    {
      schemaVersion: "archon.datahub-mcp-project-overlay/v1",
      upstreamPyprojectSha256: $upstreamPyprojectSha256,
      resolvedPyprojectSha256: $resolvedPyprojectSha256,
      version: $version,
      package: false,
      buildBackendExecution: "forbidden"
    }
  ' >"${project_overlay}"
test -s "${project_overlay}"
test ! -L "${project_overlay}"

readonly registry="$(jq -er '.resolution.registry' "${contract}")"
readonly resolution_strategy="$(
  jq -er '.resolution.strategy' "${contract}"
)"
readonly exclude_newer="$(jq -er '.resolution.excludeNewer' "${contract}")"

# This is the only resolver invocation. The uv version, registry, strategy,
# timestamp horizon, full-upgrade policy, and source-build denial are all fixed.
uv lock \
  --project "${destination}" \
  --upgrade \
  --resolution "${resolution_strategy}" \
  --exclude-newer "${exclude_newer}" \
  --default-index "${registry}" \
  --no-build \
  --no-cache
uv lock \
  --project "${destination}" \
  --check \
  --resolution "${resolution_strategy}" \
  --exclude-newer "${exclude_newer}" \
  --default-index "${registry}" \
  --no-build \
  --no-cache

test -f "${destination}/uv.lock"
test ! -L "${destination}/uv.lock"
cp -- "${destination}/uv.lock" "${resolved_lock}"
test -f "${resolved_lock}"
test ! -L "${resolved_lock}"

# Reject every non-registry or wheel-less node. An sdist reference may be present
# as registry metadata, but no node is accepted unless at least one wheel is
# locked, and all subsequent installation commands also prohibit builds.
python3 - \
  "${resolved_lock}" \
  "${wheel_graph}" \
  "$(jq -er '.package.name' "${contract}")" \
  "$(jq -er '.package.version' "${contract}")" \
  "${registry}" <<'PY'
import json
import pathlib
import re
import sys
import tomllib

lock_path, output_path, project_name, project_version, registry = sys.argv[1:]
with open(lock_path, "rb") as handle:
    lock = tomllib.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


packages = lock.get("package")
require(isinstance(packages, list) and len(packages) > 10, "invalid resolved package set")
roots = [package for package in packages if package.get("name") == project_name]
require(len(roots) == 1, "resolved lock must contain one MCP project root")
require(roots[0].get("version") == project_version, "resolved MCP project version changed")
require(
    roots[0].get("source") == {"virtual": "."},
    "resolved MCP project is not a non-buildable virtual root",
)

sha256 = re.compile(r"^sha256:[0-9a-f]{64}$")
graph = []
for package in packages:
    name = package.get("name")
    version = package.get("version")
    require(isinstance(name, str) and name, "resolved package name missing")
    require(isinstance(version, str) and version, f"resolved version missing for {name}")
    if name == project_name:
        continue
    require(
        package.get("source") == {"registry": registry},
        f"non-registry dependency rejected: {name}",
    )
    wheels = package.get("wheels")
    require(
        isinstance(wheels, list) and len(wheels) > 0,
        f"wheel-less dependency rejected: {name}=={version}",
    )
    retained_wheels = []
    for wheel in wheels:
        url = wheel.get("url")
        digest = wheel.get("hash")
        size = wheel.get("size")
        require(
            isinstance(url, str) and url.startswith("https://files.pythonhosted.org/"),
            f"untrusted wheel origin for {name}=={version}",
        )
        require(
            isinstance(digest, str) and sha256.fullmatch(digest),
            f"invalid wheel digest for {name}=={version}",
        )
        require(
            isinstance(size, int) and size > 0,
            f"invalid wheel size for {name}=={version}",
        )
        retained_wheels.append(
            {"hash": digest.removeprefix("sha256:"), "size": size, "url": url}
        )
    graph.append(
        {
            "name": name,
            "version": version,
            "wheels": sorted(retained_wheels, key=lambda item: item["url"]),
        }
    )

document = {
    "schemaVersion": "archon.datahub-mcp-wheel-only-graph/v1",
    "packageCount": len(graph),
    "packages": sorted(graph, key=lambda item: (item["name"], item["version"])),
}
path = pathlib.Path(output_path)
path.write_text(
    json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
test -s "${wheel_graph}"
test ! -L "${wheel_graph}"

readonly observed_resolved_sha="$(
  sha256sum "${resolved_lock}" | awk '{print $1}'
)"
readonly expected_resolved_sha="$(
  jq -er '.resolution.resolvedLockSha256' "${contract}"
)"
test "${observed_resolved_sha}" != \
  "$(jq -er '.files["uv.lock"].sha256' "${contract}")"

binding_matches=false
if [[ "${observed_resolved_sha}" == "${expected_resolved_sha}" ]]; then
  binding_matches=true
fi
binding_placeholder=false
if [[ "${expected_resolved_sha}" == "${zero_sha256}" ]]; then
  binding_placeholder=true
fi
jq -cnS \
  --arg expectedResolvedLockSha256 "${expected_resolved_sha}" \
  --arg observedResolvedLockSha256 "${observed_resolved_sha}" \
  --arg upstreamLockSha256 "$(
    jq -er '.files["uv.lock"].sha256' "${contract}"
  )" \
  --argjson matches "${binding_matches}" \
  --argjson placeholder "${binding_placeholder}" '
    {
      schemaVersion: "archon.datahub-mcp-resolved-lock-binding/v1",
      upstreamLockSha256: $upstreamLockSha256,
      expectedResolvedLockSha256: $expectedResolvedLockSha256,
      observedResolvedLockSha256: $observedResolvedLockSha256,
      matches: $matches,
      placeholder: $placeholder
    }
  ' >"${lock_binding}"
test -s "${lock_binding}"
test ! -L "${lock_binding}"
echo "Observed resolved DataHub MCP lock SHA-256: ${observed_resolved_sha}"

# Only the uncredentialed exploratory CI job may continue far enough to audit and
# retain an as-yet-unsealed graph. Every other caller (including live proof)
# requires the repository contract to bind the observed resolved-lock bytes.
if [[ "${binding_placeholder}" == "true" ||
  "${binding_matches}" != "true" ]]; then
  if [[ "${allow_unsealed}" != "true" ]]; then
    echo "resolved DataHub MCP lock is not bound by the contract" >&2
    echo "observed SHA-256: ${observed_resolved_sha}" >&2
    exit 66
  fi
fi

# PyPI trusted-publisher provenance binds the exact MCP wheel digest to the
# official acryldata release workflow.
readonly provenance_url="$(
  jq -er '.package.pypiProvenance.url' "${contract}"
)"
readonly provenance="${evidence_dir}/pypi-provenance.json"
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

# Consume the derived lock exactly. Both the project sync and direct MCP wheel
# install deny source builds; --no-cache prevents reuse of locally built wheels.
readonly python_version="$(jq -er '.runtime.pythonVersion' "${contract}")"
readonly package_name="$(jq -er '.package.name' "${contract}")"
readonly package_version="$(jq -er '.package.version' "${contract}")"
readonly wheel_url="$(jq -er '.package.wheel.url' "${contract}")"
readonly wheel_sha="$(jq -er '.package.wheel.sha256' "${contract}")"
readonly wheel_requirement="$(mktemp)"
trap 'rm -f "${wheel_requirement}"' EXIT

uv sync \
  --project "${destination}" \
  --frozen \
  --no-dev \
  --no-install-project \
  --no-build \
  --no-cache \
  --python "${python_version}"

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
