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
    .schemaVersion == "archon.datahub-mcp-lock/v5" and
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
      .constraints == [
        "acryl-datahub==1.6.0.15",
        "setuptools==81.0.0"
      ] and
      .sourceBuilds == "deny" and
      .projectMode == "virtual-static-metadata" and
      .virtualRootName == "archon-datahub-mcp-runtime" and
      .virtualRootVersion == "0.6.0" and
      .mcpDependency == "mcp-server-datahub==0.6.0" and
      (.resolvedLockSha256 | test("^[0-9a-f]{64}$")) and
      (keys | sort) == [
        "constraints",
        "excludeNewer",
        "mcpDependency",
        "projectMode",
        "registry",
        "resolvedLockSha256",
        "sourceBuilds",
        "strategy",
        "upgrade",
        "virtualRootName",
        "virtualRootVersion"
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
    (.upstreamLockProvenance | keys) == ["wheelLessDependency"] and
    .runtimeCompatibility.acrylDatahub == {
      name: "acryl-datahub",
      version: "1.6.0.15",
      metadataUrl: "https://pypi.org/pypi/acryl-datahub/1.6.0.15/json",
      setuptoolsRequirement: "setuptools<82.0.0",
      wheel: {
        filename: "acryl_datahub-1.6.0.15-py3-none-any.whl",
        url:
          "https://files.pythonhosted.org/packages/c1/81/32a1e7a9b7bd75c4930ba27edad498cde2e4032464df8ad7577776038341/acryl_datahub-1.6.0.15-py3-none-any.whl",
        sha256:
          "18263b60c52c333dda3091578dead0a238e606c92c0561fe7b52c905e7b00cbf",
        size: 4725320
      }
    } and
    .runtimeCompatibility.setuptools == {
      name: "setuptools",
      version: "81.0.0",
      metadataUrl: "https://pypi.org/pypi/setuptools/81.0.0/json",
      wheel: {
        filename: "setuptools-81.0.0-py3-none-any.whl",
        url:
          "https://files.pythonhosted.org/packages/e1/e3/c164c88b2e5ce7b24d667b9bd83589cf4f3520d97cad01534cd3c4f55fdb/setuptools-81.0.0-py3-none-any.whl",
        sha256:
          "fdd925d5c5d9f62e4b74b30d6dd7828ce236fd6ed998a08d81de62ce5a6310d6",
        size: 1062021
      }
    } and
    (.runtimeCompatibility | keys | sort) == [
      "acrylDatahub",
      "setuptools"
    ] and
    .advisoryDisposition.schemaVersion ==
      "archon.openvex-policy/v1" and
    .advisoryDisposition.vex == {
      path:
        ".github/security/openvex/datahub-mcp-setuptools-81.0.0.openvex.json",
      sha256:
        "9432452a9fd4b602ec6509b059d7e45d5fd48cfa3ccb3fcbdfa561451d3b8dbc",
      issuedAt: "2026-07-23T11:30:00Z",
      expiresAt: "2026-08-22T11:30:00Z",
      maxValidityDays: 30
    } and
    .advisoryDisposition.canonicalId == "CVE-2026-59890" and
    .advisoryDisposition.aliases == [
      "BIT-setuptools-2026-59890",
      "GHSA-h35f-9h28-mq5c",
      "PYSEC-2026-3447"
    ] and
    .advisoryDisposition.scannerRuleIds == [
      "GHSA-h35f-9h28-mq5c",
      "PYSEC-2026-3447"
    ] and
    .advisoryDisposition.product == {
      name: "mcp-server-datahub",
      version: "0.6.0",
      purl: "pkg:pypi/mcp-server-datahub@0.6.0"
    } and
    .advisoryDisposition.package == {
      name: "setuptools",
      version: "81.0.0",
      purl: "pkg:pypi/setuptools@81.0.0"
    } and
    .advisoryDisposition.status == "not_affected" and
    .advisoryDisposition.justification ==
      "vulnerable_code_not_in_execute_path" and
    .advisoryDisposition.conditions == {
      runnerOs: "Linux",
      pythonPlatform: "linux",
      sourceBuilds: "deny",
      sourceDistributionCreation: "forbidden",
      installation: "hash-bound-wheels-only"
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
      .runtimeCompatibility.acrylDatahub.wheel.sha256,
      .runtimeCompatibility.setuptools.wheel.sha256,
      .advisoryDisposition.vex.sha256,
      .files[].sha256
    ] |
      all(test("^[0-9a-f]{64}$"))) and
    ([
      .package.wheel.size,
      .upstreamLockProvenance.wheelLessDependency.sdist.size,
      .runtimeCompatibility.acrylDatahub.wheel.size,
      .runtimeCompatibility.setuptools.wheel.size,
      .files[].size
    ] |
      all(type == "number" and . > 0))
  ' "${contract}" >/dev/null

readonly vex_path="$(
  jq -er '.advisoryDisposition.vex.path' "${contract}"
)"
readonly vex_sha="$(
  jq -er '.advisoryDisposition.vex.sha256' "${contract}"
)"
readonly vex_issued_at="$(
  jq -er '.advisoryDisposition.vex.issuedAt' "${contract}"
)"
readonly vex_expires_at="$(
  jq -er '.advisoryDisposition.vex.expiresAt' "${contract}"
)"
readonly vex_max_validity_days="$(
  jq -er '.advisoryDisposition.vex.maxValidityDays' "${contract}"
)"
test -f "${vex_path}"
test ! -L "${vex_path}"
test "$(sha256sum "${vex_path}" | awk '{print $1}')" = "${vex_sha}"
jq --exit-status \
  --arg productWheelSha "$(jq -er '.package.wheel.sha256' "${contract}")" \
  --arg setuptoolsWheelSha "$(
    jq -er '.runtimeCompatibility.setuptools.wheel.sha256' "${contract}"
  )" \
  --arg impactStatement "$(
    jq -er '.advisoryDisposition.impactStatement' "${contract}"
  )" '
    ."@context" == "https://openvex.dev/ns/v0.2.0" and
    ."@id" ==
      "https://github.com/upgradedev/archon-datahub/security/vex/datahub-mcp-v0.6.0/setuptools-81.0.0/CVE-2026-59890" and
    .author == "https://github.com/upgradedev/archon-datahub" and
    .role == "Document Creator" and
    .timestamp == "2026-07-23T11:30:00Z" and
    .version == 1 and
    (.statements | length) == 1 and
    .statements[0].vulnerability == {
      "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-59890",
      name: "CVE-2026-59890",
      aliases: [
        "BIT-setuptools-2026-59890",
        "GHSA-h35f-9h28-mq5c",
        "PYSEC-2026-3447"
      ]
    } and
    .statements[0].products == [{
      "@id": "pkg:pypi/mcp-server-datahub@0.6.0",
      hashes: {"sha-256": $productWheelSha},
      subcomponents: [{
        "@id": "pkg:pypi/setuptools@81.0.0",
        hashes: {"sha-256": $setuptoolsWheelSha}
      }]
    }] and
    .statements[0].status == "not_affected" and
    .statements[0].justification ==
      "vulnerable_code_not_in_execute_path" and
    .statements[0].impact_statement == $impactStatement
  ' "${vex_path}" >/dev/null
readonly vex_issued_epoch="$(date -u --date="${vex_issued_at}" +%s)"
readonly vex_expires_epoch="$(date -u --date="${vex_expires_at}" +%s)"
readonly now_epoch="$(date -u +%s)"
test "${vex_max_validity_days}" = "30"
test "${vex_issued_epoch}" -le "${now_epoch}"
test "${now_epoch}" -lt "${vex_expires_epoch}"
test "${vex_expires_epoch}" -gt "${vex_issued_epoch}"
test "$((vex_expires_epoch - vex_issued_epoch))" -le \
  "$((vex_max_validity_days * 24 * 60 * 60))"

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
readonly openvex="${evidence_dir}/openvex.json"
mkdir -p "${evidence_dir}"
cp -- "${destination}/pyproject.toml" "${upstream_pyproject}"
cp -- "${destination}/uv.lock" "${upstream_lock}"
cp -- "${vex_path}" "${openvex}"
test -f "${upstream_pyproject}"
test ! -L "${upstream_pyproject}"
test -f "${upstream_lock}"
test ! -L "${upstream_lock}"
test -f "${openvex}"
test ! -L "${openvex}"
test "$(sha256sum "${upstream_pyproject}" | awk '{print $1}')" = \
  "$(jq -er '.files["pyproject.toml"].sha256' "${contract}")"
test "$(sha256sum "${upstream_lock}" | awk '{print $1}')" = \
  "$(jq -er '.files["uv.lock"].sha256' "${contract}")"
test "$(sha256sum "${openvex}" | awk '{print $1}')" = "${vex_sha}"

# Validate the authenticated upstream TOML documents without asking uv to resolve
# the dynamic editable project. The Git tree/blob/SHA/size checks above establish
# exact authorship; this structural check establishes that the retained lock is
# the source project's graph without invoking its build backend.
python3 - \
  "${upstream_pyproject}" \
  "${upstream_lock}" \
  "$(jq -er '.package.name' "${contract}")" <<'PY'
import sys
import tomllib

pyproject_path, lock_path, expected_name = sys.argv[1:]
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
require(
    "version" not in roots[0],
    "upstream dynamic project unexpectedly has a locked version",
)
require(
    roots[0].get("source") == {"editable": "."},
    "upstream lock root is not the authenticated checkout",
)
PY

# Convert only the already hash-verified project metadata into a distinctly named
# virtual project with a static version. The official MCP release is added as a
# registry dependency, so uv audits the package that is actually executed instead
# of excluding it as the local project root. No upstream build backend executes.
python3 - \
  "${destination}/pyproject.toml" \
  "$(jq -er '.package.name' "${contract}")" \
  "$(jq -er '.resolution.virtualRootName' "${contract}")" \
  "$(jq -er '.resolution.virtualRootVersion' "${contract}")" \
  "$(jq -er '.resolution.mcpDependency' "${contract}")" \
  "$(jq -cer '.resolution.constraints | select(length == 2)' \
    "${contract}")" <<'PY'
import json
import pathlib
import sys
import tomllib

path = pathlib.Path(sys.argv[1])
upstream_name = sys.argv[2]
virtual_name = sys.argv[3]
virtual_version = sys.argv[4]
mcp_dependency = sys.argv[5]
constraints = json.loads(sys.argv[6])
if upstream_name != "mcp-server-datahub":
    raise SystemExit("upstream MCP project identity changed")
if virtual_name != "archon-datahub-mcp-runtime":
    raise SystemExit("virtual runtime project identity changed")
if virtual_version != "0.6.0":
    raise SystemExit("virtual runtime project version changed")
if mcp_dependency != "mcp-server-datahub==0.6.0":
    raise SystemExit("audited MCP registry dependency changed")
if constraints != [
    "acryl-datahub==1.6.0.15",
    "setuptools==81.0.0",
]:
    raise SystemExit("resolved dependency constraints changed")
if not path.is_file() or path.is_symlink():
    raise SystemExit("upstream pyproject must be one regular file")
text = path.read_text(encoding="utf-8")
upstream = tomllib.loads(text)
upstream_project = upstream.get("project", {})
upstream_dependencies = upstream_project.get("dependencies")
if upstream_project.get("name") != upstream_name:
    raise SystemExit("upstream project name changed")
if not isinstance(upstream_dependencies, list) or not upstream_dependencies:
    raise SystemExit("upstream project dependencies changed")
if mcp_dependency in upstream_dependencies:
    raise SystemExit("upstream project already depends on its registry package")
name_marker = f'name = "{upstream_name}"'
dynamic = 'dynamic = ["version"]'
dependencies_marker = "dependencies = [\n"
tool_uv = "[tool.uv]\n"
if text.count(name_marker) != 1:
    raise SystemExit("upstream project name marker changed")
if text.count(dynamic) != 1:
    raise SystemExit("upstream dynamic version marker changed")
if text.count(dependencies_marker) != 1:
    raise SystemExit("upstream dependency table changed")
if text.count(tool_uv) != 1:
    raise SystemExit("upstream [tool.uv] table changed")
if "\npackage =" in text:
    raise SystemExit("upstream project already declares tool.uv.package")
if "\nconstraint-dependencies =" in text:
    raise SystemExit("upstream project already declares dependency constraints")
text = text.replace(name_marker, f'name = "{virtual_name}"', 1)
text = text.replace(dynamic, f'version = "{virtual_version}"', 1)
text = text.replace(
    dependencies_marker,
    dependencies_marker + f'    "{mcp_dependency}",\n',
    1,
)
text = text.replace(
    tool_uv,
    tool_uv
    + "package = false\n"
    + "constraint-dependencies = "
    + json.dumps(constraints, ensure_ascii=True, separators=(",", ":"))
    + "\n",
    1,
)
resolved = tomllib.loads(text)
project = resolved.get("project", {})
tool = resolved.get("tool", {}).get("uv", {})
if project.get("name") != virtual_name:
    raise SystemExit("resolved virtual project name changed")
if project.get("version") != virtual_version or "dynamic" in project:
    raise SystemExit("resolved virtual project version is not static")
if project.get("dependencies") != [mcp_dependency, *upstream_dependencies]:
    raise SystemExit("resolved audited dependency set changed")
if tool.get("package") is not False:
    raise SystemExit("resolved project must remain virtual")
if tool.get("constraint-dependencies") != constraints:
    raise SystemExit("resolved dependency constraint changed")
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
  --arg upstreamProjectName "$(jq -er '.package.name' "${contract}")" \
  --arg resolvedProjectName "$(
    jq -er '.resolution.virtualRootName' "${contract}"
  )" \
  --arg version "$(jq -er '.resolution.virtualRootVersion' "${contract}")" \
  --arg mcpDependency "$(jq -er '.resolution.mcpDependency' "${contract}")" \
  --argjson constraints "$(
    jq -cer '.resolution.constraints | select(length == 2)' \
      "${contract}"
  )" '
    {
      schemaVersion: "archon.datahub-mcp-project-overlay/v3",
      upstreamPyprojectSha256: $upstreamPyprojectSha256,
      resolvedPyprojectSha256: $resolvedPyprojectSha256,
      upstreamProjectName: $upstreamProjectName,
      resolvedProjectName: $resolvedProjectName,
      version: $version,
      mcpDependency: $mcpDependency,
      package: false,
      constraintDependencies: $constraints,
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
  "${contract}" \
  "$(jq -er '.resolution.virtualRootName' "${contract}")" \
  "$(jq -er '.resolution.virtualRootVersion' "${contract}")" \
  "${registry}" <<'PY'
import json
import pathlib
import re
import sys
import tomllib

lock_path, output_path, contract_path, project_name, project_version, registry = (
    sys.argv[1:]
)
with open(lock_path, "rb") as handle:
    lock = tomllib.load(handle)
with open(contract_path, encoding="utf-8") as handle:
    contract = json.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


packages = lock.get("package")
require(isinstance(packages, list) and len(packages) > 10, "invalid resolved package set")
roots = [package for package in packages if package.get("name") == project_name]
require(len(roots) == 1, "resolved lock must contain one virtual runtime root")
require(
    roots[0].get("version") == project_version,
    "resolved virtual runtime root version changed",
)
require(
    roots[0].get("source") == {"virtual": "."},
    "resolved runtime project is not a non-buildable virtual root",
)
root_dependencies = roots[0].get("dependencies")
require(
    isinstance(root_dependencies, list),
    "resolved virtual runtime dependencies are missing",
)
mcp_dependency_edges = [
    dependency
    for dependency in root_dependencies
    if isinstance(dependency, dict)
    and dependency.get("name") == contract["package"]["name"]
]
require(
    len(mcp_dependency_edges) == 1,
    "virtual runtime root must reach one audited MCP registry package",
)

sha256 = re.compile(r"^sha256:[0-9a-f]{64}$")
compatibility = contract["runtimeCompatibility"]
expected_artifacts = {
    contract["package"]["name"]: contract["package"],
    **{
        artifact["name"]: artifact
        for artifact in compatibility.values()
    },
}
require(
    contract["resolution"]["constraints"]
    == [
        "acryl-datahub==1.6.0.15",
        "setuptools==81.0.0",
    ],
    "runtime compatibility constraints changed",
)
require(
    set(expected_artifacts)
    == {"mcp-server-datahub", "acryl-datahub", "setuptools"},
    "pinned runtime artifacts changed",
)
pinned_artifacts_seen = set()
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
    if name in expected_artifacts:
        artifact = expected_artifacts[name]
        pinned_artifacts_seen.add(name)
        expected_wheel = {
            "hash": artifact["wheel"]["sha256"],
            "size": artifact["wheel"]["size"],
            "url": artifact["wheel"]["url"],
        }
        require(
            version == artifact["version"],
            f"resolved {name} version violates the compatibility constraint",
        )
        require(
            retained_wheels == [expected_wheel],
            f"resolved {name} wheel set differs from the exact pinned artifact",
        )
    graph.append(
        {
            "name": name,
            "version": version,
            "wheels": sorted(retained_wheels, key=lambda item: item["url"]),
        }
    )

require(
    pinned_artifacts_seen == set(expected_artifacts),
    "resolved graph omitted an exact pinned runtime artifact",
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
