#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly source_bundle="/tmp/archon-datahub-core-source.tar.gz"
readonly install_root="/opt/archon"
readonly staging="/var/tmp/archon-datahub-core-build"
readonly datahub_commit="059a36c0b035a6057de00114ccac0ea9003d6bc2"
readonly datahub_tree="7b444fc729abbd5c831862b3821c06ee323aeb9d"
readonly compose_sha256="e74f42d5382e2a3cf98620322f8e20f1cbd7fb356af078a233001085b734108a"
readonly hardened_compose_sha256="10d2ce9fe864eb6eab3710e7f8a87b9d6fa98ac0e17c82f17eaa83bb92f02f7e"
readonly compose_version="v5.3.1"
readonly compose_binary_sha256="f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959"

require_value() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" || "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    echo "${name} is missing or invalid" >&2
    exit 64
  fi
}

for name in \
  ARCHON_RELEASE_SHA \
  ARCHON_BASE_AMI_ID \
  ARCHON_COMPANION_SOURCE_SHA \
  ARCHON_GENERATION \
  ARCHON_CAPABILITY_DIGEST \
  ARCHON_IMAGE_MANIFEST_DIGEST; do
  require_value "${name}"
done
[[ "${ARCHON_RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${ARCHON_BASE_AMI_ID}" =~ ^ami-[0-9a-f]{8,17}$ ]]
[[ "${ARCHON_COMPANION_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${ARCHON_GENERATION}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
[[ "${ARCHON_CAPABILITY_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "${ARCHON_IMAGE_MANIFEST_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$(id -u)" == "0" ]]
test -f "${source_bundle}"
test ! -L "${source_bundle}"

cleanup() {
  rm -rf -- "${staging}"
  rm -f -- "${source_bundle}" /tmp/archon-compose-build.env
}
trap cleanup EXIT
rm -rf -- "${staging}"
mkdir -p "${staging}"

python3 - "${source_bundle}" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    if not members or len(members) > 20_000:
        raise SystemExit("source bundle member count is invalid")
    total = 0
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
            raise SystemExit("source bundle contains an unsafe path")
        if member.isdev() or member.isfifo():
            raise SystemExit("source bundle contains a special file")
        total += max(0, member.size)
    if total > 2_000_000_000:
        raise SystemExit("source bundle exceeds its size bound")
PY
tar --extract --gzip --file "${source_bundle}" \
  --directory "${staging}" --no-same-owner --no-same-permissions
test -f "${staging}/bundle-manifest.json"
readonly resolved_manifest="${staging}/supply-chain/resolved-images.json"
test -f "${resolved_manifest}"
test ! -L "${resolved_manifest}"
resolved_manifest_sha="$(sha256sum "${resolved_manifest}" | awk '{print $1}')"
readonly resolved_manifest_sha
test "sha256:${resolved_manifest_sha}" = "${ARCHON_IMAGE_MANIFEST_DIGEST}"
jq --exit-status \
  --arg releaseSha "${ARCHON_RELEASE_SHA}" \
  --arg companionSourceSha "${ARCHON_COMPANION_SOURCE_SHA}" \
  --arg resolvedManifestSha256 "${resolved_manifest_sha}" '
    .schemaVersion == "archon.datahub-core-source-bundle/v2" and
    .releaseSha == $releaseSha and
    .companionSourceSha == $companionSourceSha and
    .companionArtifactVerified == true and
    .resolvedImagesManifestSha256 == $resolvedManifestSha256 and
    (.companionRunId | type == "string" and test("^[1-9][0-9]{0,19}$"))
  ' "${staging}/bundle-manifest.json" >/dev/null
jq --exit-status \
  --arg commit "${datahub_commit}" \
  --arg tree "${datahub_tree}" \
  --arg composeSha256 "${compose_sha256}" '
    .schemaVersion == "archon.datahub-core-resolved-images/v1" and
    .source == {commit:$commit,tree:$tree,composeSha256:$composeSha256} and
    (.images | type == "array" and length >= 8 and length <= 32) and
    (.services | type == "array" and length >= 8) and
    all(.images[];
      (.declaredReference | type == "string" and test("^[^[:space:]@]+(:[^[:space:]@]+)?$")) and
      (.resolvedReference | type == "string" and test("^[^[:space:]@]+@sha256:[0-9a-f]{64}$")) and
      (.imageId | type == "string" and test("^sha256:[0-9a-f]{64}$"))) and
    all(.services[];
      (.service | type == "string" and test("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")) and
      (.resolvedReference | type == "string" and test("^[^[:space:]@]+@sha256:[0-9a-f]{64}$"))) and
    .security.rawFindingsRetained == true and
    .security.unfixedFindingsRetained == true and
    .security.actionableGate == "fixed HIGH,CRITICAL" and
    .security.vexGenerated == false
  ' "${resolved_manifest}" >/dev/null

# The runner supplies its already-pinned uv binary in the source bundle.
test -x "${staging}/tools/uv"
test -f "${staging}/tools/uv.sha256"
(
  cd "${staging}/tools"
  sha256sum --check --strict uv.sha256
)
install -D -m 0755 "${staging}/tools/uv" /usr/local/bin/uv
test "$(uv --version | awk '{print $2}')" = "0.11.31"

# Patch AL2023 before installing the exact build/runtime prerequisites. The AMI
# boots the patched kernel; a second security-only check later must be empty.
dnf --refresh upgrade -y
dnf install -y docker git jq
dnf clean all
rm -rf /var/cache/dnf

# Trivy is runner-supplied and checksum sealed. It is used only during the bake
# and is removed, together with its databases, before the AMI is finalized.
test -x "${staging}/tools/trivy"
test -f "${staging}/tools/trivy.sha256"
(
  cd "${staging}/tools"
  sha256sum --check --strict trivy.sha256
)
install -D -m 0755 "${staging}/tools/trivy" /usr/local/bin/trivy
test "$(trivy --version | awk 'NR==1 {print $2}')" = "0.70.0"
install -d -m 0755 /usr/local/lib/docker/cli-plugins
curl --fail --silent --show-error --location \
  --output /usr/local/lib/docker/cli-plugins/docker-compose \
  "https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-x86_64"
echo "${compose_binary_sha256}  /usr/local/lib/docker/cli-plugins/docker-compose" |
  sha256sum --check --strict
chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose
test "$(docker compose version --short)" = "${compose_version#v}"
systemctl enable --now docker

# Verify and load the immutable companion OCI artifact. It is never rebuilt here.
readonly companion_root="${staging}/companion"
test -f "${companion_root}/evidence/companion-image.tar.gz"
test -f "${companion_root}/evidence/image-subject.sha256"
test -f "${companion_root}/evidence/SHA256SUMS"
test -f "${companion_root}/evidence/provenance.json"
(
  cd "${companion_root}"
  sha256sum --check --strict evidence/SHA256SUMS
  sha256sum --check --strict evidence/image-subject.sha256
)
readonly provenance="${companion_root}/evidence/provenance.json"
jq --exit-status \
  --arg sourceSha "${ARCHON_COMPANION_SOURCE_SHA}" '
    .schemaVersion == "archon.datahub-companion-image-provenance/v1" and
    .sourceSha == $sourceSha and
    (.imageId | test("^sha256:[0-9a-f]{64}$")) and
    (.archiveSha256 | test("^[0-9a-f]{64}$")) and
    (.buildDigest | test("^sha256:[0-9a-f]{64}$")) and
    .sourceBuilds == "deny" and
    (.runtimeUser == "65532" or .runtimeUser == "65532:65532")
  ' "${provenance}" >/dev/null
archive_sha="$(sha256sum "${companion_root}/evidence/companion-image.tar.gz" | awk '{print $1}')"
readonly archive_sha
test "${archive_sha}" = "$(jq -er '.archiveSha256' "${provenance}")"
gzip --decompress --stdout "${companion_root}/evidence/companion-image.tar.gz" |
  docker load >/dev/null
companion_image_id="$(jq -er '.imageId' "${provenance}")"
readonly companion_image_id
test "$(docker image inspect --format '{{.Id}}' "${companion_image_id}")" = \
  "${companion_image_id}"
docker image tag "${companion_image_id}" archon/datahub-companion:sealed

install -d -m 0755 \
  "${install_root}/core/demo" \
  "${install_root}/image" \
  "${install_root}/datahub" \
  "${install_root}/.github/locks"
printf '%s\n' "${companion_image_id}" >"${install_root}/image/companion-image.id"
chmod 0444 "${install_root}/image/companion-image.id"
install -m 0444 "${provenance}" "${install_root}/image/companion-provenance.json"
install -m 0444 \
  "${staging}/repo/infra/aws/image/datahub-core-image.lock.json" \
  "${install_root}/image/datahub-core-image.lock.json"
install -m 0444 \
  "${staging}/repo/.github/locks/datahub-agent-stack.json" \
  "${install_root}/.github/locks/datahub-agent-stack.json"
install -m 0444 \
  "${staging}/repo/.github/locks/datahub-mcp-v0.6.0.json" \
  "${install_root}/.github/locks/datahub-mcp-v0.6.0.json"
install -m 0444 \
  "${staging}/repo/infra/aws/image/core_job_adapter.py" \
  "${install_root}/core/core_job_adapter.py"
install -m 0444 \
  "${staging}/repo/infra/aws/image/governed_datahub_gateway.py" \
  "${install_root}/governed_gateway.py"
install -m 0444 \
  "${staging}/repo/infra/aws/image/datahub_core_bootstrap.py" \
  "${install_root}/core/datahub_core_bootstrap.py"
install -m 0444 \
  "${staging}/repo/services/datahub-companion/demo/archon_demo.sql" \
  "${install_root}/core/demo/archon_demo.sql"
install -m 0444 \
  "${staging}/repo/services/datahub-companion/demo/seed_datahub.py" \
  "${install_root}/core/demo/seed_datahub.py"

# Materialize a separate, hash-bound gateway/bootstrap venv. This reuses the
# audited MCP dependency graph but not the official read-MCP process or token.
export UV_PYTHON_INSTALL_DIR="${install_root}/python"
uv python install 3.11.15
(
  cd "${staging}/repo"
  ARCHON_DATAHUB_MCP_LOCK_CONTRACT=.github/locks/datahub-mcp-v0.6.0.json \
    ./scripts/materialize-datahub-mcp-lock.sh "${install_root}/governed"
)
test -x "${install_root}/governed/.venv/bin/python"
PYTHONDONTWRITEBYTECODE=1 \
  "${install_root}/governed/.venv/bin/python" - <<PY
import boto3
import datahub
import fastmcp
import sys
sys.path.insert(0, "${install_root}/core")
import core_job_adapter
import datahub_core_bootstrap
assert datahub_core_bootstrap.SOURCE_URN.endswith("archon_demo.customers,PROD)")
PY
rm -rf -- "${install_root}/governed/.git"
find "${install_root}" -type d -name __pycache__ -prune -exec rm -rf -- {} +

# The runner has already authenticated the exact DataHub source and resolved each
# image once. Revalidate the sealed evidence; never resolve a mutable tag here.
readonly supply_root="${staging}/supply-chain"
test -f "${supply_root}/SHA256SUMS"
(
  cd "${supply_root}"
  sha256sum --check --strict SHA256SUMS
)
test "$(sha256sum "${supply_root}/upstream-compose.yml" | awk '{print $1}')" = \
  "${compose_sha256}"
install -m 0600 "${supply_root}/upstream-compose.yml" \
  "${install_root}/datahub/docker-compose.yml"
python3 - "${install_root}/datahub/docker-compose.yml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = {
    "DATAHUB_SYSTEM_CLIENT_SECRET=JohnSnowKnowsNothing":
        ("DATAHUB_SYSTEM_CLIENT_SECRET=${DATAHUB_SYSTEM_CLIENT_SECRET}", 1),
    "DATAHUB_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":
        ("DATAHUB_SECRET=${DATAHUB_SECRET}", 1),
    "EBEAN_DATASOURCE_PASSWORD=datahub":
        ("EBEAN_DATASOURCE_PASSWORD=${ARCHON_MYSQL_PASSWORD}", 2),
    "NEO4J_PASSWORD=datahub":
        ("NEO4J_PASSWORD=${ARCHON_NEO4J_PASSWORD}", 1),
    "MYSQL_PASSWORD=datahub":
        ("MYSQL_PASSWORD=${ARCHON_MYSQL_PASSWORD}", 1),
    "MYSQL_ROOT_PASSWORD=datahub":
        ("MYSQL_ROOT_PASSWORD=${ARCHON_MYSQL_ROOT_PASSWORD}", 1),
    "NEO4J_AUTH=neo4j/datahub":
        ("NEO4J_AUTH=neo4j/${ARCHON_NEO4J_PASSWORD}", 1),
}
for fixed, (parameterized, expected) in replacements.items():
    observed = text.count(fixed)
    if observed != expected:
        raise SystemExit(
            f"upstream credential anchor {fixed!r}: expected {expected}, observed {observed}"
        )
    text = text.replace(fixed, parameterized)
path.write_text(text, encoding="utf-8")
PY
chmod 0444 "${install_root}/datahub/docker-compose.yml"
hardened_compose_sha="$(
  sha256sum "${install_root}/datahub/docker-compose.yml" | awk '{print $1}'
)"
readonly hardened_compose_sha
test "${hardened_compose_sha}" = "${hardened_compose_sha256}"
if grep -E --line-number \
  'JohnSnowKnowsNothing|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|EBEAN_DATASOURCE_PASSWORD=datahub|NEO4J_PASSWORD=datahub|MYSQL_PASSWORD=datahub|MYSQL_ROOT_PASSWORD=datahub|NEO4J_AUTH=neo4j/datahub' \
  "${install_root}/datahub/docker-compose.yml"; then
  echo "fixed upstream credential remained after compose hardening" >&2
  exit 67
fi

cat >"${install_root}/datahub/docker-compose.archon.yml" <<'YAML'
x-archon-logging: &archon-logging
  driver: local
  options:
    max-size: "10m"
    max-file: "2"
services:
  broker:
    logging: *archon-logging
  datahub-actions:
    environment:
      METADATA_SERVICE_AUTH_ENABLED: "true"
      DATAHUB_SYSTEM_CLIENT_SECRET: ${DATAHUB_SYSTEM_CLIENT_SECRET}
    logging: *archon-logging
  datahub-frontend-react:
    environment:
      METADATA_SERVICE_AUTH_ENABLED: "true"
      DATAHUB_SYSTEM_CLIENT_SECRET: ${DATAHUB_SYSTEM_CLIENT_SECRET}
      DATAHUB_SECRET: ${DATAHUB_SECRET}
    logging: *archon-logging
  datahub-gms:
    environment:
      METADATA_SERVICE_AUTH_ENABLED: "true"
      METADATA_SERVICE_AUTHENTICATOR_EXCEPTIONS_ENABLED: "true"
      DATAHUB_SYSTEM_CLIENT_SECRET: ${DATAHUB_SYSTEM_CLIENT_SECRET}
      DATAHUB_TOKEN_SERVICE_SIGNING_KEY: ${DATAHUB_TOKEN_SERVICE_SIGNING_KEY}
      DATAHUB_TOKEN_SERVICE_SALT: ${DATAHUB_TOKEN_SERVICE_SALT}
      EBEAN_DATASOURCE_PASSWORD: ${ARCHON_MYSQL_PASSWORD}
      NEO4J_PASSWORD: ${ARCHON_NEO4J_PASSWORD}
    logging: *archon-logging
  datahub-upgrade:
    environment:
      EBEAN_DATASOURCE_PASSWORD: ${ARCHON_MYSQL_PASSWORD}
      NEO4J_PASSWORD: ${ARCHON_NEO4J_PASSWORD}
    logging: *archon-logging
  elasticsearch:
    logging: *archon-logging
  kafka-setup:
    logging: *archon-logging
  mysql:
    environment:
      MYSQL_PASSWORD: ${ARCHON_MYSQL_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${ARCHON_MYSQL_ROOT_PASSWORD}
    logging: *archon-logging
  neo4j:
    environment:
      NEO4J_AUTH: neo4j/${ARCHON_NEO4J_PASSWORD}
    logging: *archon-logging
  schema-registry:
    logging: *archon-logging
  zookeeper:
    logging: *archon-logging
YAML
chmod 0444 "${install_root}/datahub/docker-compose.archon.yml"

# JSON is valid Compose YAML. Every service uses the one previously resolved
# RepoDigest and declares pull_policy=never.
jq --sort-keys '
  {
    services: (
      .services |
      map({key:.service,value:{image:.resolvedReference,pull_policy:"never"}}) |
      from_entries
    )
  }
' "${resolved_manifest}" >"${install_root}/datahub/docker-compose.images.yml"
chmod 0444 "${install_root}/datahub/docker-compose.images.yml"

cat >/tmp/archon-compose-build.env <<'ENV'
HOME=/root
DATAHUB_VERSION=v1.6.0
DATAHUB_CONFLUENT_VERSION=7.9.2
DATAHUB_SEARCH_TAG=7.16.1
DATAHUB_MYSQL_VERSION=8.2
DATAHUB_SYSTEM_CLIENT_SECRET=build-only-not-runtime
DATAHUB_TOKEN_SERVICE_SIGNING_KEY=build-only-not-runtime
DATAHUB_TOKEN_SERVICE_SALT=build-only-not-runtime
DATAHUB_SECRET=build-only-not-runtime
ARCHON_MYSQL_PASSWORD=build-only-not-runtime
ARCHON_MYSQL_ROOT_PASSWORD=build-only-not-runtime
ARCHON_NEO4J_PASSWORD=build-only-not-runtime
ENV
compose=(
  docker compose --env-file /tmp/archon-compose-build.env
  -f "${install_root}/datahub/docker-compose.yml"
  -f "${install_root}/datahub/docker-compose.archon.yml"
  -f "${install_root}/datahub/docker-compose.images.yml"
)
"${compose[@]}" config --quiet

: >"${install_root}/image/datahub-images.txt"
while IFS=$'\t' read -r reference resolved image_id; do
  [[ -n "${reference}" && "${resolved}" == *@sha256:* ]]
  docker pull --quiet "${resolved}" >/dev/null
  test "$(docker image inspect --format '{{.Id}}' "${resolved}")" = "${image_id}"
  docker image inspect --format '{{json .RepoDigests}}' "${resolved}" |
    jq --exit-status --arg resolved "${resolved}" 'index($resolved) != null' >/dev/null
  docker image tag "${resolved}" "${reference}"
  printf '%s\t%s\n' "${reference}" "${resolved}" >>
    "${install_root}/image/datahub-images.txt"
done < <(
  jq -r '.images[] | [.declaredReference,.resolvedReference,.imageId] | @tsv' \
    "${resolved_manifest}"
)
test "$(wc -l <"${install_root}/image/datahub-images.txt")" -ge 8
chmod 0444 "${install_root}/image/datahub-images.txt"
datahub_images_sha="$(
  sha256sum "${install_root}/image/datahub-images.txt" | awk '{print $1}'
)"
readonly datahub_images_sha

mapfile -t configured_images < <("${compose[@]}" config --images | sort -u)
mapfile -t sealed_images < <(jq -r '.images[].resolvedReference' "${resolved_manifest}" | sort -u)
test "${#configured_images[@]}" = "${#sealed_images[@]}"
diff --unified <(printf '%s\n' "${sealed_images[@]}") \
  <(printf '%s\n' "${configured_images[@]}")

install -d -m 0755 "${install_root}/image/supply-chain"
cp -a "${supply_root}/." "${install_root}/image/supply-chain/"
# Produce a post-update OS SBOM and raw vulnerability evidence. The deploy gate
# rejects only actionable fixed HIGH/CRITICAL findings while retaining unfixed
# findings in JSON and SARIF for judge inspection.
readonly os_evidence="${install_root}/image/supply-chain/os"
install -d -m 0700 "${os_evidence}"
export TRIVY_CACHE_DIR="${staging}/trivy-cache"
trivy rootfs --scanners vuln --pkg-types os \
  --skip-dirs /var/lib/docker --skip-dirs /proc --skip-dirs /sys \
  --skip-dirs /dev --skip-dirs /run --format json \
  --output "${os_evidence}/trivy.json" /
trivy rootfs --scanners vuln --pkg-types os \
  --skip-dirs /var/lib/docker --skip-dirs /proc --skip-dirs /sys \
  --skip-dirs /dev --skip-dirs /run --format sarif \
  --output "${os_evidence}/trivy.sarif" /
trivy rootfs --scanners vuln --pkg-types os \
  --skip-dirs /var/lib/docker --skip-dirs /proc --skip-dirs /sys \
  --skip-dirs /dev --skip-dirs /run --format cyclonedx \
  --output "${os_evidence}/sbom.cdx.json" /
trivy rootfs --scanners vuln --pkg-types os \
  --skip-dirs /var/lib/docker --skip-dirs /proc --skip-dirs /sys \
  --skip-dirs /dev --skip-dirs /run --format spdx-json \
  --output "${os_evidence}/sbom.spdx.json" /
test -f "${TRIVY_CACHE_DIR}/db/metadata.json"
cp "${TRIVY_CACHE_DIR}/db/metadata.json" \
  "${os_evidence}/trivy-db-metadata.json"
jq --exit-status 'type == "object"' \
  "${os_evidence}/trivy-db-metadata.json" >/dev/null
jq --exit-status '
  [.Results[]?.Vulnerabilities[]? |
    select(.Severity == "HIGH" or .Severity == "CRITICAL") |
    select(.FixedVersion != null and .FixedVersion != "")] |
  length == 0
' "${os_evidence}/trivy.json" >/dev/null
jq --exit-status '.bomFormat == "CycloneDX" and (.components | type == "array")' \
  "${os_evidence}/sbom.cdx.json" >/dev/null
jq --exit-status '.spdxVersion | startswith("SPDX-")' \
  "${os_evidence}/sbom.spdx.json" >/dev/null
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort \
  >"${os_evidence}/installed-rpms.tsv"

set +e
dnf --refresh check-update --security >"${os_evidence}/dnf-security-check.txt" 2>&1
security_update_status=$?
set -e
if [[ "${security_update_status}" != "0" ]]; then
  if [[ "${security_update_status}" == "100" ]]; then
    echo "applicable AL2023 security updates remain after patching" >&2
  else
    echo "AL2023 security update verification failed" >&2
  fi
  exit 69
fi
jq -cnS \
  --arg baseAmiId "${ARCHON_BASE_AMI_ID}" \
  --arg checkedAt "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" '
    {
      schemaVersion:"archon.al2023-security-update-proof/v1",
      baseAmiId:$baseAmiId,
      command:"dnf --refresh check-update --security",
      exitCode:0,
      applicableSecurityUpdates:[],
      checkedAt:$checkedAt
    }
  ' >"${os_evidence}/security-update-proof.json"

# Remove the scanner, its DB, caches, and build-only package metadata before the
# AMI snapshot. Only reports and checksums remain.
rm -f -- /usr/local/bin/trivy "${staging}/tools/trivy"
rm -rf -- "${TRIVY_CACHE_DIR}" /root/.cache/trivy /var/cache/dnf
hash -r
test -z "$(command -v trivy || true)"
test ! -e "${TRIVY_CACHE_DIR}"
jq -cnS \
  --arg checkedAt "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" '
    {
      schemaVersion:"archon.ami-scanner-removal-proof/v1",
      trivyBinaryPresent:false,
      trivyDatabasePresent:false,
      checkedAt:$checkedAt
    }
  ' >"${os_evidence}/scanner-removal-proof.json"
find "${install_root}/image/supply-chain" -type d -exec chmod 0555 {} +
find "${install_root}/image/supply-chain" -type f -exec chmod 0444 {} +
(
  cd "${install_root}/image/supply-chain"
  find . -type f ! -name SHA256SUMS -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
)
chmod 0444 "${install_root}/image/supply-chain/SHA256SUMS"
cat >/etc/systemd/system/archon-datahub-core.service <<'UNIT'
[Unit]
Description=Archon ephemeral DataHub Core supervisor
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/etc/archon/datahub-core.env
ExecStart=/opt/archon/governed/.venv/bin/python /opt/archon/core/datahub_core_bootstrap.py
Restart=no
TimeoutStartSec=25min
TimeoutStopSec=4min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl disable archon-datahub-core.service || true
systemctl disable sshd.service || true

supply_chain_sha="$(
  sha256sum "${install_root}/image/supply-chain/SHA256SUMS" | awk '{print $1}'
)"
readonly supply_chain_sha
os_cdx_sha="$(sha256sum "${os_evidence}/sbom.cdx.json" | awk '{print $1}')"
readonly os_cdx_sha
os_spdx_sha="$(sha256sum "${os_evidence}/sbom.spdx.json" | awk '{print $1}')"
readonly os_spdx_sha
os_trivy_db_sha="$(sha256sum "${os_evidence}/trivy-db-metadata.json" | awk '{print $1}')"
readonly os_trivy_db_sha
jq -cnS \
  --arg schemaVersion "archon.datahub-core-ami-manifest/v2" \
  --arg releaseSha "${ARCHON_RELEASE_SHA}" \
  --arg baseAmiId "${ARCHON_BASE_AMI_ID}" \
  --arg companionSourceSha "${ARCHON_COMPANION_SOURCE_SHA}" \
  --arg generation "${ARCHON_GENERATION}" \
  --arg capabilityDigest "${ARCHON_CAPABILITY_DIGEST}" \
  --arg resolvedImagesDigest "${ARCHON_IMAGE_MANIFEST_DIGEST}" \
  --arg companionImageId "${companion_image_id}" \
  --arg companionArchiveSha256 "${archive_sha}" \
  --arg dataHubComposeSha256 "${compose_sha256}" \
  --arg dataHubHardenedComposeSha256 "${hardened_compose_sha}" \
  --arg dataHubImagesSha256 "${datahub_images_sha}" \
  --arg supplyChainChecksumsSha256 "${supply_chain_sha}" \
  --arg osCycloneDxSha256 "${os_cdx_sha}" \
  --arg osSpdxSha256 "${os_spdx_sha}" \
  --arg osTrivyDbMetadataSha256 "${os_trivy_db_sha}" \
  --arg dockerComposeVersion "${compose_version}" '
    {
      schemaVersion: $schemaVersion,
      releaseSha: $releaseSha,
      baseAmiId: $baseAmiId,
      companionSourceSha: $companionSourceSha,
      generation: $generation,
      capabilityDigest: $capabilityDigest,
      resolvedImagesDigest: $resolvedImagesDigest,
      companionImageId: $companionImageId,
      companionArchiveSha256: $companionArchiveSha256,
      dataHubComposeSha256: $dataHubComposeSha256,
      dataHubHardenedComposeSha256: $dataHubHardenedComposeSha256,
      dataHubImagesSha256: $dataHubImagesSha256,
      supplyChainChecksumsSha256: $supplyChainChecksumsSha256,
      osSbom: {
        cycloneDxSha256: $osCycloneDxSha256,
        spdxSha256: $osSpdxSha256
      },
      osScanner: {
        name: "Trivy",
        version: "0.70.0",
        databaseMetadataSha256: $osTrivyDbMetadataSha256
      },
      dockerComposeVersion: $dockerComposeVersion,
      runtimePullsAllowed: false,
      composePullPolicy: "never",
      allCoreImagesDigestPinned: true,
      rawTrivyFindingsRetained: true,
      unfixedFindingsRetained: true,
      vexGenerated: false,
      al2023Patched: true,
      applicableSecurityUpdates: 0,
      scannerBinaryPresent: false,
      scannerDatabasePresent: false,
      analyticsOauthMasterKeyRequired: true,
      plaintextAnalyticsTokenAtRestAllowed: false,
      mutationAuthorization: "KMS_ECDSA_SHA_256",
      staticArchonCredentialsPresent: false,
      vendorLoopbackBootstrapCredentialRequired: true,
      generatedDatabasePresent: false
    }
  ' >"${install_root}/image/image-manifest.json"
chmod 0444 "${install_root}/image/image-manifest.json"

test ! -e "${install_root}/core/demo/archon-demo.sqlite"
test ! -e /run/archon/datahub-credentials.json
if grep -R --line-number --fixed-strings \
  "core-loopback-readonly" "${install_root}"; then
  echo "static credential marker found in AMI" >&2
  exit 68
fi
rm -f /root/.bash_history /tmp/archon-compose-build.env
docker builder prune --all --force >/dev/null

# Packer downloads this non-secret projection and deletes it in the following
# provisioner before the snapshot is finalized.
tar --create --gzip \
  --file /tmp/archon-datahub-core-bake-evidence.tar.gz \
  --directory "${install_root}/image" \
  --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  image-manifest.json datahub-images.txt datahub-core-image.lock.json supply-chain
test -s /tmp/archon-datahub-core-bake-evidence.tar.gz
sync