#!/usr/bin/env bash
set -euo pipefail

# Temporary, CI-only repair for GHSA-mh99-v99m-4gvg. aws-cdk-lib@2.262.1
# bundles brace-expansion@5.0.7, so npm overrides cannot replace that nested
# package. This script admits only that exact immutable bundle, replaces it
# with the integrity-pinned fixed release, validates the installed API, and
# emits a content-addressed receipt for the subsequent audit gate.

if (( $# != 1 )); then
  echo "usage: patch-cdk-brace-expansion.sh <infra-directory>" >&2
  exit 64
fi

if [[ "${CI:-}" != "true" || "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "This compensating control may run only in GitHub Actions CI" >&2
  exit 78
fi

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

readonly advisory="GHSA-mh99-v99m-4gvg"
readonly expected_cdk_version="2.262.1"
readonly expected_cdk_url="https://registry.npmjs.org/aws-cdk-lib/-/aws-cdk-lib-2.262.1.tgz"
readonly expected_cdk_integrity="sha512-B6YP4r6ojUZCDhl+qBu/CrWzcipR8sIgshcqYvgw013sghPXmVkYdJ3yuI9+DKML3YLSjQrHy1nGJs+Nqq7JCg=="
readonly vulnerable_version="5.0.7"
readonly patched_version="5.0.8"
readonly tarball_url="https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.8.tgz"
readonly tarball_integrity="sha512-JZyDyq3D4AUifKTPOB7DELf6XsB3WdPuNxCtob1vFXPsSXhdAiHBWJ/tJ8HAc9aH84BK+5JFZLNkJKx3G9kzQg=="

readonly workspace="$(realpath -e "${GITHUB_WORKSPACE}")"
readonly infra_dir="$(realpath -e "$1")"
readonly expected_infra_dir="${workspace}/infra/aws"
if [[ "${infra_dir}" != "${expected_infra_dir}" ]]; then
  echo "The compensating control is bound to ${expected_infra_dir}" >&2
  exit 65
fi

readonly lock_file="${infra_dir}/package-lock.json"
readonly target="${infra_dir}/node_modules/aws-cdk-lib/node_modules/brace-expansion"
readonly expected_target="${expected_infra_dir}/node_modules/aws-cdk-lib/node_modules/brace-expansion"
test -f "${lock_file}"
test ! -L "${lock_file}"
test -d "${target}"
test ! -L "${target}"
if [[ "$(realpath -e "${target}")" != "${expected_target}" ]]; then
  echo "The vulnerable bundled-package path did not resolve exactly" >&2
  exit 65
fi
if find "${target}" -type l -print -quit | grep -q .; then
  echo "The vulnerable bundled package must not contain symlinks" >&2
  exit 65
fi

LOCK_FILE="${lock_file}" \
EXPECTED_CDK_VERSION="${expected_cdk_version}" \
EXPECTED_CDK_URL="${expected_cdk_url}" \
EXPECTED_CDK_INTEGRITY="${expected_cdk_integrity}" \
VULNERABLE_VERSION="${vulnerable_version}" \
node <<'NODE'
const lock = require(process.env.LOCK_FILE);
const root = lock.packages?.[""];
const cdk = lock.packages?.["node_modules/aws-cdk-lib"];
const vulnerable =
  lock.packages?.[
    "node_modules/aws-cdk-lib/node_modules/brace-expansion"
  ];

if (
  lock.lockfileVersion !== 3 ||
  root?.dependencies?.["aws-cdk-lib"] !== process.env.EXPECTED_CDK_VERSION ||
  cdk?.version !== process.env.EXPECTED_CDK_VERSION ||
  cdk?.resolved !== process.env.EXPECTED_CDK_URL ||
  cdk?.integrity !== process.env.EXPECTED_CDK_INTEGRITY ||
  vulnerable?.version !== process.env.VULNERABLE_VERSION ||
  vulnerable?.inBundle !== true
) {
  throw new Error("The exact reviewed aws-cdk-lib bundled dependency is absent");
}
NODE

TARGET="${target}" \
VULNERABLE_VERSION="${vulnerable_version}" \
node <<'NODE'
const pkg = require(`${process.env.TARGET}/package.json`);
if (
  pkg.name !== "brace-expansion" ||
  pkg.version !== process.env.VULNERABLE_VERSION
) {
  throw new Error("The installed vulnerable package differs from the lock");
}
NODE

umask 077
readonly work_dir="$(mktemp -d "${RUNNER_TEMP}/archon-cdk-hotpatch.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
readonly archive="${work_dir}/brace-expansion.tgz"
readonly extracted="${work_dir}/extracted"
mkdir -p "${extracted}"

curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --silent \
  --show-error \
  --location \
  --max-redirs 3 \
  --retry 3 \
  --retry-all-errors \
  --connect-timeout 15 \
  --max-time 120 \
  --output "${archive}" \
  "${tarball_url}"

readonly archive_size="$(stat -c '%s' "${archive}")"
(( archive_size > 0 && archive_size <= 131072 ))
readonly actual_integrity="sha512-$(openssl dgst -sha512 -binary "${archive}" | openssl base64 -A)"
if [[ "${actual_integrity}" != "${tarball_integrity}" ]]; then
  echo "The fixed brace-expansion tarball failed its SHA-512 integrity check" >&2
  exit 1
fi

mapfile -t archive_entries < <(tar --list --gzip --file "${archive}")
(( ${#archive_entries[@]} >= 3 && ${#archive_entries[@]} <= 64 ))
for entry in "${archive_entries[@]}"; do
  if [[ "${entry}" == /* || "${entry}" =~ (^|/)\.\.(/|$) ]]; then
    echo "The fixed-package archive contains an unsafe path" >&2
    exit 1
  fi
  case "${entry}" in
    package | package/ | package/*) ;;
    *)
      echo "The fixed-package archive escaped its package root" >&2
      exit 1
      ;;
  esac
done
if tar --list --verbose --gzip --file "${archive}" |
  awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { found = 1 } END { exit found ? 0 : 1 }'; then
  echo "The fixed-package archive may contain only files and directories" >&2
  exit 1
fi

tar \
  --extract \
  --gzip \
  --file "${archive}" \
  --directory "${extracted}" \
  --no-same-owner \
  --no-same-permissions
test -d "${extracted}/package"
test ! -L "${extracted}/package"
if find "${extracted}/package" \( ! -type f -a ! -type d \) -print -quit |
  grep -q .; then
  echo "The extracted fixed package may contain only regular files and directories" >&2
  exit 1
fi
readonly extracted_files="$(find "${extracted}/package" -type f | wc -l)"
readonly extracted_bytes="$(du -sb "${extracted}/package" | cut -f1)"
(( extracted_files >= 3 && extracted_files <= 64 ))
(( extracted_bytes > 0 && extracted_bytes <= 262144 ))

PACKAGE_ROOT="${extracted}/package" \
PATCHED_VERSION="${patched_version}" \
node <<'NODE'
const pkg = require(`${process.env.PACKAGE_ROOT}/package.json`);
if (
  pkg.name !== "brace-expansion" ||
  pkg.version !== process.env.PATCHED_VERSION
) {
  throw new Error("The integrity-pinned package has unexpected identity");
}
NODE

# The exact target was resolved and prefix-checked above. No source file is
# modified: only the ephemeral npm installation on this CI runner is repaired.
rm -rf -- "${target}"
mkdir -p "${target}"
cp -a "${extracted}/package/." "${target}/"
chmod -R go-w "${target}"

test -d "${target}"
test ! -L "${target}"
if find "${target}" \( ! -type f -a ! -type d \) -print -quit | grep -q .; then
  echo "The repaired package may contain only regular files and directories" >&2
  exit 1
fi

TARGET="${target}" \
PATCHED_VERSION="${patched_version}" \
node <<'NODE'
const assert = require("node:assert/strict");
const pkg = require(`${process.env.TARGET}/package.json`);
const { expand } = require(process.env.TARGET);

assert.equal(pkg.name, "brace-expansion");
assert.equal(pkg.version, process.env.PATCHED_VERSION);
assert.deepEqual(expand("x{a,b}y"), ["xay", "xby"]);
NODE

readonly tree_digest="$(
  cd "${target}"
  find . -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum |
    sha256sum |
    cut -d' ' -f1
)"
[[ "${tree_digest}" =~ ^[0-9a-f]{64}$ ]]

readonly evidence_dir="${RUNNER_TEMP}/cdk-brace-expansion-compensation"
mkdir -p "${evidence_dir}"
readonly receipt="${evidence_dir}/patch-receipt.json"
readonly cdk_integrity="$(
  LOCK_FILE="${lock_file}" node -e \
    'process.stdout.write(require(process.env.LOCK_FILE).packages["node_modules/aws-cdk-lib"].integrity)'
)"

jq -nS \
  --arg advisory "${advisory}" \
  --arg cdkVersion "${expected_cdk_version}" \
  --arg cdkIntegrity "${cdk_integrity}" \
  --arg path "node_modules/aws-cdk-lib/node_modules/brace-expansion" \
  --arg vulnerableVersion "${vulnerable_version}" \
  --arg patchedVersion "${patched_version}" \
  --arg tarballUrl "${tarball_url}" \
  --arg tarballIntegrity "${tarball_integrity}" \
  --arg treeSha256 "${tree_digest}" \
  '{
    schemaVersion: 1,
    advisory: $advisory,
    scope: {
      cdkPackage: "aws-cdk-lib",
      cdkVersion: $cdkVersion,
      cdkIntegrity: $cdkIntegrity,
      bundledPath: $path,
      vulnerableVersion: $vulnerableVersion
    },
    replacement: {
      package: "brace-expansion",
      version: $patchedVersion,
      tarballUrl: $tarballUrl,
      tarballIntegrity: $tarballIntegrity,
      installedTreeSha256: $treeSha256
    },
    enforcement: {
      ciOnly: true,
      sourceTreeModified: false,
      exactPathOnly: true
    }
  }' >"${receipt}"

test -s "${receipt}"
test ! -L "${receipt}"
jq --exit-status '.schemaVersion == 1' "${receipt}" >/dev/null
echo "Applied and sealed the exact ${advisory} CI compensating control"
