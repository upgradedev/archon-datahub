#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Lock-candidate set digests are computed only by CI/CD" >&2
  exit 1
fi
if [[ "$#" -ne 0 ]]; then
  echo "usage: compute-lock-candidate-set-digest.sh" >&2
  exit 1
fi

required_files=(
  package.json
  package-lock.json
  infra/aws/package.json
  infra/aws/package-lock.json
  web/package.json
  web/package-lock.json
)
for file in "${required_files[@]}"; do
  test -f "${file}"
  test ! -L "${file}"
done

root_manifest_sha="$(sha256sum package.json | awk '{print $1}')"
root_lock_sha="$(sha256sum package-lock.json | awk '{print $1}')"
infra_manifest_sha="$(sha256sum infra/aws/package.json | awk '{print $1}')"
infra_lock_sha="$(sha256sum infra/aws/package-lock.json | awk '{print $1}')"
web_manifest_sha="$(sha256sum web/package.json | awk '{print $1}')"
web_lock_sha="$(sha256sum web/package-lock.json | awk '{print $1}')"

jq -cnS \
  --arg rootManifestSha256 "${root_manifest_sha}" \
  --arg rootLockSha256 "${root_lock_sha}" \
  --arg infraManifestSha256 "${infra_manifest_sha}" \
  --arg infraLockSha256 "${infra_lock_sha}" \
  --arg webManifestSha256 "${web_manifest_sha}" \
  --arg webLockSha256 "${web_lock_sha}" \
  '{
    schemaVersion: "archon.lock-candidate-set/v1",
    root: {
      packageJsonSha256: $rootManifestSha256,
      packageLockSha256: $rootLockSha256
    },
    infrastructure: {
      packageJsonSha256: $infraManifestSha256,
      packageLockSha256: $infraLockSha256
    },
    web: {
      packageJsonSha256: $webManifestSha256,
      packageLockSha256: $webLockSha256
    }
  }' |
  sha256sum |
  awk '{print $1}'
