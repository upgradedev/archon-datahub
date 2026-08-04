#!/usr/bin/env bash
set -euo pipefail

# Fail-closed npm-audit gate for the single aws-cdk-lib bundled dependency
# repaired by patch-cdk-brace-expansion.sh. This is intentionally narrower than
# an npm audit allow-list: exact report shape, path, versions, lock metadata,
# patched filesystem tree, and patch receipt must all agree.

if (( $# != 1 )); then
  echo "usage: verify-cdk-npm-audit-compensation.sh <infra-directory>" >&2
  exit 64
fi

if [[ "${CI:-}" != "true" || "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "This compensating audit gate may run only in GitHub Actions CI" >&2
  exit 78
fi

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

readonly workspace="$(realpath -e "${GITHUB_WORKSPACE}")"
readonly infra_dir="$(realpath -e "$1")"
readonly expected_infra_dir="${workspace}/infra/aws"
if [[ "${infra_dir}" != "${expected_infra_dir}" ]]; then
  echo "The compensating audit gate is bound to ${expected_infra_dir}" >&2
  exit 65
fi

# The immutable bundled lock entry (5.0.7) matches two published advisories.
# Both are compensated by the same on-disk repair to the patched release.
readonly advisory="GHSA-mh99-v99m-4gvg"
readonly advisory_secondary="GHSA-rgw5-rvv9-x895"
readonly expected_cdk_version="2.262.1"
readonly expected_cdk_url="https://registry.npmjs.org/aws-cdk-lib/-/aws-cdk-lib-2.262.1.tgz"
readonly expected_cdk_integrity="sha512-B6YP4r6ojUZCDhl+qBu/CrWzcipR8sIgshcqYvgw013sghPXmVkYdJ3yuI9+DKML3YLSjQrHy1nGJs+Nqq7JCg=="
readonly vulnerable_version="5.0.7"
readonly patched_version="5.0.9"
readonly bundled_path="node_modules/aws-cdk-lib/node_modules/brace-expansion"
readonly tarball_url="https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.9.tgz"
readonly tarball_integrity="sha512-ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg=="
readonly lock_file="${infra_dir}/package-lock.json"
readonly target="${infra_dir}/${bundled_path}"
readonly evidence_dir="${RUNNER_TEMP}/cdk-brace-expansion-compensation"
readonly patch_receipt="${evidence_dir}/patch-receipt.json"
test -f "${lock_file}"
test ! -L "${lock_file}"
test -d "${target}"
test ! -L "${target}"
test -f "${patch_receipt}"
test ! -L "${patch_receipt}"
if [[ "$(realpath -e "${target}")" != "${expected_infra_dir}/${bundled_path}" ]]; then
  echo "The repaired bundled-package path did not resolve exactly" >&2
  exit 65
fi
if find "${target}" \( ! -type f -a ! -type d \) -print -quit | grep -q .; then
  echo "The repaired package may contain only regular files and directories" >&2
  exit 1
fi

readonly tree_digest="$(
  cd "${target}"
  find . -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum |
    sha256sum |
    cut -d' ' -f1
)"
[[ "${tree_digest}" =~ ^[0-9a-f]{64}$ ]]

readonly attempts="${NPM_AUDIT_ATTEMPTS:-4}"
readonly initial_backoff="${NPM_AUDIT_INITIAL_BACKOFF_SECONDS:-10}"
[[ "${attempts}" =~ ^[1-9][0-9]?$ ]]
[[ "${initial_backoff}" =~ ^[1-9][0-9]?$ ]]
(( attempts <= 8 ))
(( initial_backoff <= 60 ))

umask 077
readonly work_dir="$(mktemp -d "${RUNNER_TEMP}/archon-cdk-audit.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT

backoff="${initial_backoff}"
for (( attempt = 1; attempt <= attempts; attempt += 1 )); do
  report="${work_dir}/attempt-${attempt}.json"
  set +e
  (
    cd "${infra_dir}"
    npm audit --audit-level=high --json
  ) >"${report}"
  status=$?
  set -e

  test -f "${report}"
  test ! -L "${report}"
  cat "${report}"

  if (( status == 0 )); then
    echo "::error::The immutable vulnerable lock no longer produced its expected advisory; remove or re-review the compensation"
    exit 1
  fi

  set +e
  REPORT="${report}" \
  RECEIPT="${patch_receipt}" \
  LOCK_FILE="${lock_file}" \
  TARGET="${target}" \
  TREE_DIGEST="${tree_digest}" \
  ADVISORY="${advisory}" \
  ADVISORY_SECONDARY="${advisory_secondary}" \
  EXPECTED_CDK_VERSION="${expected_cdk_version}" \
  EXPECTED_CDK_URL="${expected_cdk_url}" \
  EXPECTED_CDK_INTEGRITY="${expected_cdk_integrity}" \
  VULNERABLE_VERSION="${vulnerable_version}" \
  PATCHED_VERSION="${patched_version}" \
  BUNDLED_PATH="${bundled_path}" \
  TARBALL_URL="${tarball_url}" \
  TARBALL_INTEGRITY="${tarball_integrity}" \
  AUDIT_STATUS="${status}" \
  node <<'NODE'
const assert = require("node:assert/strict");
const report = require(process.env.REPORT);
const receipt = require(process.env.RECEIPT);
const lock = require(process.env.LOCK_FILE);
const installed = require(`${process.env.TARGET}/package.json`);
const vulnerabilities = report.metadata?.vulnerabilities;
const finding = report.vulnerabilities?.["brace-expansion"];
const cdk = lock.packages?.["node_modules/aws-cdk-lib"];
const vulnerable =
  lock.packages?.[
    "node_modules/aws-cdk-lib/node_modules/brace-expansion"
  ];

assert.equal(Number(process.env.AUDIT_STATUS), 1);
assert.equal(report.auditReportVersion, 2);
assert.deepEqual(Object.keys(report.vulnerabilities ?? {}), [
  "brace-expansion",
]);
assert.deepEqual(
  {
    info: vulnerabilities?.info,
    low: vulnerabilities?.low,
    moderate: vulnerabilities?.moderate,
    high: vulnerabilities?.high,
    critical: vulnerabilities?.critical,
    total: vulnerabilities?.total,
  },
  { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 }
);
assert.equal(finding.name, "brace-expansion");
assert.equal(finding.severity, "high");
assert.equal(finding.isDirect, false);
assert.deepEqual(finding.effects, []);
assert.deepEqual(finding.nodes, [process.env.BUNDLED_PATH]);

// One immutable lock entry can match several published advisories over time, so
// the gate checks membership rather than a fixed count: EVERY advisory reported
// on the bundled path must be one we have reviewed and compensated, and an
// unknown one still fails closed. npm's human-readable range prose is
// deliberately not asserted -- it is presentation, not a security property, and
// pinning it made a newly published advisory look like a contract breach.
const reviewed = new Set(
  [process.env.ADVISORY, process.env.ADVISORY_SECONDARY]
    .filter(Boolean)
    .map((id) => `https://github.com/advisories/${id}`)
);
assert.ok(
  Array.isArray(finding.via) && finding.via.length >= 1,
  "expected at least one advisory on the bundled path"
);
const seen = new Set();
for (const entry of finding.via) {
  assert.equal(entry.name, "brace-expansion");
  assert.equal(entry.dependency, "brace-expansion");
  assert.equal(entry.severity, "high");
  assert.ok(
    reviewed.has(entry.url),
    `uncompensated advisory on the bundled path: ${entry.url}`
  );
  seen.add(entry.url);
}
assert.equal(seen.size, finding.via.length, "duplicate advisory entries");

assert.equal(cdk.version, process.env.EXPECTED_CDK_VERSION);
assert.equal(cdk.resolved, process.env.EXPECTED_CDK_URL);
assert.equal(cdk.integrity, process.env.EXPECTED_CDK_INTEGRITY);
assert.equal(vulnerable.version, process.env.VULNERABLE_VERSION);
assert.equal(vulnerable.inBundle, true);
assert.equal(installed.name, "brace-expansion");
assert.equal(installed.version, process.env.PATCHED_VERSION);

assert.equal(receipt.schemaVersion, 1);
assert.equal(receipt.advisory, process.env.ADVISORY);
assert.deepEqual(receipt.scope, {
  cdkPackage: "aws-cdk-lib",
  cdkVersion: process.env.EXPECTED_CDK_VERSION,
  cdkIntegrity: cdk.integrity,
  bundledPath: process.env.BUNDLED_PATH,
  vulnerableVersion: process.env.VULNERABLE_VERSION,
});
assert.equal(receipt.replacement.package, "brace-expansion");
assert.equal(receipt.replacement.version, process.env.PATCHED_VERSION);
assert.equal(receipt.replacement.tarballUrl, process.env.TARBALL_URL);
assert.equal(
  receipt.replacement.tarballIntegrity,
  process.env.TARBALL_INTEGRITY
);
assert.equal(
  receipt.replacement.installedTreeSha256,
  process.env.TREE_DIGEST
);
assert.deepEqual(receipt.enforcement, {
  ciOnly: true,
  sourceTreeModified: false,
  exactPathOnly: true,
});
NODE
  validation_status=$?
  set -e

  if (( validation_status == 0 )); then
    readonly final_report="${evidence_dir}/audit-report.json"
    readonly audit_receipt="${evidence_dir}/audit-compensation.json"
    install -m 0600 "${report}" "${final_report}"
    readonly report_digest="$(sha256sum "${final_report}" | cut -d' ' -f1)"
    readonly patch_receipt_digest="$(sha256sum "${patch_receipt}" | cut -d' ' -f1)"
    jq -nS \
      --arg advisory "${advisory}" \
      --arg bundledPath "${bundled_path}" \
      --arg reportSha256 "${report_digest}" \
      --arg patchReceiptSha256 "${patch_receipt_digest}" \
      --arg installedTreeSha256 "${tree_digest}" \
      '{
        schemaVersion: 1,
        decision: "exact-compensated-advisory",
        advisory: $advisory,
        bundledPath: $bundledPath,
        reportSha256: $reportSha256,
        patchReceiptSha256: $patchReceiptSha256,
        installedTreeSha256: $installedTreeSha256,
        otherHighOrCritical: 0
      }' >"${audit_receipt}"
    (
      cd "${evidence_dir}"
      sha256sum \
        audit-compensation.json \
        audit-report.json \
        patch-receipt.json >SHA256SUMS
      sha256sum --check --strict SHA256SUMS
    )
    echo "Accepted only the fully compensated ${advisory} bundled-path finding"
    exit 0
  fi

  if jq -e '
      (
        (.metadata.vulnerabilities.high // 0) > 0 or
        (.metadata.vulnerabilities.critical // 0) > 0
      ) or
      any(
        .vulnerabilities[]?;
        .severity == "high" or .severity == "critical"
      )
    ' "${report}" >/dev/null 2>&1; then
    echo "::error::npm audit differs from the one exact compensated advisory"
    exit "${status}"
  fi

  if (( attempt == attempts )); then
    echo "::error::npm audit did not return trustworthy evidence after ${attempts} attempts"
    exit "${status}"
  fi

  echo "::warning::npm advisory service attempt ${attempt}/${attempts} failed; retrying in ${backoff}s"
  sleep "${backoff}"
  backoff=$(( backoff * 2 ))
  if (( backoff > 60 )); then
    backoff=60
  fi
done

exit 1
