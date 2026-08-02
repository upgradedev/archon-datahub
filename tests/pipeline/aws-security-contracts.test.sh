#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

required=(
  infra/aws/lib/archon-edge-stack.ts
  infra/aws/lib/ephemeral-datahub-core-stack.ts
  infra/aws/lib/archon-judge-stack.ts
  infra/aws/lib/judge-cloud-runtime.ts
  infra/aws/lib/judge-contract.ts
  infra/aws/lib/judge-edge-api.ts
  infra/aws/policy/archon.guard
  .github/workflows/ci.yml
  .github/workflows/deploy.yml
  .github/workflows/supply-chain.yml
  .github/workflows/availability.yml
  .github/workflows/production-posture.yml
  .github/workflows/production-paging-test.yml
  scripts/observe-aws-live-runtime.sh
)
for path in "${required[@]}"; do test -f "${path}"; done

test ! -e infra/aws/lib/archon-stack.ts
test ! -e infra/aws/lib/archon-registry-stack.ts
test ! -e infra/aws/test/archon-stack.test.ts

bash scripts/validate-aws-network-contract.sh

grep -Fq 'retired_always_on_topology_is_absent' infra/aws/policy/archon.guard
grep -Fq 'core_is_zero_idle_single_host' infra/aws/policy/archon.guard
grep -Fq 'lambdas_are_bounded_observable_and_not_vpc_attached' \
  infra/aws/policy/archon.guard
grep -Fq 'actions/attest@' .github/workflows/deploy.yml
grep -Fq 'gh attestation verify' .github/workflows/deploy.yml
grep -Fq 'CloudRuntimeReleaseDigest' .github/workflows/deploy.yml
grep -Fq 'DataHubCoreImageManifestDigest' .github/workflows/deploy.yml
grep -Fq 'SpaArtifactSha256=${SPA_TAR_SHA256}' .github/workflows/deploy.yml
grep -Fq 'LambdaArtifactSha256=${LAMBDA_TAR_SHA256}' .github/workflows/deploy.yml
grep -Fq 'for name in control runtime-control' .github/workflows/ci.yml
grep -Fq 'control|control/*|runtime-control|runtime-control/*' \
  .github/workflows/supply-chain.yml
grep -Fq 'cognito.OAuthScope.PROFILE' infra/aws/lib/judge-edge-api.ts
if grep -nE -- 'RetentionDays\.ONE_MONTH|sampledRequestsEnabled: true' \
  infra/aws/lib/archon-edge-stack.ts \
  infra/aws/lib/ephemeral-datahub-core-stack.ts \
  infra/aws/lib/archon-judge-stack.ts \
  infra/aws/lib/judge-cloud-runtime.ts \
  infra/aws/lib/judge-contract.ts \
  infra/aws/lib/judge-edge-api.ts; then
  echo "::error::Guard-controlled logs and WAF sampling drifted" >&2
  exit 1
fi
grep -Fq 'EXPECT_CORE_IDLE: "true"' .github/workflows/availability.yml
grep -Fq 'detect-stack-drift' .github/workflows/production-posture.yml
grep -Fq 'CloudWatch->SNS(KMS)->SQS(KMS)' \
  .github/workflows/production-paging-test.yml

codex_security_pattern='codex[-._ ]?security'
for positive_control_plane_reference in \
  'uses: openai/codex-security@pinned-commit' \
  'run: codex.security scan' \
  'run: codex_security scan' \
  'name: Codex Security'; do
  if ! LC_ALL=C grep -qEi -- "${codex_security_pattern}" \
    <<<"${positive_control_plane_reference}"; then
    echo "::error::Codex Security guard failed its positive self-test" >&2
    exit 1
  fi
done
for negative_control_plane_reference in \
  'name: AWS security contracts' \
  'run: npm run security'; do
  if LC_ALL=C grep -qEi -- "${codex_security_pattern}" \
    <<<"${negative_control_plane_reference}"; then
    echo "::error::Codex Security guard failed its negative self-test" >&2
    exit 1
  fi
done

codex_security_scan_status=0
if codex_security_hits="$(
  LC_ALL=C grep -rInEi -- "${codex_security_pattern}" \
    .github/workflows infra/aws/bin infra/aws/lib infra/aws/policy scripts
)"; then
  codex_security_scan_status=0
else
  codex_security_scan_status=$?
fi
if ((codex_security_scan_status > 1)); then
  echo "::error::Codex Security guard could not inspect the control plane" >&2
  exit 1
fi

# verify-contrib enforces one documentation-only negative assertion. Allow
# only that exact reviewed line; every other executable reference still fails.
allowed_verify_contrib_assertions=0
codex_security_violations=()
if [[ -n "${codex_security_hits}" ]]; then
  while IFS= read -r codex_security_hit; do
    codex_security_hit_path="${codex_security_hit%%:*}"
    codex_security_hit_rest="${codex_security_hit#*:}"
    codex_security_hit_line="${codex_security_hit_rest%%:*}"
    codex_security_hit_text="${codex_security_hit_rest#*:}"
    if [[ "${codex_security_hit_path}" == "scripts/verify-contrib.mjs" &&
      "${codex_security_hit_line}" =~ ^[0-9]+$ &&
      "${codex_security_hit_text}" == \
        '  "does not depend on Codex Security",' ]]; then
      allowed_verify_contrib_assertions=$((allowed_verify_contrib_assertions + 1))
      continue
    fi
    codex_security_violations+=("${codex_security_hit}")
  done <<<"${codex_security_hits}"
fi
if ((allowed_verify_contrib_assertions != 1)); then
  echo "::error::The reviewed verify-contrib negative assertion drifted" >&2
  exit 1
fi
if ((${#codex_security_violations[@]} > 0)); then
  printf '%s\n' "${codex_security_violations[@]}"
  echo "::error::Codex Security must not be part of the security control plane" >&2
  exit 1
fi
