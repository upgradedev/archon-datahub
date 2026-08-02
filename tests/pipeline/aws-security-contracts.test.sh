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
if rg -n 'RetentionDays\.ONE_MONTH|sampledRequestsEnabled: true' \
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

if rg -n --glob '!aws-security-contracts.test.sh' \
  'codex.security|Codex Security' \
  .github/workflows infra/aws/bin infra/aws/lib infra/aws/policy scripts tests/pipeline; then
  echo "::error::Codex Security must not be part of the security control plane" >&2
  exit 1
fi
