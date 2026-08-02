#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

active=(
  infra/aws/bin/archon.ts
  infra/aws/lib/archon-judge-stack.ts
  infra/aws/lib/judge-cloud-runtime.ts
  infra/aws/lib/ephemeral-datahub-core-stack.ts
  .github/workflows/deploy.yml
  scripts/observe-aws-live-runtime.sh
)

for path in "${active[@]}"; do
  test -f "${path}"
done

if grep -Eiq 'AWS::ECS|Fargate|VpcLink|NetworkLoadBalancer|AWS::EKS' \
  "${active[@]}"; then
  echo "::error::retired always-on network topology returned to an active path" >&2
  exit 1
fi

grep -Fq 'VpcConfig' infra/aws/policy/archon.guard
grep -Fq 'NetworkInterfaces[*].AssociatePublicIpAddress == false' \
  infra/aws/policy/archon.guard
grep -Fq 'assert_retired_stack_absent "Archon-${ARCHON_STAGE}"' \
  scripts/observe-aws-live-runtime.sh
grep -Fq 'assert_retired_stack_absent "Archon-Registry"' \
  scripts/observe-aws-live-runtime.sh
grep -Fq 'legacyAlwaysOnRuntimeAbsent:$legacyAlwaysOnRuntimeAbsent' \
  scripts/observe-aws-live-runtime.sh
if grep -Fq 'legacyAlwaysOnRuntimeAbsent:true' \
  scripts/observe-aws-live-runtime.sh; then
  echo "::error::Legacy-runtime absence must be observed, not hardcoded" >&2
  exit 1
fi
grep -Fq 'CloudFrontDomainName' .github/workflows/deploy.yml
grep -Fq 'DynamoDbPrefixListId' .github/workflows/deploy.yml
