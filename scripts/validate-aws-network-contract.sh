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
grep -Fq 'legacyAlwaysOnRuntimeAbsent:true' \
  scripts/observe-aws-live-runtime.sh
grep -Fq 'CloudFrontDomainName' .github/workflows/deploy.yml
grep -Fq 'DynamoDbPrefixListId' .github/workflows/deploy.yml
