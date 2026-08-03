import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path: string): string =>
  readFileSync(new URL("../../" + path, import.meta.url), "utf8");

const workflow = read(".github/workflows/governed-canary.yml");
const recovery = read(".github/workflows/governed-canary-recovery.yml");
const credentials = read("scripts/load-datahub-cloud-canary-credentials.sh");
const driver = read("scripts/governed-canary.ts");
const journey = read("web/e2e/live-judge-journey.live.spec.ts");
const roles = read("infra/aws/foundation/governed-canary-roles.yml");
const deploy = read(".github/workflows/deploy.yml");
const operations = read(".github/workflows/submission-operations.yml");

const section = (source: string, start: string, end?: string): string => {
  const from = source.indexOf(start);
  assert.notEqual(from, -1, "missing section " + start);
  const to = end ? source.indexOf(end, from + start.length) : source.length;
  assert.notEqual(to, -1, "missing section terminator " + end);
  return source.slice(from, to);
};

test("governed canary consumes only current lean deployment evidence and Judge runtime", () => {
  assert.match(workflow, /^name: Governed DataHub Cloud canary v2$/m);
  assert.match(workflow, /^permissions: \{\}$/m);
  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.doesNotMatch(workflow, /^  (push|pull_request|schedule):$/m);
  assert.match(workflow, /archon\.aws-deployment-evidence\/v2/);
  assert.match(workflow, /archon\.lean-runtime-observation\/v1/);
  assert.match(workflow, /deployment-evidence-staging-/);
  assert.match(workflow, /CANARY_STACK_NAME: Archon-staging-Judge/);
  assert.match(workflow, /CANARY_RUNTIME_PROFILE: cloud/);
  assert.match(workflow, /ARCHON_LIVE_RUNTIME_PROFILE=cloud/);
  assert.match(workflow, /ArchonCanonicalDatasetUrn/);
  assert.match(workflow, /archon_demo\.customers,PROD/);
  assert.match(workflow, /ArchonGovernedColumnPath/);
  assert.match(workflow, /customer_email/);
  assert.match(workflow, /Deploy lean dual-runtime AWS release/);
  assert.doesNotMatch(workflow, /Deploy immutable AWS release/);
  assert.doesNotMatch(workflow, /Archon-staging\/(?!Judge)/);
  assert.doesNotMatch(workflow, /WorkerDesiredCount|live-runtime-manifest|ECS/i);
});

test("write and inverse are separately approved and share a non-cancelling lock", () => {
  assert.match(workflow, /group: archon-governed-canary-mutation-recovery/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /name: governed-canary-prepare/);
  assert.match(workflow, /name: governed-canary$/m);
  assert.match(workflow, /name: governed-canary-recovery/);
  assert.doesNotMatch(workflow, /^\s+name: governed-canary-rollback$/m);
  const prepare = section(workflow, "  prepare:", "  execute:");
  const execute = section(workflow, "  execute:", "  rollback:");
  const rollback = section(workflow, "  rollback:");
  for (const job of [prepare, execute, rollback]) {
    assert.doesNotMatch(job, /secrets\.CANARY_DATAHUB_(READ|WRITE)_TOKEN/);
  }
  assert.match(rollback, /AWS_CANARY_RECOVERY_ROLE_ARN/);
  assert.match(rollback, /source scripts\/load-datahub-cloud-canary-credentials\.sh/);
  assert.match(rollback, /allowed-account-ids: \$\{\{ vars\.AWS_ACCOUNT_ID \}\}/);
  assert.match(execute, /CANARY_COGNITO_USERNAME/);
  assert.match(execute, /CANARY_COGNITO_PASSWORD/);
  assert.match(execute, /archon-runtime-operators/);
  assert.match(execute, /archon-approvers/);
  assert.match(workflow, /archon\.governed-canary-recovery\/v4/);
  assert.match(workflow, /archon\.governed-canary-recovery-evidence\/v2/);
});

test("interrupted recovery authenticates the exact immutable source before AWS retrieval", () => {
  assert.match(recovery, /^permissions: \{\}$/m);
  assert.match(recovery, /Governed DataHub Cloud canary v2/);
  assert.match(recovery, /workflow_run:/);
  assert.match(recovery, /workflow_dispatch:/);
  assert.match(recovery, /RECOVER SEALED GOVERNED DATAHUB CLOUD CANARY/);
  assert.match(recovery, /\.conclusion=="failure" or \.conclusion=="cancelled"/);
  assert.match(recovery, /expected exactly one sealed recovery artifact/);
  assert.match(recovery, /node --import tsx scripts\/governed-canary\.ts verify/);
  assert.match(recovery, /VERIFICATION_MODE: sealed/);
  assert.match(recovery, /name: governed-canary-recovery/);
  assert.match(recovery, /AWS_CANARY_RECOVERY_ROLE_ARN/);
  assert.match(recovery, /source scripts\/load-datahub-cloud-canary-credentials\.sh/);
  assert.match(recovery, /allowed-account-ids: \$\{\{ vars\.AWS_ACCOUNT_ID \}\}/);
  assert.doesNotMatch(recovery, /secrets\.CANARY_DATAHUB_(READ|WRITE)_TOKEN/);
  assert.doesNotMatch(section(recovery, "  resolve:", "  recover:"), /secrets\./);
  assert.match(recovery, /actions\/attest@[a-f0-9]{40}/);
});

test("AWS credential loader binds exact current reader and writer secret versions in memory", () => {
  assert.match(credentials, /BASH_SOURCE\[0\].*==.*\$0/);
  assert.match(credentials, /Archon-staging-Judge/);
  assert.match(credentials, /exact_output ArchonCloudReaderSecretArn/);
  assert.match(credentials, /exact_output ArchonCloudWriterSecretArn/);
  assert.match(credentials, /--version-stage AWSCURRENT/);
  assert.match(credentials, /has\("SecretBinary"\) \| not/);
  assert.match(credentials, /archon\.datahub-cloud-reader-secret\/v1/);
  assert.match(credentials, /archon\.datahub-cloud-writer-secret\/v1/);
  assert.match(credentials, /test "\$\{CANARY_DATAHUB_READ_TOKEN\}" !=/);
  assert.match(credentials, /::add-mask::%s/);
  assert.match(credentials, /CANARY_DATAHUB_CREDENTIAL_BINDING_SHA256/);
  assert.doesNotMatch(credentials, /GITHUB_OUTPUT|GITHUB_ENV|mktemp|tee /);
});

test("recovery is an exact PII-only inverse with endpoint and read-back proofs", () => {
  for (const contract of [
    "archon.governed-canary-recovery/v4",
    "archon.governed-canary-recovery-evidence/v2",
    "archon.datahub-cloud-endpoint-binding/v1",
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
    "customer_email",
    "urn:li:tag:PII",
    "Archon-staging-Judge",
  ]) {
    assert.ok(driver.includes(contract));
  }
  assert.match(driver, /operation === "verify"/);
  assert.match(driver, /removeTags\(\{/);
  assert.match(driver, /tagUrns: \[PII_TAG_URN\]/);
  assert.match(driver, /exactProjection\(before, manifest\.target\)/);
  assert.match(
    driver,
    /const after = await reader\.readTagProjection\(target\);\s+exactProjection\(after, manifest\.target\);/
  );
  assert.match(driver, /live DataHub Cloud endpoints changed after recovery was sealed/);
});

test("browser proof covers all four DataHub capabilities and official MCP mutation", () => {
  for (const component of [
    "DataHub MCP Server",
    "Agent Context Kit",
    "DataHub Skills",
    "Analytics Agent",
  ]) {
    assert.ok(journey.includes(component));
  }
  assert.match(journey, /ARCHON_LIVE_V2_ONLY/);
  assert.match(journey, /requestedProfile: runtimeProfile/);
  assert.match(journey, /resolvedProfile: runtimeProfile/);
  assert.match(journey, /add_tags/);
  assert.match(journey, /post-write ACK/i);
  assert.match(journey, /governedMutationAndContextDeltaVerified: true/);
  assert.match(journey, /secretMaterialRetained: false/);
});

test("AWS roles stay least-privilege and promotion stays independent", () => {
  assert.equal(roles.match(/stack\/Archon-staging-Judge\/\*/g)?.length, 3);
  assert.doesNotMatch(roles, /stack\/Archon-staging\/\*/);
  assert.match(roles, /ReadExactStagingCloudRuntimeSecrets/);
  assert.match(roles, /DecryptExactStagingCloudRuntimeSecrets/);
  assert.match(roles, /secretsmanager:GetSecretValue/);
  assert.match(roles, /kms:Decrypt/);
  assert.match(roles, /kms:ViaService/);
  assert.match(roles, /kms:EncryptionContext:SecretARN/);
  assert.match(deploy, /archon\.aws-deployment-evidence\/v2/);
  assert.doesNotMatch(deploy, /repository_dispatch|workflow_run:/);
  assert.match(operations, /archon\.governed-canary-recovery-evidence\/v2/);
  assert.match(operations, /archon\.governed-canary-recovery\/v4/);
  assert.match(operations, /governed-canary-cloud-v2/);
  assert.doesNotMatch(operations, /governed-canary-fixture-binding|rollback-evidence\/v1/);
});