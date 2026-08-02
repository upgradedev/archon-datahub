import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalize,
  createRecoveryEvidence,
  endpointBinding,
  parseRecoveryManifest,
  sealRecoveryManifest,
} from "../../scripts/governed-canary.js";

const dataset =
  "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)";
const digest = (character: string) => `sha256:${character.repeat(64)}`;

function environment(): Record<string, string> {
  return {
    GITHUB_REPOSITORY: "upgradedev/archon-datahub",
    GITHUB_SHA: "a".repeat(40),
    CANARY_SOURCE_WORKFLOW_RUN_ID: "12345",
    CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT: "2",
    CANARY_CONTROL_PLANE_GATES_SHA256: digest("1"),
    CANARY_RELEASE_SHA: "a".repeat(40),
    CANARY_DEPLOYMENT_RUN_ID: "45678",
    CANARY_DEPLOYMENT_ARTIFACT_ID: "87654",
    CANARY_DEPLOYMENT_ARTIFACT_DIGEST: digest("2"),
    CANARY_DEPLOYMENT_EVIDENCE_SHA256: digest("3"),
    CANARY_OBSERVATION_SHA256: digest("4"),
    CANARY_APPLICATION_URL: "https://staging.archon-datahub.click",
    CANARY_STACK_NAME: "Archon-staging-Judge",
    CANARY_CLOUD_IMAGE_DIGEST: digest("5"),
    CANARY_ISOLATION_MARKER: "archon-canary",
    CANARY_DATAHUB_READ_GMS_URL: "https://archon-canary.datahub.example",
    CANARY_DATAHUB_READ_MCP_URL: "https://archon-canary.datahub.example/api/mcp",
    CANARY_DATAHUB_WRITE_GMS_URL: "https://archon-canary.datahub.example/",
    CANARY_DATAHUB_WRITE_MCP_URL: "https://archon-canary.datahub.example/api/mcp/",
  };
}

test("seals one canonical Cloud-only recovery manifest", async () => {
  const manifest = await sealRecoveryManifest(
    environment(),
    "2026-08-02T10:00:00.000Z"
  );
  assert.equal(manifest.schemaVersion, "archon.governed-canary-recovery/v4");
  assert.equal(manifest.runtime.profileId, "cloud");
  assert.equal(manifest.runtime.resolution, "explicit");
  assert.equal(manifest.runtime.stackName, "Archon-staging-Judge");
  const exactTarget: {
    readonly entityUrn: typeof dataset;
    readonly columnPath: "customer_email";
    readonly tagUrn: "urn:li:tag:PII";
  } = manifest.target;
  assert.deepEqual(exactTarget, manifest.target);  assert.equal(manifest.target.entityUrn, dataset);
  assert.equal(manifest.target.columnPath, "customer_email");
  assert.equal(manifest.target.tagUrn, "urn:li:tag:PII");
  assert.deepEqual(JSON.parse(canonicalize(manifest as never)), manifest);
  assert.deepEqual(await parseRecoveryManifest(manifest), manifest);
});

test("rejects legacy stacks, endpoint spoofing and manifest tampering", async () => {
  await assert.rejects(
    () => sealRecoveryManifest({ ...environment(), CANARY_STACK_NAME: "Archon-staging" }),
    /only Archon-staging-Judge/u
  );
  await assert.rejects(
    () => endpointBinding({
      ...environment(),
      CANARY_DATAHUB_WRITE_MCP_URL:
        "https://archon-canary.attacker.example/api/mcp",
    }),
    /one isolated DataHub Cloud tenant/u
  );
  const manifest = await sealRecoveryManifest(environment());
  await assert.rejects(
    () => parseRecoveryManifest({
      ...manifest,
      runtime: { ...manifest.runtime, profileId: "core" },
    }),
    /identity|digest/u
  );
});

test("recovery evidence proves the exact PII-only inverse", async () => {
  const manifest = await sealRecoveryManifest(environment());
  const evidence = await createRecoveryEvidence({
    manifest,
    endpointBindingSha256: manifest.endpointBindingSha256,
    before: {
      entityUrn: dataset,
      columnPath: "customer_email",
      tags: ["urn:li:tag:Existing", "urn:li:tag:PII"],
      digest: digest("6") as `sha256:${string}`,
    },
    after: {
      entityUrn: dataset,
      columnPath: "customer_email",
      tags: ["urn:li:tag:Existing"],
      digest: digest("7") as `sha256:${string}`,
    },
    mutation: { requestDigest: digest("8"), responseDigest: digest("9") },
    recoveredAt: "2026-08-02T10:30:00.000Z",
  });
  assert.equal(evidence.disposition, "restored");
  assert.equal(evidence.mutation.performed, true);
  assert.match(evidence.digest, /^sha256:[a-f0-9]{64}$/u);

  await assert.rejects(
    () => createRecoveryEvidence({
      manifest,
      endpointBindingSha256: digest("0"),
      before: {
        entityUrn: dataset,
        columnPath: "customer_email",
        tags: [],
        digest: digest("6") as `sha256:${string}`,
      },
      after: {
        entityUrn: dataset,
        columnPath: "customer_email",
        tags: [],
        digest: digest("7") as `sha256:${string}`,
      },
      recoveredAt: "2026-08-02T10:30:00.000Z",
    }),
    /sealed endpoint binding/u
  );

  await assert.rejects(
    () => createRecoveryEvidence({
      manifest,
      endpointBindingSha256: manifest.endpointBindingSha256,
      before: {
        entityUrn: dataset,
        columnPath: "customer_email",
        tags: ["urn:li:tag:PII"],
        digest: digest("a") as `sha256:${string}`,
      },
      after: {
        entityUrn: dataset,
        columnPath: "customer_email",
        tags: ["urn:li:tag:PII"],
        digest: digest("b") as `sha256:${string}`,
      },
      recoveredAt: "2026-08-02T10:30:00.000Z",
    }),
    /exact pre-canary baseline/u
  );
});