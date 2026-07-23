import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canaryAuthBindingsDigest,
  canaryEndpointBindingsDigest,
  parseCanaryIdentity,
  parseRuntimeConfig,
  rollbackDispositionForObservedDigest,
  verifyRecoveryManifest,
  type CanaryIdentity,
  type RecoveryManifest,
} from "../../scripts/governed-canary.js";
import { digest } from "../../src/remediation/integrity.js";
import { createTagProjection } from "../../src/remediation/planner.js";

const DATASET =
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,archon_governed_canary_fixture,TEST)";

function environment(): Record<string, string> {
  return {
    GITHUB_REPOSITORY: "upgradedev/archon-datahub",
    GITHUB_RUN_ID: "12345",
    GITHUB_RUN_ATTEMPT: "1",
    CANARY_SOURCE_WORKFLOW_RUN_ID: "12345",
    CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT: "1",
    CANARY_DEPLOYMENT_RUN_ID: "98765",
    CANARY_RELEASE_SHA: "a".repeat(40),
    CANARY_APPLICATION_URL: "https://example.cloudfront.net",
    CANARY_EVIDENCE_BUCKET: "archon-governed-canary-evidence",
    CANARY_COGNITO_CLIENT_ID: "canaryclient123",
    CANARY_COGNITO_HOSTED_UI_ORIGIN:
      "https://archon-staging.auth.eu-west-1.amazoncognito.com",
    CANARY_DATASET_URN: DATASET,
    CANARY_COLUMN_PATH: "email",
    CANARY_QUERY: "archon_governed_canary_fixture",
    CANARY_TAG_URN: "urn:li:tag:PII",
    CANARY_ISOLATION_MARKER: "archon-canary",
    CANARY_DATAHUB_READ_GMS_URL: "https://archon-canary.acryl.io",
    CANARY_DATAHUB_READ_MCP_URL:
      "https://archon-canary.acryl.io/integrations/ai/mcp/",
    CANARY_DATAHUB_WRITE_GMS_URL: "https://archon-canary.acryl.io",
    CANARY_DATAHUB_WRITE_MCP_URL:
      "https://archon-canary.acryl.io/integrations/ai/mcp-write/",
  };
}

function recovery(identity: CanaryIdentity): RecoveryManifest {
  const before = createTagProjection({
    entityUrn: identity.datasetUrn,
    columnPath: "email",
    tags: [],
  });
  const after = createTagProjection({
    entityUrn: identity.datasetUrn,
    columnPath: "email",
    tags: ["urn:li:tag:PII"],
  });
  const unsigned = {
    schemaVersion: "archon.governed-canary-recovery/v1" as const,
    repository: identity.repository,
    workflowRunId: identity.workflowRunId,
    workflowRunAttempt: identity.workflowRunAttempt,
    deploymentRunId: identity.deploymentRunId,
    releaseSha: identity.releaseSha,
    applicationUrl: identity.applicationUrl,
    evidenceBucket: identity.evidenceBucket,
    authBindingsDigest: canaryAuthBindingsDigest(identity),
    endpointBindingsDigest: canaryEndpointBindingsDigest(identity),
    auditId: "b".repeat(64),
    executionId:
      "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:b".concat(
        "b".repeat(63)
    ),
    approvalId: "approval-canary-123",
    approvalExpiresAt: "2026-07-23T18:15:00.000Z",
    evidenceDigest: digest("audit-evidence"),
    planDigest: digest("canary-plan"),
    target: {
      entityUrn: identity.datasetUrn,
      columnPath: "email" as const,
      tagUrn: "urn:li:tag:PII" as const,
    },
    expectedBefore: before,
    expectedAfter: after,
    inverseAction: {
      tool: "remove_tags" as const,
      arguments: {
        tag_urns: ["urn:li:tag:PII"] as ["urn:li:tag:PII"],
        entity_urns: [identity.datasetUrn] as [string],
        column_paths: ["email"] as ["email"],
      },
    },
    preparedAt: "2026-07-23T18:00:00.000Z",
  };
  return { ...unsigned, recoveryDigest: digest(unsigned) };
}

test("governed canary accepts only a fixed isolated TEST/DEV fixture", () => {
  const identity = parseCanaryIdentity(environment());
  assert.equal(identity.datasetUrn, DATASET);
  assert.equal(identity.columnPath, "email");
  assert.equal(identity.tagUrn, "urn:li:tag:PII");
});

test("governed canary rejects production and arbitrary dataset targets", () => {
  const production = environment();
  production["CANARY_DATASET_URN"] =
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,archon_governed_canary_fixture,PROD)";
  assert.throws(() => parseCanaryIdentity(production), /DEV or TEST/u);

  const arbitrary = environment();
  arbitrary["CANARY_DATASET_URN"] =
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,customers,TEST)";
  assert.throws(() => parseCanaryIdentity(arbitrary), /DEV or TEST/u);
});

test("governed canary rejects endpoints outside its dedicated tenant marker", () => {
  const unsafe = environment();
  unsafe["CANARY_DATAHUB_WRITE_MCP_URL"] =
    "https://production.acryl.io/integrations/ai/mcp/";
  assert.throws(() => parseCanaryIdentity(unsafe), /dedicated canary tenant/u);

  const substringSpoof = environment();
  substringSpoof["CANARY_DATAHUB_WRITE_MCP_URL"] =
    "https://evil-archon-canary.acryl.io/integrations/ai/mcp/";
  assert.throws(
    () => parseCanaryIdentity(substringSpoof),
    /dedicated canary tenant/u
  );
});

test("runtime Cognito client and origin must equal the sealed staging outputs", () => {
  const identity = parseCanaryIdentity(environment());
  const config = {
    schemaVersion: 1,
    auth: {
      clientId: identity.cognitoClientId,
      authorizationEndpoint: `${identity.cognitoHostedUiOrigin}/oauth2/authorize`,
      tokenEndpoint: `${identity.cognitoHostedUiOrigin}/oauth2/token`,
      redirectUri: `${identity.applicationUrl}/`,
      scopes: ["openid", "email", "archon/approve"],
    },
  };
  assert.deepEqual(parseRuntimeConfig(config, identity), config);

  assert.throws(
    () =>
      parseRuntimeConfig(
        {
          ...config,
          auth: { ...config.auth, clientId: "differentclient123" },
        },
        identity
      ),
    /sealed staging outputs/u
  );
  assert.throws(
    () =>
      parseRuntimeConfig(
        {
          ...config,
          auth: {
            ...config.auth,
            authorizationEndpoint:
              "https://attacker.example/oauth2/authorize",
            tokenEndpoint: "https://attacker.example/oauth2/token",
          },
        },
        identity
      ),
    /sealed staging outputs/u
  );
});

test("rollback recovery is content-addressed and rejects target tampering", () => {
  const identity = parseCanaryIdentity(environment());
  const manifest = recovery(identity);
  assert.deepEqual(verifyRecoveryManifest(manifest, identity), manifest);

  const tampered = structuredClone(manifest);
  tampered.target.entityUrn =
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,customers,TEST)";
  assert.throws(
    () => verifyRecoveryManifest(tampered, identity),
    /invalid or does not match/u
  );

  const differentClient = environment();
  differentClient["CANARY_COGNITO_CLIENT_ID"] = "otherclient123";
  assert.throws(
    () =>
      verifyRecoveryManifest(
        manifest,
        parseCanaryIdentity(differentClient)
      ),
    /invalid or does not match/u
  );
});

test("rollback is idempotent for exact before state and rejects divergence", () => {
  const before = digest("before");
  const after = digest("after");
  assert.equal(
    rollbackDispositionForObservedDigest(before, before, after),
    "ALREADY_RESTORED"
  );
  assert.equal(
    rollbackDispositionForObservedDigest(after, before, after),
    "ROLLED_BACK"
  );
  assert.throws(
    () =>
      rollbackDispositionForObservedDigest(
        digest("divergent"),
        before,
        after
      ),
    /outside the exact before\/after bindings/u
  );
});
