import { createHash, randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { DirectGmsTagProjectionReader } from "../src/datahub/tag-projection-reader-live.js";
import { LiveDataHubMutationClient } from "../src/datahub/mutation-client-live.js";
import type {
  AuditEvidenceV1,
  ExecutionEvidenceV1,
} from "../src/worker/contracts.js";
import type {
  ExecutionReceiptV1,
  RollbackProposalV1,
  TagProjection,
} from "../src/remediation/contracts.js";
import {
  canonicalize,
  digest,
  verifyDigest,
  withoutDigest,
  type Sha256Digest,
} from "../src/remediation/integrity.js";
import {
  createRollbackProposal,
  verifyExecutionReceipt,
} from "../src/remediation/receipt.js";
import { verifyApprovalRequest } from "../src/remediation/control-loop.js";
import { verifyAuditEvidence } from "../src/worker/service.js";

const APPLICATION_TAG = "urn:li:tag:PII";
const CANARY_QUERY = "archon_governed_canary_fixture";
const CANARY_COLUMN = "email";
const RECOVERY_SCHEMA = "archon.governed-canary-recovery/v1";
const ROLLBACK_SCHEMA = "archon.governed-canary-rollback/v1";
const ROLLBACK_EVIDENCE_SCHEMA =
  "archon.governed-canary-rollback-evidence/v1";
const CONTROL_STATUS_SCHEMA = "archon.control-loop-status/v1";
const CONTROL_START_SCHEMA = "archon.control-loop-start/v1";
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const RELEASE_SHA = /^[a-f0-9]{40}$/u;
const AUDIT_ID = /^[a-f0-9]{64}$/u;
const STAGING_EXECUTION_ARN =
  /^arn:aws:states:[a-z0-9-]+:[0-9]{12}:execution:archon-staging-control-loop:[a-f0-9]{64}$/u;
const DATASET_URN =
  /^urn:li:dataset:\(urn:li:dataPlatform:[A-Za-z0-9._-]+,archon_governed_canary_fixture(?:_[A-Za-z0-9_-]+)?,(?:DEV|TEST)\)$/u;
const MAX_JSON_BYTES = 6 * 1024 * 1024;
const POLL_INTERVAL_MS = 3_000;
const PREPARE_TIMEOUT_MS = 15 * 60 * 1_000;
const TERMINAL_TIMEOUT_MS = 15 * 60 * 1_000;
const VERIFIED_CHECK_IDS = [
  "TARGET_UNCHANGED",
  "PREEXISTING_TAGS_PRESERVED",
  "POLICY_TAG_PRESENT",
  "NO_UNEXPECTED_TAGS",
  "APPROVAL_BINDING_VALID",
] as const;

type JsonRecord = Record<string, unknown>;

export interface CanaryIdentity {
  repository: string;
  workflowRunId: string;
  workflowRunAttempt: string;
  deploymentRunId: string;
  releaseSha: string;
  applicationUrl: string;
  evidenceBucket: string;
  cognitoClientId: string;
  cognitoHostedUiOrigin: string;
  datasetUrn: string;
  columnPath: typeof CANARY_COLUMN;
  query: typeof CANARY_QUERY;
  tagUrn: typeof APPLICATION_TAG;
  isolationMarker: string;
  dataHubReadGmsUrl: string;
  dataHubReadMcpUrl: string;
  dataHubWriteGmsUrl: string;
  dataHubWriteMcpUrl: string;
}

export interface RecoveryManifest {
  schemaVersion: typeof RECOVERY_SCHEMA;
  repository: string;
  workflowRunId: string;
  workflowRunAttempt: string;
  deploymentRunId: string;
  releaseSha: string;
  applicationUrl: string;
  evidenceBucket: string;
  authBindingsDigest: Sha256Digest;
  endpointBindingsDigest: Sha256Digest;
  auditId: string;
  executionId: string;
  approvalId: string;
  approvalExpiresAt: string;
  evidenceDigest: Sha256Digest;
  planDigest: Sha256Digest;
  target: {
    entityUrn: string;
    columnPath: typeof CANARY_COLUMN;
    tagUrn: typeof APPLICATION_TAG;
  };
  expectedBefore: TagProjection;
  expectedAfter: TagProjection;
  inverseAction: {
    tool: "remove_tags";
    arguments: {
      tag_urns: [typeof APPLICATION_TAG];
      entity_urns: [string];
      column_paths: [typeof CANARY_COLUMN];
    };
  };
  preparedAt: string;
  recoveryDigest: Sha256Digest;
}

export interface RollbackManifest {
  schemaVersion: typeof ROLLBACK_SCHEMA;
  recoveryDigest: Sha256Digest;
  receiptDigest: Sha256Digest;
  executionEvidenceDigest: Sha256Digest;
  proposal: RollbackProposalV1;
  verifiedAt: string;
  digest: Sha256Digest;
}

interface ControlApproval {
  approvalId: string;
  status: "PENDING" | "DECIDED";
  planDigest: Sha256Digest;
  evidenceDigest: Sha256Digest;
  decision?: "APPROVE" | "REJECT";
}

interface ControlResult {
  outcome: "READ_ONLY_COMPLETE" | "VERIFIED" | "REJECTED";
  receiptDigest?: Sha256Digest;
  executionEvidenceDigest?: Sha256Digest;
  completedAt?: string;
  verification?: {
    checks?: Array<{ checkId?: unknown; passed?: unknown }>;
    eventCount?: unknown;
    rollbackAvailability?: unknown;
  };
}

interface ControlStatus {
  schemaVersion: typeof CONTROL_STATUS_SCHEMA;
  auditId: string;
  status:
    | "RUNNING"
    | "AWAITING_APPROVAL"
    | "SUCCEEDED"
    | "FAILED"
    | "TIMED_OUT"
    | "ABORTED";
  releaseSha?: string;
  approval?: ControlApproval;
  result?: ControlResult;
}

export interface RuntimeConfig {
  schemaVersion: 1;
  auth: {
    clientId: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    redirectUri: string;
    scopes: string[];
  };
}

function authBindings(identity: Pick<
  CanaryIdentity,
  "applicationUrl" | "cognitoClientId" | "cognitoHostedUiOrigin"
>): JsonRecord {
  return {
    applicationUrl: identity.applicationUrl,
    clientId: identity.cognitoClientId,
    hostedUiOrigin: identity.cognitoHostedUiOrigin,
    authorizationEndpoint: `${identity.cognitoHostedUiOrigin}/oauth2/authorize`,
    tokenEndpoint: `${identity.cognitoHostedUiOrigin}/oauth2/token`,
  };
}

export function canaryAuthBindingsDigest(
  identity: Pick<
    CanaryIdentity,
    "applicationUrl" | "cognitoClientId" | "cognitoHostedUiOrigin"
  >
): Sha256Digest {
  return digest(authBindings(identity));
}

function fail(message: string): never {
  throw new Error(`Governed canary rejected the operation: ${message}`);
}

function record(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  return value as JsonRecord;
}

function required(
  source: NodeJS.ProcessEnv | Record<string, string | undefined>,
  name: string,
  maximum = 4_096
): string {
  const value = source[name]?.trim();
  if (
    !value ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail(`${name} is missing or invalid.`);
  }
  return value;
}

function exactHttpsUrl(value: string, label: string, rootOnly = false): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be a URL.`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (rootOnly && (parsed.pathname !== "/" || parsed.search))
  ) {
    fail(`${label} must be an exact HTTPS URL.`);
  }
  return rootOnly ? parsed.origin : parsed.toString();
}

function endpointBindings(identity: Pick<
  CanaryIdentity,
  | "isolationMarker"
  | "dataHubReadGmsUrl"
  | "dataHubReadMcpUrl"
  | "dataHubWriteGmsUrl"
  | "dataHubWriteMcpUrl"
>): JsonRecord {
  return {
    isolationMarker: identity.isolationMarker,
    readGmsUrl: identity.dataHubReadGmsUrl,
    readMcpUrl: identity.dataHubReadMcpUrl,
    writeGmsUrl: identity.dataHubWriteGmsUrl,
    writeMcpUrl: identity.dataHubWriteMcpUrl,
  };
}

export function canaryEndpointBindingsDigest(
  identity: Pick<
    CanaryIdentity,
    | "isolationMarker"
    | "dataHubReadGmsUrl"
    | "dataHubReadMcpUrl"
    | "dataHubWriteGmsUrl"
    | "dataHubWriteMcpUrl"
  >
): Sha256Digest {
  return digest(endpointBindings(identity));
}

export function parseCanaryIdentity(
  source: NodeJS.ProcessEnv | Record<string, string | undefined>
): CanaryIdentity {
  const repository = required(source, "GITHUB_REPOSITORY", 256);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
    fail("GITHUB_REPOSITORY is invalid.");
  }
  const workflowRunId = required(
    source,
    "CANARY_SOURCE_WORKFLOW_RUN_ID",
    32
  );
  const workflowRunAttempt = required(
    source,
    "CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT",
    10
  );
  const deploymentRunId = required(source, "CANARY_DEPLOYMENT_RUN_ID", 32);
  if (!/^[1-9][0-9]{0,19}$/u.test(workflowRunId)) {
    fail("CANARY_SOURCE_WORKFLOW_RUN_ID must be numeric.");
  }
  if (!/^[1-9][0-9]{0,9}$/u.test(workflowRunAttempt)) {
    fail("CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT must be numeric.");
  }
  if (!/^[1-9][0-9]{0,19}$/u.test(deploymentRunId)) {
    fail("CANARY_DEPLOYMENT_RUN_ID must be numeric.");
  }
  const releaseSha = required(source, "CANARY_RELEASE_SHA", 40);
  if (!RELEASE_SHA.test(releaseSha)) {
    fail("CANARY_RELEASE_SHA must be a full lowercase commit SHA.");
  }
  const applicationUrl = exactHttpsUrl(
    required(source, "CANARY_APPLICATION_URL"),
    "CANARY_APPLICATION_URL",
    true
  );
  const evidenceBucket = required(source, "CANARY_EVIDENCE_BUCKET", 63);
  if (
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(evidenceBucket) ||
    evidenceBucket.includes("..")
  ) {
    fail("CANARY_EVIDENCE_BUCKET is invalid.");
  }
  const cognitoClientId = required(source, "CANARY_COGNITO_CLIENT_ID", 128);
  if (!/^[A-Za-z0-9]{8,128}$/u.test(cognitoClientId)) {
    fail("CANARY_COGNITO_CLIENT_ID is invalid.");
  }
  const cognitoHostedUiOrigin = exactHttpsUrl(
    required(source, "CANARY_COGNITO_HOSTED_UI_ORIGIN"),
    "CANARY_COGNITO_HOSTED_UI_ORIGIN",
    true
  );
  const datasetUrn = required(source, "CANARY_DATASET_URN", 512);
  if (!DATASET_URN.test(datasetUrn) || datasetUrn.includes(",PROD)")) {
    fail(
      "CANARY_DATASET_URN must name the dedicated archon_governed_canary_fixture in DEV or TEST."
    );
  }
  const columnPath = required(source, "CANARY_COLUMN_PATH", 32);
  const query = required(source, "CANARY_QUERY", 64);
  const tagUrn = required(source, "CANARY_TAG_URN", 64);
  if (
    columnPath !== CANARY_COLUMN ||
    query !== CANARY_QUERY ||
    tagUrn !== APPLICATION_TAG
  ) {
    fail("the canary query, email field, and PII tag are fixed by policy.");
  }
  const isolationMarker = required(source, "CANARY_ISOLATION_MARKER", 63)
    .toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{6,61}[a-z0-9]$/u.test(isolationMarker)) {
    fail("CANARY_ISOLATION_MARKER must be a DNS-safe dedicated-tenant marker.");
  }
  const urls = {
    dataHubReadGmsUrl: exactHttpsUrl(
      required(source, "CANARY_DATAHUB_READ_GMS_URL"),
      "CANARY_DATAHUB_READ_GMS_URL"
    ),
    dataHubReadMcpUrl: exactHttpsUrl(
      required(source, "CANARY_DATAHUB_READ_MCP_URL"),
      "CANARY_DATAHUB_READ_MCP_URL"
    ),
    dataHubWriteGmsUrl: exactHttpsUrl(
      required(source, "CANARY_DATAHUB_WRITE_GMS_URL"),
      "CANARY_DATAHUB_WRITE_GMS_URL"
    ),
    dataHubWriteMcpUrl: exactHttpsUrl(
      required(source, "CANARY_DATAHUB_WRITE_MCP_URL"),
      "CANARY_DATAHUB_WRITE_MCP_URL"
    ),
  };
  for (const [name, value] of Object.entries(urls)) {
    const host = new URL(value).hostname.toLowerCase();
    if (!host.split(".").includes(isolationMarker)) {
      fail(`${name} is not bound to the dedicated canary tenant marker.`);
    }
  }
  if (
    new URL(urls.dataHubReadGmsUrl).origin !==
    new URL(urls.dataHubWriteGmsUrl).origin
  ) {
    fail("read and write GMS endpoints must belong to one isolated canary tenant.");
  }
  return {
    repository,
    workflowRunId,
    workflowRunAttempt,
    deploymentRunId,
    releaseSha,
    applicationUrl,
    evidenceBucket,
    cognitoClientId,
    cognitoHostedUiOrigin,
    datasetUrn,
    columnPath: CANARY_COLUMN,
    query: CANARY_QUERY,
    tagUrn: APPLICATION_TAG,
    isolationMarker,
    ...urls,
  };
}

function isTagProjection(value: unknown): value is TagProjection {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const projection = value as Partial<TagProjection>;
  return (
    typeof projection.entityUrn === "string" &&
    typeof projection.columnPath === "string" &&
    Array.isArray(projection.tags) &&
    projection.tags.every((tag) => typeof tag === "string") &&
    canonicalize(projection.tags) ===
      canonicalize(
        [...new Set(projection.tags)].sort((left, right) =>
          left.localeCompare(right)
        )
      ) &&
    typeof projection.digest === "string" &&
    SHA256.test(projection.digest) &&
    verifyDigest(
      {
        entityUrn: projection.entityUrn,
        columnPath: projection.columnPath,
        tags: projection.tags,
      },
      projection.digest as Sha256Digest
    )
  );
}

function exactTagTransition(
  before: TagProjection,
  after: TagProjection,
  identity: CanaryIdentity
): boolean {
  const expected = [...new Set([...before.tags, APPLICATION_TAG])].sort((a, b) =>
    a.localeCompare(b)
  );
  return (
    before.entityUrn === identity.datasetUrn &&
    after.entityUrn === identity.datasetUrn &&
    before.columnPath === CANARY_COLUMN &&
    after.columnPath === CANARY_COLUMN &&
    !before.tags.includes(APPLICATION_TAG) &&
    canonicalize(after.tags) === canonicalize(expected)
  );
}

function parseControlStatus(value: unknown, expectedAuditId: string): ControlStatus {
  const status = record(value, "control-loop status");
  if (
    status["schemaVersion"] !== CONTROL_STATUS_SCHEMA ||
    status["auditId"] !== expectedAuditId ||
    ![
      "RUNNING",
      "AWAITING_APPROVAL",
      "SUCCEEDED",
      "FAILED",
      "TIMED_OUT",
      "ABORTED",
    ].includes(String(status["status"]))
  ) {
    fail("the control-loop status contract is invalid.");
  }
  const parsed = status as unknown as ControlStatus;
  if (
    parsed.releaseSha !== undefined &&
    (typeof parsed.releaseSha !== "string" ||
      !/^[a-f0-9]{7,64}$/u.test(parsed.releaseSha))
  ) {
    fail("the status release binding is invalid.");
  }
  if (parsed.approval !== undefined) {
    const approval = record(parsed.approval, "approval projection");
    if (
      typeof approval["approvalId"] !== "string" ||
      !["PENDING", "DECIDED"].includes(String(approval["status"])) ||
      typeof approval["planDigest"] !== "string" ||
      !SHA256.test(approval["planDigest"]) ||
      typeof approval["evidenceDigest"] !== "string" ||
      !SHA256.test(approval["evidenceDigest"])
    ) {
      fail("the approval projection is invalid.");
    }
  }
  return parsed;
}

async function boundedJson(response: Response, label: string): Promise<unknown> {
  const text = await response.text();
  if (
    Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES ||
    !response.headers.get("content-type")?.toLowerCase().startsWith(
      "application/json"
    )
  ) {
    fail(`${label} did not return bounded JSON.`);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail(`${label} returned invalid JSON.`);
  }
}

async function apiJson(
  url: string,
  init: RequestInit,
  label: string,
  accepted: readonly number[]
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 35_000);
  try {
    const response = await fetch(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
    });
    const body = await boundedJson(response, label);
    if (!accepted.includes(response.status)) {
      fail(`${label} failed with HTTP ${response.status}.`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

async function startControlLoop(identity: CanaryIdentity): Promise<string> {
  const value = record(
    await apiJson(
      `${identity.applicationUrl}/api/control-loops`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ mode: "GOVERNED", query: identity.query }),
      },
      "control-loop start",
      [202]
    ),
    "control-loop start"
  );
  if (
    value["schemaVersion"] !== CONTROL_START_SCHEMA ||
    typeof value["auditId"] !== "string" ||
    !AUDIT_ID.test(value["auditId"]) ||
    value["status"] !== "RUNNING" ||
    value["pollUrl"] !== `/api/control-loops/${value["auditId"]}`
  ) {
    fail("the control-loop start capability is invalid.");
  }
  return value["auditId"];
}

async function readStatus(
  identity: CanaryIdentity,
  auditId: string
): Promise<ControlStatus> {
  return parseControlStatus(
    await apiJson(
      `${identity.applicationUrl}/api/control-loops/${auditId}`,
      { method: "GET", headers: { Accept: "application/json" } },
      "control-loop status",
      [200]
    ),
    auditId
  );
}

async function waitForStatus(
  identity: CanaryIdentity,
  auditId: string,
  wanted: "AWAITING_APPROVAL" | "SUCCEEDED",
  timeoutMs: number
): Promise<ControlStatus> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await readStatus(identity, auditId);
    if (status.status === wanted) return status;
    if (["FAILED", "TIMED_OUT", "ABORTED"].includes(status.status)) {
      fail(`the governed control loop ended in ${status.status}.`);
    }
    if (wanted === "AWAITING_APPROVAL" && status.status === "SUCCEEDED") {
      fail("the governed loop bypassed approval.");
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  fail(`the governed control loop did not reach ${wanted} before timeout.`);
}

async function evidenceObject(
  bucket: string,
  kind: "audit" | "execution",
  expectedDigest: Sha256Digest
): Promise<unknown> {
  if (!SHA256.test(expectedDigest)) fail("an evidence digest is invalid.");
  const client = new S3Client({});
  const object = await client.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: `v1/${kind}/sha256/${expectedDigest.slice("sha256:".length)}.json`,
      ChecksumMode: "ENABLED",
    })
  );
  if (!object.Body || typeof object.Body.transformToByteArray !== "function") {
    fail(`${kind} evidence is unavailable.`);
  }
  const bytes = await object.Body.transformToByteArray();
  if (bytes.byteLength > MAX_JSON_BYTES) fail(`${kind} evidence is too large.`);
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    fail(`${kind} evidence is not JSON.`);
  }
}

function actionableEvidence(value: AuditEvidenceV1): {
  dossier: JsonRecord;
  plan: JsonRecord;
  approvalRequest: JsonRecord;
} {
  if (value.remediation.disposition !== "ACTIONABLE") {
    fail("the isolated fixture did not produce an actionable G6 result.");
  }
  if (!verifyApprovalRequest(value.remediation.approvalRequest)) {
    fail("the canary approval request is invalid.");
  }
  return {
    dossier: value.remediation.dossier as unknown as JsonRecord,
    plan: value.remediation.plan as unknown as JsonRecord,
    approvalRequest: value.remediation.approvalRequest as unknown as JsonRecord,
  };
}

export function createRecoveryManifest(input: {
  identity: CanaryIdentity;
  status: ControlStatus;
  evidence: AuditEvidenceV1;
  preparedAt: string;
}): RecoveryManifest {
  const { identity, status, evidence, preparedAt } = input;
  const approval = status.approval;
  if (
    status.status !== "AWAITING_APPROVAL" ||
    status.releaseSha !== identity.releaseSha ||
    status.auditId !== evidence.request.requestId ||
    !approval ||
    approval.status !== "PENDING" ||
    !verifyAuditEvidence(evidence, approval.evidenceDigest) ||
    evidence.digest !== approval.evidenceDigest ||
    evidence.releaseSha !== identity.releaseSha ||
    evidence.request.mode !== "GOVERNED" ||
    evidence.request.query !== identity.query ||
    evidence.report.classification.totalEntities !== 1
  ) {
    fail("the pending approval is not bound to the exact isolated release audit.");
  }
  const { dossier, plan, approvalRequest } = actionableEvidence(evidence);
  const target = record(dossier["target"], "evidence target");
  const action = record(plan["action"], "remediation action");
  const arguments_ = record(action["arguments"], "remediation arguments");
  const inverse = record(action["inverse"], "inverse action");
  const inverseArguments = record(
    inverse["arguments"],
    "inverse action arguments"
  );
  const approvalExpiresAt = approvalRequest["expiresAt"];
  const before = plan["expectedBefore"];
  const after = plan["expectedAfter"];
  if (
    target["entityUrn"] !== identity.datasetUrn ||
    target["columnPath"] !== CANARY_COLUMN ||
    action["tool"] !== "add_tags" ||
    inverse["tool"] !== "remove_tags" ||
    canonicalize(arguments_["tag_urns"]) !== canonicalize([APPLICATION_TAG]) ||
    canonicalize(arguments_["entity_urns"]) !==
      canonicalize([identity.datasetUrn]) ||
    canonicalize(arguments_["column_paths"]) !== canonicalize([CANARY_COLUMN]) ||
    canonicalize(inverseArguments) !== canonicalize(arguments_) ||
    !isTagProjection(before) ||
    !isTagProjection(after) ||
    !exactTagTransition(before, after, identity) ||
    approvalRequest["approvalId"] !== approval.approvalId ||
    approvalRequest["planDigest"] !== approval.planDigest ||
    typeof approvalExpiresAt !== "string" ||
    Date.parse(approvalExpiresAt) <= Date.parse(preparedAt) ||
    plan["digest"] !== approval.planDigest ||
    typeof dossier["digest"] !== "string" ||
    !SHA256.test(dossier["digest"]) ||
    !Number.isFinite(Date.parse(preparedAt))
  ) {
    fail("the approval plan is not the fixed one-field canary transition.");
  }
  const executionId = evidence.executionId;
  if (
    typeof executionId !== "string" ||
    !STAGING_EXECUTION_ARN.test(executionId) ||
    !executionId.endsWith(`:${status.auditId}`)
  ) {
    fail("the audit execution identity is not bound to its public audit ID.");
  }
  const unsigned = {
    schemaVersion: RECOVERY_SCHEMA,
    repository: identity.repository,
    workflowRunId: identity.workflowRunId,
    workflowRunAttempt: identity.workflowRunAttempt,
    deploymentRunId: identity.deploymentRunId,
    releaseSha: identity.releaseSha,
    applicationUrl: identity.applicationUrl,
    evidenceBucket: identity.evidenceBucket,
    authBindingsDigest: canaryAuthBindingsDigest(identity),
    endpointBindingsDigest: canaryEndpointBindingsDigest(identity),
    auditId: status.auditId,
    executionId,
    approvalId: approval.approvalId,
    approvalExpiresAt,
    evidenceDigest: approval.evidenceDigest,
    planDigest: approval.planDigest,
    target: {
      entityUrn: identity.datasetUrn,
      columnPath: CANARY_COLUMN,
      tagUrn: APPLICATION_TAG,
    },
    expectedBefore: before,
    expectedAfter: after,
    inverseAction: {
      tool: "remove_tags" as const,
      arguments: {
        tag_urns: [APPLICATION_TAG] as [typeof APPLICATION_TAG],
        entity_urns: [identity.datasetUrn] as [string],
        column_paths: [CANARY_COLUMN] as [typeof CANARY_COLUMN],
      },
    },
    preparedAt,
  };
  return { ...unsigned, recoveryDigest: digest(unsigned) };
}

export function verifyRecoveryManifest(
  value: unknown,
  identity: CanaryIdentity
): RecoveryManifest {
  const manifest = record(value, "recovery manifest") as unknown as RecoveryManifest;
  const { recoveryDigest, ...unsigned } = manifest;
  if (
    manifest.schemaVersion !== RECOVERY_SCHEMA ||
    manifest.repository !== identity.repository ||
    manifest.workflowRunId !== identity.workflowRunId ||
    manifest.workflowRunAttempt !== identity.workflowRunAttempt ||
    manifest.deploymentRunId !== identity.deploymentRunId ||
    manifest.releaseSha !== identity.releaseSha ||
    manifest.applicationUrl !== identity.applicationUrl ||
    manifest.evidenceBucket !== identity.evidenceBucket ||
    manifest.authBindingsDigest !== canaryAuthBindingsDigest(identity) ||
    manifest.endpointBindingsDigest !== canaryEndpointBindingsDigest(identity) ||
    !AUDIT_ID.test(manifest.auditId) ||
    !STAGING_EXECUTION_ARN.test(manifest.executionId) ||
    !manifest.executionId.endsWith(`:${manifest.auditId}`) ||
    !Number.isFinite(Date.parse(manifest.approvalExpiresAt)) ||
    Date.parse(manifest.approvalExpiresAt) <= Date.parse(manifest.preparedAt) ||
    !SHA256.test(manifest.evidenceDigest) ||
    !SHA256.test(manifest.planDigest) ||
    manifest.target.entityUrn !== identity.datasetUrn ||
    manifest.target.columnPath !== CANARY_COLUMN ||
    manifest.target.tagUrn !== APPLICATION_TAG ||
    !isTagProjection(manifest.expectedBefore) ||
    !isTagProjection(manifest.expectedAfter) ||
    !exactTagTransition(manifest.expectedBefore, manifest.expectedAfter, identity) ||
    manifest.inverseAction.tool !== "remove_tags" ||
    canonicalize(manifest.inverseAction.arguments) !==
      canonicalize({
        tag_urns: [APPLICATION_TAG],
        entity_urns: [identity.datasetUrn],
        column_paths: [CANARY_COLUMN],
      }) ||
    !Number.isFinite(Date.parse(manifest.preparedAt)) ||
    !SHA256.test(recoveryDigest) ||
    digest(unsigned) !== recoveryDigest
  ) {
    fail("the recovery manifest is invalid or does not match this run.");
  }
  return manifest;
}

export function parseRuntimeConfig(
  value: unknown,
  identity: CanaryIdentity
): RuntimeConfig {
  const config = record(value, "runtime config");
  const auth = record(config["auth"], "runtime auth config");
  if (
    config["schemaVersion"] !== 1 ||
    typeof auth["clientId"] !== "string" ||
    !/^[A-Za-z0-9]{8,128}$/u.test(auth["clientId"]) ||
    auth["clientId"] !== identity.cognitoClientId ||
    !Array.isArray(auth["scopes"]) ||
    canonicalize(auth["scopes"]) !==
      canonicalize(["openid", "email", "archon/approve"]) ||
    auth["redirectUri"] !== `${identity.applicationUrl}/`
  ) {
    fail("the runtime auth config does not match the sealed staging outputs.");
  }
  const authorizationEndpoint = exactHttpsUrl(
    String(auth["authorizationEndpoint"]),
    "authorization endpoint"
  );
  const tokenEndpoint = exactHttpsUrl(
    String(auth["tokenEndpoint"]),
    "token endpoint"
  );
  if (
    new URL(authorizationEndpoint).pathname !== "/oauth2/authorize" ||
    new URL(tokenEndpoint).pathname !== "/oauth2/token" ||
    new URL(authorizationEndpoint).origin !== identity.cognitoHostedUiOrigin ||
    new URL(tokenEndpoint).origin !== identity.cognitoHostedUiOrigin ||
    authorizationEndpoint !==
      `${identity.cognitoHostedUiOrigin}/oauth2/authorize` ||
    tokenEndpoint !== `${identity.cognitoHostedUiOrigin}/oauth2/token`
  ) {
    fail("the Cognito OAuth client or endpoints do not match the sealed staging outputs.");
  }
  return {
    schemaVersion: 1,
    auth: {
      clientId: auth["clientId"],
      authorizationEndpoint,
      tokenEndpoint,
      redirectUri: auth["redirectUri"],
      scopes: auth["scopes"] as string[],
    },
  };
}

interface CdpWebSocket {
  readonly readyState: number;
  onopen: (() => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  send(data: string): void;
  close(): void;
}

type CdpWebSocketConstructor = new (url: string) => CdpWebSocket;

class CdpClient {
  readonly #socket: CdpWebSocket;
  readonly #pending = new Map<
    number,
    { resolve: (value: JsonRecord) => void; reject: (error: Error) => void }
  >();
  readonly #listeners = new Map<
    string,
    Set<(parameters: JsonRecord) => void>
  >();
  #sequence = 0;

  private constructor(socket: CdpWebSocket) {
    this.#socket = socket;
    socket.onmessage = (event) => {
      let message: JsonRecord;
      try {
        message = JSON.parse(String(event.data)) as JsonRecord;
      } catch {
        return;
      }
      if (typeof message["id"] === "number") {
        const pending = this.#pending.get(message["id"]);
        if (!pending) return;
        this.#pending.delete(message["id"]);
        if (message["error"]) {
          pending.reject(new Error("Chrome rejected a canary browser command."));
        } else {
          pending.resolve(
            message["result"] &&
              typeof message["result"] === "object" &&
              !Array.isArray(message["result"])
              ? (message["result"] as JsonRecord)
              : {}
          );
        }
        return;
      }
      if (
        typeof message["method"] === "string" &&
        message["params"] &&
        typeof message["params"] === "object" &&
        !Array.isArray(message["params"])
      ) {
        for (const listener of this.#listeners.get(message["method"]) ?? []) {
          listener(message["params"] as JsonRecord);
        }
      }
    };
  }

  static async connect(url: string): Promise<CdpClient> {
    const WebSocketImplementation = (
      globalThis as unknown as { WebSocket?: CdpWebSocketConstructor }
    ).WebSocket;
    if (!WebSocketImplementation) fail("Node.js does not expose WebSocket.");
    const socket = new WebSocketImplementation(url);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("Chrome DevTools connection timed out.")),
        10_000
      );
      socket.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      socket.onerror = () => {
        clearTimeout(timer);
        reject(new Error("Chrome DevTools connection failed."));
      };
    });
    return new CdpClient(socket);
  }

  on(method: string, listener: (parameters: JsonRecord) => void): () => void {
    const listeners = this.#listeners.get(method) ?? new Set();
    listeners.add(listener);
    this.#listeners.set(method, listeners);
    return () => listeners.delete(listener);
  }

  send(method: string, params: JsonRecord = {}): Promise<JsonRecord> {
    const id = ++this.#sequence;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params }));
    });
  }

  close(): void {
    this.#socket.close();
  }
}

async function waitForChrome(port: number): Promise<string> {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (response.ok) return "ready";
    } catch {
      // Chrome is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail("headless Chrome did not start.");
}

async function runtimeValue(client: CdpClient, expression: string): Promise<unknown> {
  const result = await client.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result["exceptionDetails"]) {
    fail("the Cognito login page rejected browser automation.");
  }
  const remote = record(result["result"], "Chrome evaluation result");
  return remote["value"];
}

async function waitForLoginForm(client: CdpClient): Promise<void> {
  const selector =
    'document.querySelector("input[name=\\"username\\"],#signInFormUsername,#username")' +
    ' && document.querySelector("input[name=\\"password\\"],#signInFormPassword,#password")';
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if ((await runtimeValue(client, `Boolean(${selector})`)) === true) return;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  fail("Cognito did not present the expected Hosted UI login form.");
}

async function loadRuntimeConfig(
  identity: CanaryIdentity
): Promise<RuntimeConfig> {
  return parseRuntimeConfig(
    await apiJson(
      `${identity.applicationUrl}/runtime-config.json`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
      },
      "runtime config",
      [200]
    ),
    identity
  );
}

async function hostedPkceToken(
  identity: CanaryIdentity,
  runtime: RuntimeConfig,
  username: string,
  password: string,
  chromeBin: string,
  chromeProfile: string
): Promise<string> {
  const state = randomBytes(32).toString("base64url");
  const verifier = randomBytes(64).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier, "ascii")
    .digest("base64url");
  const authorization = new URL(runtime.auth.authorizationEndpoint);
  authorization.search = new URLSearchParams({
    response_type: "code",
    client_id: runtime.auth.clientId,
    redirect_uri: runtime.auth.redirectUri,
    scope: runtime.auth.scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();

  const port = 9_222;
  const chrome = spawn(
    chromeBin,
    [
      "--headless=new",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--no-first-run",
      "--no-default-browser-check",
      "--remote-debugging-address=127.0.0.1",
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${chromeProfile}`,
      "about:blank",
    ],
    { stdio: "ignore" }
  );
  let client: CdpClient | undefined;
  let callbackTimer: NodeJS.Timeout | undefined;
  let removeCallbackListener: (() => void) | undefined;
  try {
    await waitForChrome(port);
    const targetResponse = await fetch(
      `http://127.0.0.1:${port}/json/new?${encodeURIComponent(
        authorization.toString()
      )}`,
      { method: "PUT" }
    );
    const target = record(
      await boundedJson(targetResponse, "Chrome target"),
      "Chrome target"
    );
    if (typeof target["webSocketDebuggerUrl"] !== "string") {
      fail("Chrome did not expose a DevTools target.");
    }
    client = await CdpClient.connect(target["webSocketDebuggerUrl"]);
    await client.send("Runtime.enable");
    await client.send("Page.enable");
    await client.send("Fetch.enable", {
      patterns: [
        {
          urlPattern: `${identity.applicationUrl}/*`,
          resourceType: "Document",
          requestStage: "Request",
        },
      ],
    });
    const callback = new Promise<string>((resolve, reject) => {
      callbackTimer = setTimeout(
        () => reject(new Error("Cognito PKCE callback timed out.")),
        90_000
      );
      removeCallbackListener = client!.on("Fetch.requestPaused", (parameters) => {
        const request = parameters["request"];
        const requestId = parameters["requestId"];
        if (
          !request ||
          typeof request !== "object" ||
          Array.isArray(request) ||
          typeof (request as JsonRecord)["url"] !== "string" ||
          typeof requestId !== "string"
        ) {
          return;
        }
        const url = (request as JsonRecord)["url"] as string;
        if (!url.startsWith(`${identity.applicationUrl}/?`)) return;
        clearTimeout(callbackTimer);
        removeCallbackListener?.();
        void client!.send("Fetch.failRequest", {
          requestId,
          errorReason: "Aborted",
        });
        resolve(url);
      });
    });
    await waitForLoginForm(client);
    const expression = `(() => {
      const username = document.querySelector(
        'input[name="username"],#signInFormUsername,#username'
      );
      const password = document.querySelector(
        'input[name="password"],#signInFormPassword,#password'
      );
      const submit = document.querySelector(
        'input[name="signInSubmitButton"],button[type="submit"],input[type="submit"]'
      );
      if (!(username instanceof HTMLInputElement) ||
          !(password instanceof HTMLInputElement) ||
          !(submit instanceof HTMLElement)) return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype, 'value'
      )?.set;
      if (!setter) return false;
      setter.call(username, ${JSON.stringify(username)});
      setter.call(password, ${JSON.stringify(password)});
      for (const input of [username, password]) {
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      submit.click();
      return true;
    })()`;
    if ((await runtimeValue(client, expression)) !== true) {
      fail("Cognito Hosted UI inputs were not usable.");
    }
    const callbackUrl = new URL(await callback);
    const codes = callbackUrl.searchParams.getAll("code");
    const states = callbackUrl.searchParams.getAll("state");
    if (
      codes.length !== 1 ||
      states.length !== 1 ||
      states[0] !== state ||
      callbackUrl.origin !== identity.applicationUrl ||
      callbackUrl.pathname !== "/" ||
      codes[0]!.length < 8 ||
      codes[0]!.length > 4_096
    ) {
      fail("the Cognito authorization callback is invalid.");
    }
    const tokenResponse = await fetch(runtime.auth.tokenEndpoint, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(35_000),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: runtime.auth.clientId,
        code: codes[0]!,
        redirect_uri: runtime.auth.redirectUri,
        code_verifier: verifier,
      }),
    });
    const token = record(
      await boundedJson(tokenResponse, "Cognito token response"),
      "Cognito token response"
    );
    if (
      !tokenResponse.ok ||
      token["token_type"] !== "Bearer" ||
      typeof token["access_token"] !== "string" ||
      token["access_token"].length < 20 ||
      token["access_token"].length > 16_384 ||
      /[\s\u0000-\u001f\u007f]/u.test(token["access_token"]) ||
      (token["scope"] !== undefined &&
        (typeof token["scope"] !== "string" ||
          !token["scope"].split(/\s+/u).includes("archon/approve")))
    ) {
      fail("Cognito did not issue a scoped bearer token.");
    }
    return token["access_token"];
  } finally {
    if (callbackTimer) clearTimeout(callbackTimer);
    removeCallbackListener?.();
    client?.close();
    terminate(chrome);
    await rm(chromeProfile, { recursive: true, force: true });
  }
}

function terminate(child: ChildProcess): void {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }, 2_000).unref();
  }
}

async function submitApproval(
  identity: CanaryIdentity,
  manifest: RecoveryManifest,
  token: string
): Promise<void> {
  const value = record(
    await apiJson(
      `${identity.applicationUrl}/api/approvals/${encodeURIComponent(
        manifest.approvalId
      )}/decisions`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          decision: "APPROVE",
          comment: `Governed canary run ${identity.workflowRunId}; plan ${manifest.planDigest}`,
        }),
      },
      "approval decision",
      [200, 202]
    ),
    "approval decision"
  );
  if (
    value["approvalId"] !== manifest.approvalId ||
    value["decision"] !== "APPROVE" ||
    !["recorded", "queued"].includes(String(value["status"]))
  ) {
    fail("the approval acknowledgement is not bound to the canary plan.");
  }
}

function parseExecutionEvidence(
  value: unknown,
  expectedDigest: Sha256Digest
): ExecutionEvidenceV1 {
  const evidence = record(value, "execution evidence") as unknown as ExecutionEvidenceV1;
  if (
    evidence.schemaVersion !== "archon.execution-evidence/v1" ||
    evidence.digest !== expectedDigest ||
    !verifyDigest(withoutDigest(evidence), expectedDigest)
  ) {
    fail("execution evidence failed its content-addressed integrity check.");
  }
  return evidence;
}

function createBoundRollbackManifest(input: {
  identity: CanaryIdentity;
  recovery: RecoveryManifest;
  status: ControlStatus;
  evidence: ExecutionEvidenceV1;
}): RollbackManifest {
  const { identity, recovery, status, evidence } = input;
  const result = status.result;
  const approval = status.approval;
  const verification = result?.verification;
  const receipt: ExecutionReceiptV1 = evidence.receipt;
  if (
    status.status !== "SUCCEEDED" ||
    status.releaseSha !== identity.releaseSha ||
    !approval ||
    approval.status !== "DECIDED" ||
    approval.decision !== "APPROVE" ||
    approval.approvalId !== recovery.approvalId ||
    approval.planDigest !== recovery.planDigest ||
    approval.evidenceDigest !== recovery.evidenceDigest ||
    !result ||
    result.outcome !== "VERIFIED" ||
    !result.receiptDigest ||
    !result.executionEvidenceDigest ||
    result.receiptDigest !== receipt.digest ||
    result.executionEvidenceDigest !== evidence.digest ||
    evidence.executionId !== recovery.executionId ||
    evidence.approvalId !== recovery.approvalId ||
    evidence.auditEvidenceDigest !== recovery.evidenceDigest ||
    evidence.decision.decision !== "APPROVE" ||
    evidence.decision.planDigest !== recovery.planDigest ||
    receipt.outcome !== "VERIFIED" ||
    receipt.planDigest !== recovery.planDigest ||
    canonicalize(receipt.action.inverse) !==
      canonicalize(recovery.inverseAction) ||
    !isTagProjection(receipt.before) ||
    !isTagProjection(receipt.after) ||
    receipt.before.digest !== recovery.expectedBefore.digest ||
    receipt.after.digest !== recovery.expectedAfter.digest ||
    !verifyExecutionReceipt(receipt).valid ||
    !verification ||
    verification.rollbackAvailability !== "ELIGIBLE" ||
    verification.eventCount !== 7 ||
    !Array.isArray(verification.checks) ||
    verification.checks.length !== 5 ||
    verification.checks.some(
      (check, index) =>
        check.passed !== true ||
        check.checkId !== VERIFIED_CHECK_IDS[index]
    )
  ) {
    fail("the terminal result is not a fully verified canary receipt.");
  }
  const proposal = createRollbackProposal(receipt, receipt.after);
  if (
    !proposal ||
    proposal.requiresFreshApproval !== true ||
    proposal.originalReceiptDigest !== receipt.digest ||
    proposal.expectedCurrentDigest !== recovery.expectedAfter.digest ||
    proposal.restoreStateDigest !== recovery.expectedBefore.digest ||
    canonicalize(proposal.inverseAction) !== canonicalize(recovery.inverseAction)
  ) {
    fail("a fresh, exact rollback proposal could not be derived.");
  }
  const unsigned = {
    schemaVersion: ROLLBACK_SCHEMA,
    recoveryDigest: recovery.recoveryDigest,
    receiptDigest: receipt.digest,
    executionEvidenceDigest: evidence.digest,
    proposal,
    verifiedAt: result.completedAt ?? receipt.completedAt,
  };
  return { ...unsigned, digest: digest(unsigned) };
}

export function verifyRollbackManifest(
  value: unknown,
  recovery: RecoveryManifest
): RollbackManifest {
  const manifest = record(value, "rollback manifest") as unknown as RollbackManifest;
  const { digest: manifestDigest, ...unsigned } = manifest;
  const proposal = manifest.proposal;
  const {
    rollbackId,
    digest: proposalDigest,
    ...proposalPayload
  } = proposal;
  if (
    manifest.schemaVersion !== ROLLBACK_SCHEMA ||
    manifest.recoveryDigest !== recovery.recoveryDigest ||
    !SHA256.test(manifest.receiptDigest) ||
    !SHA256.test(manifest.executionEvidenceDigest) ||
    !Number.isFinite(Date.parse(manifest.verifiedAt)) ||
    !SHA256.test(manifestDigest) ||
    digest(unsigned) !== manifestDigest ||
    proposal.schemaVersion !== "archon.rollback-proposal/v1" ||
    proposal.originalReceiptDigest !== manifest.receiptDigest ||
    proposal.expectedCurrentDigest !== recovery.expectedAfter.digest ||
    proposal.restoreStateDigest !== recovery.expectedBefore.digest ||
    proposal.requiresFreshApproval !== true ||
    canonicalize(proposal.inverseAction) !== canonicalize(recovery.inverseAction) ||
    !SHA256.test(proposalDigest) ||
    verifyDigest(proposalPayload, proposalDigest) !== true ||
    rollbackId !==
      `rollback-${proposalDigest.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}`
  ) {
    fail("the rollback proposal is invalid or not bound to the verified write.");
  }
  return manifest;
}

export function rollbackDispositionForObservedDigest(
  observedDigest: Sha256Digest,
  expectedBeforeDigest: Sha256Digest,
  expectedAfterDigest: Sha256Digest
): "ALREADY_RESTORED" | "ROLLED_BACK" {
  if (
    !SHA256.test(observedDigest) ||
    !SHA256.test(expectedBeforeDigest) ||
    !SHA256.test(expectedAfterDigest) ||
    expectedBeforeDigest === expectedAfterDigest
  ) {
    fail("rollback state bindings are invalid.");
  }
  if (observedDigest === expectedBeforeDigest) return "ALREADY_RESTORED";
  if (observedDigest === expectedAfterDigest) return "ROLLED_BACK";
  fail("rollback refused a state outside the exact before/after bindings.");
}

async function prepare(): Promise<void> {
  const identity = parseCanaryIdentity(process.env);
  const outputPath = required(process.env, "CANARY_RECOVERY_PATH", 4_096);
  const auditId = await startControlLoop(identity);
  const status = await waitForStatus(
    identity,
    auditId,
    "AWAITING_APPROVAL",
    PREPARE_TIMEOUT_MS
  );
  if (!status.approval) fail("the pending governed loop has no approval.");
  const evidence = (await evidenceObject(
    identity.evidenceBucket,
    "audit",
    status.approval.evidenceDigest
  )) as AuditEvidenceV1;
  const manifest = createRecoveryManifest({
    identity,
    status,
    evidence,
    preparedAt: new Date().toISOString(),
  });
  await writeFile(outputPath, `${canonicalize(manifest)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function approve(): Promise<void> {
  const identity = parseCanaryIdentity(process.env);
  const recoveryPath = required(process.env, "CANARY_RECOVERY_PATH", 4_096);
  const rollbackPath = required(process.env, "CANARY_ROLLBACK_PATH", 4_096);
  const recovery = verifyRecoveryManifest(
    JSON.parse(await readFile(recoveryPath, "utf8")),
    identity
  );
  if (Date.parse(recovery.approvalExpiresAt) - Date.now() < 120_000) {
    fail("the sealed approval has less than two minutes remaining.");
  }
  const current = await readStatus(identity, recovery.auditId);
  const approval = current.approval;
  if (
    current.status !== "AWAITING_APPROVAL" ||
    !approval ||
    approval.status !== "PENDING" ||
    approval.approvalId !== recovery.approvalId ||
    approval.planDigest !== recovery.planDigest ||
    approval.evidenceDigest !== recovery.evidenceDigest ||
    current.releaseSha !== identity.releaseSha
  ) {
    fail("the approval changed after recovery evidence was sealed.");
  }
  const runtime = await loadRuntimeConfig(identity);
  const username = required(process.env, "CANARY_COGNITO_USERNAME", 256);
  const password = required(process.env, "CANARY_COGNITO_PASSWORD", 4_096);
  const chromeBin = required(process.env, "CANARY_CHROME_BIN", 4_096);
  const chromeProfile = required(process.env, "CANARY_CHROME_PROFILE", 4_096);
  const token = await hostedPkceToken(
    identity,
    runtime,
    username,
    password,
    chromeBin,
    chromeProfile
  );
  await submitApproval(identity, recovery, token);
  const terminal = await waitForStatus(
    identity,
    recovery.auditId,
    "SUCCEEDED",
    TERMINAL_TIMEOUT_MS
  );
  const executionDigest = terminal.result?.executionEvidenceDigest;
  if (!executionDigest || !SHA256.test(executionDigest)) {
    fail("the terminal result has no execution evidence digest.");
  }
  const execution = parseExecutionEvidence(
    await evidenceObject(identity.evidenceBucket, "execution", executionDigest),
    executionDigest
  );
  const rollback = createBoundRollbackManifest({
    identity,
    recovery,
    status: terminal,
    evidence: execution,
  });
  await writeFile(rollbackPath, `${canonicalize(rollback)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function rollback(): Promise<void> {
  const identity = parseCanaryIdentity(process.env);
  const recoveryPath = required(process.env, "CANARY_RECOVERY_PATH", 4_096);
  const rollbackPath = process.env["CANARY_ROLLBACK_PATH"]?.trim();
  const evidencePath = required(
    process.env,
    "CANARY_ROLLBACK_EVIDENCE_PATH",
    4_096
  );
  const writeJobResult = required(process.env, "CANARY_WRITE_JOB_RESULT", 32);
  const readToken = required(process.env, "CANARY_DATAHUB_READ_TOKEN", 16_384);
  const writeToken = required(process.env, "CANARY_DATAHUB_WRITE_TOKEN", 16_384);
  const recovery = verifyRecoveryManifest(
    JSON.parse(await readFile(recoveryPath, "utf8")),
    identity
  );
  let rollbackManifest: RollbackManifest | undefined;
  if (rollbackPath) {
    try {
      rollbackManifest = verifyRollbackManifest(
        JSON.parse(await readFile(rollbackPath, "utf8")),
        recovery
      );
    } catch (error) {
      if (writeJobResult === "success") throw error;
    }
  }
  if (writeJobResult === "success" && !rollbackManifest) {
    fail("a successful governed write requires its verified rollback proposal.");
  }

  const reader = new DirectGmsTagProjectionReader({
    gmsUrl: identity.dataHubReadGmsUrl,
    token: readToken,
    requestTimeoutMs: 30_000,
  });
  const current = await reader.readTagProjection({
    entityUrn: identity.datasetUrn,
    columnPath: CANARY_COLUMN,
  });
  const expectedCurrentDigest = rollbackManifest
    ? rollbackManifest.proposal.expectedCurrentDigest
    : recovery.expectedAfter.digest;
  const disposition = rollbackDispositionForObservedDigest(
    current.digest,
    recovery.expectedBefore.digest,
    expectedCurrentDigest
  );
  const shouldRemove = disposition === "ROLLED_BACK";

  let mutation:
    | { requestDigest: Sha256Digest; responseDigest: Sha256Digest }
    | undefined;
  if (shouldRemove) {
    process.env["DATAHUB_WRITE_GMS_URL"] = identity.dataHubWriteGmsUrl;
    process.env["DATAHUB_WRITE_MCP_URL"] = identity.dataHubWriteMcpUrl;
    process.env["DATAHUB_WRITE_GMS_TOKEN"] = writeToken;
    mutation = await new LiveDataHubMutationClient().removeTags(
      {
        tagUrns: [APPLICATION_TAG],
        entityUrns: [identity.datasetUrn],
        columnPaths: [CANARY_COLUMN],
      },
      { timeoutMs: 120_000 }
    );
  }
  let restored: TagProjection | undefined;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const observed = await reader.readTagProjection({
      entityUrn: identity.datasetUrn,
      columnPath: CANARY_COLUMN,
    });
    if (observed.digest === recovery.expectedBefore.digest) {
      restored = observed;
      break;
    }
    if (
      !shouldRemove ||
      observed.digest !== recovery.expectedAfter.digest
    ) {
      fail("read-after-rollback observed an unapproved divergent state.");
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (
    !restored ||
    restored.digest !== recovery.expectedBefore.digest ||
    canonicalize(restored.tags) !== canonicalize(recovery.expectedBefore.tags)
  ) {
    fail("read-after-rollback did not prove the exact pre-canary state.");
  }
  const unsigned = {
    schemaVersion: ROLLBACK_EVIDENCE_SCHEMA,
    repository: identity.repository,
    workflowRunId: identity.workflowRunId,
    workflowRunAttempt: identity.workflowRunAttempt,
    recoveryWorkflowRunId: required(process.env, "GITHUB_RUN_ID", 32),
    recoveryWorkflowRunAttempt: required(
      process.env,
      "GITHUB_RUN_ATTEMPT",
      10
    ),
    deploymentRunId: identity.deploymentRunId,
    releaseSha: identity.releaseSha,
    auditId: recovery.auditId,
    recoveryDigest: recovery.recoveryDigest,
    ...(rollbackManifest
      ? {
          rollbackManifestDigest: rollbackManifest.digest,
          rollbackProposalDigest: rollbackManifest.proposal.digest,
          receiptDigest: rollbackManifest.receiptDigest,
          executionEvidenceDigest: rollbackManifest.executionEvidenceDigest,
        }
      : {}),
    target: recovery.target,
    observedDigest: current.digest,
    restoredDigest: restored.digest,
    disposition,
    ...(mutation
      ? {
          mutation: {
            requestDigest: mutation.requestDigest,
            responseDigest: mutation.responseDigest,
          },
        }
      : {}),
    verifiedAt: new Date().toISOString(),
  };
  await writeFile(
    evidencePath,
    `${canonicalize({ ...unsigned, digest: digest(unsigned) })}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
}

async function main(): Promise<void> {
  const operation = process.argv[2];
  if (operation === "prepare") return prepare();
  if (operation === "approve") return approve();
  if (operation === "rollback") return rollback();
  fail("operation must be prepare, approve, or rollback.");
}

const invoked = process.argv[1]?.replace(/\\/gu, "/");
if (
  invoked === "scripts/governed-canary.ts" ||
  invoked?.endsWith("/scripts/governed-canary.ts")
) {
  await main();
}
