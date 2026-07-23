import type {
  ApprovalDecisionV1,
  ApprovalRequestV1,
  EvidenceDossierV1,
  ExecutionReceiptV1,
  RemediationPlanV1,
} from "../remediation/contracts.js";
import type { Sha256Digest } from "../remediation/integrity.js";
import type { AuditReport } from "../pipeline/pipeline.js";

const MAX_SQS_BODY_BYTES = 128 * 1024;
const ID_PATTERN = /^[A-Za-z0-9._:-]{8,160}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const EXECUTION_ARN_PATTERN =
  /^arn:(?:aws|aws-us-gov|aws-cn):states:[a-z0-9-]+:\d{12}:execution:[A-Za-z0-9-_]+:[A-Za-z0-9-_]+$/u;

export type AsyncMessageKind = "audit" | "approval" | "remediation";

export interface AuditRequestV1 {
  schemaVersion: "archon.audit-request/v1";
  requestId: string;
  requestedAt: string;
  query?: string;
  mode?: "READ_ONLY" | "GOVERNED";
}

export interface AuditQueueMessageV1 {
  type: "AUDIT_REQUESTED";
  taskToken: string;
  executionId: string;
  request: AuditRequestV1;
}

export interface ApprovalQueueMessageV1 {
  type: "APPROVAL_REQUESTED";
  taskToken: string;
  executionId: string;
  approvalId: string;
  planDigest: Sha256Digest;
  evidenceDigest: Sha256Digest;
  approvalRequestDigest: Sha256Digest;
  requestedAt: string;
  expiresAt: string;
}

export interface ApprovalCallbackV1 {
  approvalId: string;
  decision: {
    decision: "APPROVE" | "REJECT";
    approver: {
      subject: string;
      issuer: string;
      roles: ["DataSteward"];
      authenticated: true;
    };
    decidedAt: string;
  };
}

export interface RemediationQueueMessageV1 {
  type: "REMEDIATION_REQUESTED";
  taskToken: string;
  executionId: string;
  approvalId: string;
  planDigest: Sha256Digest;
  evidenceDigest: Sha256Digest;
  approvalResult: ApprovalCallbackV1;
}

export type AuditQueueMessage = AuditQueueMessageV1;
export type RemediationQueueMessage = RemediationQueueMessageV1;
export type WorkerQueueMessage =
  | AuditQueueMessageV1
  | ApprovalQueueMessageV1
  | RemediationQueueMessageV1;

export type ManualOnlyReason =
  | "READ_ONLY_REQUEST"
  | "NO_ACTIONABLE_G6_FINDING"
  | "REMEDIATION_PRESTATE_UNAVAILABLE"
  | "POLICY_REJECTED_PROPOSAL";

export interface ActionableEvidenceV1 {
  disposition: "ACTIONABLE";
  dossier: EvidenceDossierV1;
  plan: RemediationPlanV1;
  approvalRequest: ApprovalRequestV1;
}

export interface ManualOnlyEvidenceV1 {
  disposition: "MANUAL_ONLY";
  reason: ManualOnlyReason;
}

export interface AuditEvidenceV1 {
  schemaVersion: "archon.audit-evidence/v1";
  executionId: string;
  request: AuditRequestV1;
  releaseSha: string;
  report: AuditReport;
  reportDigest: Sha256Digest;
  remediation: ActionableEvidenceV1 | ManualOnlyEvidenceV1;
  createdAt: string;
  digest: Sha256Digest;
}

export interface ExecutionEvidenceV1 {
  schemaVersion: "archon.execution-evidence/v1";
  executionId: string;
  approvalId: string;
  auditEvidenceDigest: Sha256Digest;
  decision: ApprovalDecisionV1;
  receipt: ExecutionReceiptV1;
  createdAt: string;
  digest: Sha256Digest;
}

export interface AuditCallbackOutputV1 {
  schemaVersion: "archon.audit-result/v1";
  requiresApproval: boolean;
  reportDigest: Sha256Digest;
  evidenceDigest: Sha256Digest;
  approvalId?: string;
  planDigest?: Sha256Digest;
  approvalRequestDigest?: Sha256Digest;
  approvalRequestedAt?: string;
  approvalExpiresAt?: string;
  manualOnlyReason?: ManualOnlyReason;
}

export interface RemediationCallbackOutputV1 {
  schemaVersion: "archon.remediation-result/v1";
  approvalId: string;
  planDigest: Sha256Digest;
  evidenceDigest: Sha256Digest;
  receiptDigest: Sha256Digest;
  executionEvidenceDigest: Sha256Digest;
  outcome: ExecutionReceiptV1["outcome"];
}

export class WorkerContractError extends Error {
  constructor(
    readonly code:
      | "BODY_TOO_LARGE"
      | "INVALID_JSON"
      | "INVALID_MESSAGE"
      | "INVALID_EVIDENCE",
    message: string
  ) {
    super(message);
    this.name = "WorkerContractError";
  }
}

function fail(message: string): never {
  throw new WorkerContractError("INVALID_MESSAGE", message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
  label: string
): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    fail(`${label} contains an unexpected field.`);
  }
  if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    fail(`${label} is missing a required field.`);
  }
}

function stringValue(
  value: unknown,
  label: string,
  minLength: number,
  maxLength: number
): string {
  if (
    typeof value !== "string" ||
    value.length < minLength ||
    value.length > maxLength ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail(`${label} is invalid.`);
  }
  return value;
}

function instant(value: unknown, label: string): string {
  const text = stringValue(value, label, 20, 40);
  if (!Number.isFinite(Date.parse(text))) fail(`${label} must be an ISO-8601 timestamp.`);
  return text;
}

function taskToken(value: unknown): string {
  return stringValue(value, "taskToken", 16, 1024);
}

function executionId(value: unknown): string {
  const text = stringValue(value, "executionId", 32, 2048);
  if (!EXECUTION_ARN_PATTERN.test(text)) fail("executionId must be a Step Functions execution ARN.");
  return text;
}

function identifier(value: unknown, label: string): string {
  const text = stringValue(value, label, 8, 160);
  if (!ID_PATTERN.test(text)) fail(`${label} has an invalid format.`);
  return text;
}

function sha256(value: unknown, label: string): Sha256Digest {
  const text = stringValue(value, label, 71, 71);
  if (!DIGEST_PATTERN.test(text)) fail(`${label} must be a SHA-256 digest.`);
  return text as Sha256Digest;
}

function parseAuditRequest(value: unknown): AuditRequestV1 {
  const input = record(value, "request");
  exactKeys(
    input,
    ["schemaVersion", "requestId", "requestedAt", "query", "mode"],
    ["schemaVersion", "requestId", "requestedAt"],
    "request"
  );
  if (input["schemaVersion"] !== "archon.audit-request/v1") {
    fail("request.schemaVersion is unsupported.");
  }
  const query =
    input["query"] === undefined
      ? undefined
      : stringValue(input["query"], "request.query", 1, 512);
  const mode = input["mode"];
  if (
    mode !== undefined &&
    mode !== "READ_ONLY" &&
    mode !== "GOVERNED"
  ) {
    fail("request.mode must be READ_ONLY or GOVERNED.");
  }
  return {
    schemaVersion: "archon.audit-request/v1",
    requestId: identifier(input["requestId"], "request.requestId"),
    requestedAt: instant(input["requestedAt"], "request.requestedAt"),
    ...(query === undefined ? {} : { query }),
    ...(mode === undefined ? {} : { mode }),
  };
}

function parseApprovalCallback(value: unknown): ApprovalCallbackV1 {
  const callback = record(value, "approvalResult");
  exactKeys(callback, ["approvalId", "decision"], ["approvalId", "decision"], "approvalResult");
  const decision = record(callback["decision"], "approvalResult.decision");
  exactKeys(
    decision,
    ["decision", "approver", "decidedAt"],
    ["decision", "approver", "decidedAt"],
    "approvalResult.decision"
  );
  if (decision["decision"] !== "APPROVE" && decision["decision"] !== "REJECT") {
    fail("approvalResult.decision.decision is invalid.");
  }
  const approver = record(decision["approver"], "approvalResult.decision.approver");
  exactKeys(
    approver,
    ["subject", "issuer", "roles", "authenticated"],
    ["subject", "issuer", "roles", "authenticated"],
    "approvalResult.decision.approver"
  );
  if (
    approver["authenticated"] !== true ||
    !Array.isArray(approver["roles"]) ||
    approver["roles"].length !== 1 ||
    approver["roles"][0] !== "DataSteward"
  ) {
    fail("approvalResult does not contain an authenticated DataSteward.");
  }
  const issuer = stringValue(
    approver["issuer"],
    "approvalResult.decision.approver.issuer",
    8,
    2048
  );
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    fail("approvalResult.decision.approver.issuer is not a URL.");
  }
  if (
    issuerUrl.protocol !== "https:" ||
    issuerUrl.username ||
    issuerUrl.password ||
    issuerUrl.hash
  ) {
    fail("approvalResult.decision.approver.issuer is not an HTTPS identity issuer.");
  }
  return {
    approvalId: identifier(callback["approvalId"], "approvalResult.approvalId"),
    decision: {
      decision: decision["decision"],
      approver: {
        subject: stringValue(
          approver["subject"],
          "approvalResult.decision.approver.subject",
          1,
          256
        ),
        issuer: issuerUrl.toString().replace(/\/$/u, ""),
        roles: ["DataSteward"],
        authenticated: true,
      },
      decidedAt: instant(decision["decidedAt"], "approvalResult.decision.decidedAt"),
    },
  };
}

function parseAuditMessage(input: Record<string, unknown>): AuditQueueMessageV1 {
  exactKeys(
    input,
    ["type", "taskToken", "executionId", "request"],
    ["type", "taskToken", "executionId", "request"],
    "AUDIT_REQUESTED"
  );
  return {
    type: "AUDIT_REQUESTED",
    taskToken: taskToken(input["taskToken"]),
    executionId: executionId(input["executionId"]),
    request: parseAuditRequest(input["request"]),
  };
}

function parseApprovalMessage(input: Record<string, unknown>): ApprovalQueueMessageV1 {
  exactKeys(
    input,
    [
      "type",
      "taskToken",
      "executionId",
      "approvalId",
      "planDigest",
      "evidenceDigest",
      "approvalRequestDigest",
      "requestedAt",
      "expiresAt",
    ],
    [
      "type",
      "taskToken",
      "executionId",
      "approvalId",
      "planDigest",
      "evidenceDigest",
      "approvalRequestDigest",
      "requestedAt",
      "expiresAt",
    ],
    "APPROVAL_REQUESTED"
  );
  const requestedAt = instant(input["requestedAt"], "requestedAt");
  const expiresAt = instant(input["expiresAt"], "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(requestedAt)) {
    fail("expiresAt must be later than requestedAt.");
  }
  return {
    type: "APPROVAL_REQUESTED",
    taskToken: taskToken(input["taskToken"]),
    executionId: executionId(input["executionId"]),
    approvalId: identifier(input["approvalId"], "approvalId"),
    planDigest: sha256(input["planDigest"], "planDigest"),
    evidenceDigest: sha256(input["evidenceDigest"], "evidenceDigest"),
    approvalRequestDigest: sha256(
      input["approvalRequestDigest"],
      "approvalRequestDigest"
    ),
    requestedAt,
    expiresAt,
  };
}

function parseRemediationMessage(input: Record<string, unknown>): RemediationQueueMessageV1 {
  exactKeys(
    input,
    [
      "type",
      "taskToken",
      "executionId",
      "approvalId",
      "planDigest",
      "evidenceDigest",
      "approvalResult",
    ],
    [
      "type",
      "taskToken",
      "executionId",
      "approvalId",
      "planDigest",
      "evidenceDigest",
      "approvalResult",
    ],
    "REMEDIATION_REQUESTED"
  );
  const approvalResult = parseApprovalCallback(input["approvalResult"]);
  const approvalId = identifier(input["approvalId"], "approvalId");
  if (approvalResult.approvalId !== approvalId) {
    fail("approvalResult is not bound to approvalId.");
  }
  return {
    type: "REMEDIATION_REQUESTED",
    taskToken: taskToken(input["taskToken"]),
    executionId: executionId(input["executionId"]),
    approvalId,
    planDigest: sha256(input["planDigest"], "planDigest"),
    evidenceDigest: sha256(input["evidenceDigest"], "evidenceDigest"),
    approvalResult,
  };
}

export function parseQueueMessage(kind: AsyncMessageKind, body: string): WorkerQueueMessage {
  if (Buffer.byteLength(body, "utf8") > MAX_SQS_BODY_BYTES) {
    throw new WorkerContractError("BODY_TOO_LARGE", "SQS message body exceeds the worker limit.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new WorkerContractError("INVALID_JSON", "SQS message body is not valid JSON.");
  }
  const input = record(parsed, "message");
  if (kind === "approval") {
    if (input["type"] !== "APPROVAL_REQUESTED") {
      fail("The approval queue accepts only APPROVAL_REQUESTED.");
    }
    return parseApprovalMessage(input);
  }
  if (kind === "audit") {
    if (input["type"] !== "AUDIT_REQUESTED") {
      fail("The audit queue accepts only AUDIT_REQUESTED.");
    }
    return parseAuditMessage(input);
  }
  if (input["type"] !== "REMEDIATION_REQUESTED") {
    fail("The remediation queue accepts only REMEDIATION_REQUESTED.");
  }
  return parseRemediationMessage(input);
}
