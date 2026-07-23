import { previewAudit } from "./fixtures";
import type {
  ApprovalAck,
  ApprovalDecision,
  AuditEnvelope,
  AuditReport,
  ControlLoopApproval,
  ControlLoopResult,
  ControlLoopStart,
  ControlLoopStatus,
  Finding,
  LoadedAudit,
} from "./types";

const AUDIT_PATH = "/api/audits";
const CONTROL_LOOP_PATH = "/api/control-loops";
const AUDIT_ID_PATTERN = /^[a-f0-9]{64}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const TERMINAL_CONTROL_STATES = new Set(["SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"]);
const VERIFICATION_CHECK_IDS = [
  "TARGET_UNCHANGED",
  "PREEXISTING_TAGS_PRESERVED",
  "POLICY_TAG_PRESENT",
  "NO_UNEXPECTED_TAGS",
  "APPROVAL_BINDING_VALID",
] as const;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  );
}

function isNumberRecord(value: unknown): value is Record<string, number> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === "number");
}

function isBlastRadius(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.rootUrn === "string" &&
    Array.isArray(value.downstream) &&
    value.downstream.every(
      (asset) =>
        isRecord(asset) && typeof asset.urn === "string" && typeof asset.minHops === "number",
    ) &&
    typeof value.maxHops === "number" &&
    typeof value.truncated === "boolean" &&
    ["none", "low", "medium", "high", "critical"].includes(String(value.impact))
  );
}

function isProvenance(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (event) =>
        isRecord(event) &&
        typeof event.source === "string" &&
        typeof event.runId === "string" &&
        typeof event.observedAt === "string" &&
        (event.actor === undefined || typeof event.actor === "string") &&
        (event.value === undefined || typeof event.value === "string") &&
        ["trusted", "conflicting", "observed"].includes(String(event.status)),
    )
  );
}

function isDossier(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.dossierId === "string" &&
    typeof value.digest === "string" &&
    typeof value.policyDigest === "string" &&
    typeof value.generatedAt === "string" &&
    typeof value.evidenceCount === "number"
  );
}

function isApproval(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.approvalId === "string" &&
    typeof value.expiresAt === "string" &&
    typeof value.targetField === "string" &&
    typeof value.proposedTag === "string" &&
    Array.isArray(value.before) &&
    value.before.every((entry) => typeof entry === "string") &&
    Array.isArray(value.after) &&
    value.after.every((entry) => typeof entry === "string") &&
    typeof value.planDigest === "string" &&
    ["low", "medium", "high"].includes(String(value.risk))
  );
}

function isFinding(value: unknown): value is Finding {
  return (
    isRecord(value) &&
    (value.type === "contradiction" ||
      value.type === "lineage_gap" ||
      value.type === "governance_violation") &&
    (value.severity === "high" || value.severity === "medium" || value.severity === "low") &&
    typeof value.subject === "string" &&
    typeof value.summary === "string" &&
    isRecord(value.detail) &&
    (value.detail.blastRadius === undefined || isBlastRadius(value.detail.blastRadius)) &&
    (value.detail.provenance === undefined || isProvenance(value.detail.provenance)) &&
    (value.detail.dossier === undefined || isDossier(value.detail.dossier)) &&
    (value.detail.approval === undefined || isApproval(value.detail.approval)) &&
    (value.recommendation === undefined || typeof value.recommendation === "string")
  );
}

function isAuditReport(value: unknown): value is AuditReport {
  return (
    isRecord(value) &&
    typeof value.scanId === "string" &&
    isRecord(value.classification) &&
    typeof value.classification.totalEntities === "number" &&
    typeof value.classification.withLineage === "number" &&
    typeof value.classification.sensitiveEntities === "number" &&
    isNumberRecord(value.classification.domains) &&
    isNumberRecord(value.classification.platforms) &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding) &&
    typeof value.narrative === "string" &&
    Array.isArray(value.trace) &&
    value.trace.every(
      (step) =>
        isRecord(step) && typeof step.agent === "string" && typeof step.produced === "string",
    )
  );
}

function parseAuditEnvelope(value: unknown): AuditEnvelope {
  if (
    !isRecord(value) ||
    typeof value.requestId !== "string" ||
    typeof value.releaseSha !== "string" ||
    !isAuditReport(value.report)
  ) {
    throw new ApiError("The audit API returned an invalid response contract.", 502);
  }
  return value as unknown as AuditEnvelope;
}

function isInstant(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function parseControlLoopStart(value: unknown): ControlLoopStart {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schemaVersion",
      "auditId",
      "status",
      "pollUrl",
      "submittedAt",
    ]) ||
    value.schemaVersion !== "archon.control-loop-start/v1" ||
    typeof value.auditId !== "string" ||
    !AUDIT_ID_PATTERN.test(value.auditId) ||
    value.status !== "RUNNING" ||
    value.pollUrl !== `${CONTROL_LOOP_PATH}/${value.auditId}` ||
    !isInstant(value.submittedAt)
  ) {
    throw new ApiError("The control plane returned an invalid start contract.", 502);
  }
  return value as unknown as ControlLoopStart;
}

function isControlLoopApproval(value: unknown): value is ControlLoopApproval {
  return (
    isRecord(value) &&
    hasOnlyKeys(
      value,
      ["approvalId", "status", "expiresAt", "planDigest", "evidenceDigest"],
      ["decision"],
    ) &&
    typeof value.approvalId === "string" &&
    (value.status === "PENDING" || value.status === "DECIDED") &&
    isInstant(value.expiresAt) &&
    typeof value.planDigest === "string" &&
    DIGEST_PATTERN.test(value.planDigest) &&
    typeof value.evidenceDigest === "string" &&
    DIGEST_PATTERN.test(value.evidenceDigest) &&
    ((value.status === "PENDING" && value.decision === undefined) ||
      (value.status === "DECIDED" &&
        (value.decision === "APPROVE" || value.decision === "REJECT")))
  );
}

function isControlLoopResult(value: unknown): value is ControlLoopResult {
  if (!isRecord(value)) return false;
  if (value.outcome === "READ_ONLY_COMPLETE") {
    return hasExactKeys(value, ["outcome"]);
  }
  if (
    (value.outcome !== "VERIFIED" && value.outcome !== "REJECTED") ||
    !hasExactKeys(value, [
      "outcome",
      "receiptDigest",
      "executionEvidenceDigest",
      "completedAt",
      "verification",
    ]) ||
    typeof value.receiptDigest !== "string" ||
    !DIGEST_PATTERN.test(value.receiptDigest) ||
    typeof value.executionEvidenceDigest !== "string" ||
    !DIGEST_PATTERN.test(value.executionEvidenceDigest) ||
    !isInstant(value.completedAt) ||
    !isRecord(value.verification) ||
    !hasExactKeys(value.verification, [
      "checks",
      "eventCount",
      "rollbackAvailability",
    ]) ||
    typeof value.verification.eventCount !== "number" ||
    !Number.isSafeInteger(value.verification.eventCount) ||
    !Array.isArray(value.verification.checks)
  ) {
    return false;
  }
  const checksValid = value.verification.checks.every(
    (check, index) =>
      isRecord(check) &&
      hasExactKeys(check, ["checkId", "passed"]) &&
      check.checkId === VERIFICATION_CHECK_IDS[index] &&
      check.passed === true,
  );
  if (!checksValid) return false;
  if (value.outcome === "VERIFIED") {
    return (
      value.verification.checks.length === VERIFICATION_CHECK_IDS.length &&
      value.verification.eventCount === 7 &&
      value.verification.rollbackAvailability === "ELIGIBLE"
    );
  }
  return (
    value.verification.checks.length === 0 &&
    value.verification.eventCount === 5 &&
    value.verification.rollbackAvailability === "NOT_APPLICABLE"
  );
}

function parseControlLoopStatus(
  value: unknown,
  expectedAuditId: string,
): ControlLoopStatus {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(
      value,
      ["schemaVersion", "auditId", "status", "updatedAt"],
      [
        "submittedAt",
        "completedAt",
        "releaseSha",
        "report",
        "approval",
        "manualOnlyReason",
        "result",
      ],
    ) ||
    value.schemaVersion !== "archon.control-loop-status/v1" ||
    value.auditId !== expectedAuditId ||
    ![
      "RUNNING",
      "AWAITING_APPROVAL",
      "SUCCEEDED",
      "FAILED",
      "TIMED_OUT",
      "ABORTED",
    ].includes(String(value.status)) ||
    !isInstant(value.updatedAt) ||
    (value.submittedAt !== undefined && !isInstant(value.submittedAt)) ||
    (value.completedAt !== undefined && !isInstant(value.completedAt)) ||
    (value.report !== undefined && !isAuditReport(value.report)) ||
    (value.releaseSha !== undefined && typeof value.releaseSha !== "string") ||
    (value.report === undefined) !== (value.releaseSha === undefined) ||
    (value.approval !== undefined && !isControlLoopApproval(value.approval)) ||
    (value.manualOnlyReason !== undefined && typeof value.manualOnlyReason !== "string") ||
    (value.result !== undefined && !isControlLoopResult(value.result)) ||
    (value.status === "SUCCEEDED") !== (value.result !== undefined) ||
    (isRecord(value.result) &&
      value.result.outcome === "READ_ONLY_COMPLETE" &&
      value.approval !== undefined) ||
    (isRecord(value.result) &&
      (value.result.outcome === "VERIFIED" || value.result.outcome === "REJECTED") &&
      (!isRecord(value.approval) ||
        value.approval.status !== "DECIDED" ||
        (value.result.outcome === "VERIFIED" && value.approval.decision !== "APPROVE") ||
        (value.result.outcome === "REJECTED" && value.approval.decision !== "REJECT")))
  ) {
    throw new ApiError("The control plane returned an invalid status contract.", 502);
  }
  return value as unknown as ControlLoopStatus;
}

async function jsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new ApiError("The control plane returned a non-JSON response.", response.status || 502);
  }
  const value = await response.json();
  if (!response.ok) {
    const message =
      isRecord(value) && typeof value.message === "string"
        ? value.message
        : `Control-plane request failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  return value;
}

export async function requestAudit(query = "", signal?: AbortSignal): Promise<AuditEnvelope> {
  const response = await fetch(AUDIT_PATH, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(query.trim() ? { query: query.trim() } : {}),
    signal,
  });
  return parseAuditEnvelope(await jsonResponse(response));
}

export async function startControlLoop(
  query = "",
  signal?: AbortSignal,
): Promise<ControlLoopStart> {
  const response = await fetch(CONTROL_LOOP_PATH, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(query.trim() ? { query: query.trim() } : {}),
    signal,
  });
  return parseControlLoopStart(await jsonResponse(response));
}

export async function getControlLoopStatus(
  start: Pick<ControlLoopStart, "auditId" | "pollUrl">,
  signal?: AbortSignal,
): Promise<ControlLoopStatus> {
  if (
    !AUDIT_ID_PATTERN.test(start.auditId) ||
    start.pollUrl !== `${CONTROL_LOOP_PATH}/${start.auditId}`
  ) {
    throw new ApiError("The audit polling capability is invalid.", 400);
  }
  const response = await fetch(start.pollUrl, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal,
  });
  return parseControlLoopStatus(await jsonResponse(response), start.auditId);
}

function canUseFixture(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    (error instanceof ApiError && [404, 502, 503, 504].includes(error.status))
  );
}

function waitForNextPoll(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      window.clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = window.setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function loadedFromStatus(status: ControlLoopStatus): LoadedAudit | undefined {
  if (!status.report || !status.releaseSha) return undefined;
  return {
    envelope: {
      requestId: status.auditId,
      releaseSha: status.releaseSha,
      report: status.report,
    },
    source: "live",
    controlLoop: status,
  };
}

export async function loadAudit(
  query = "",
  signal?: AbortSignal,
  onProgress?: (status: ControlLoopStatus, audit?: LoadedAudit) => void,
): Promise<LoadedAudit> {
  let start: ControlLoopStart;
  try {
    start = await startControlLoop(query, signal);
  } catch (error) {
    if (signal?.aborted) throw error;
    if (!canUseFixture(error)) throw error;
    return {
      envelope: previewAudit,
      source: "fixture",
      fallbackReason:
        "The hosted audit API is unavailable, so this view is using a deterministic, non-mutating showcase dataset.",
    };
  }

  let latest: LoadedAudit | undefined;
  let transientFailures = 0;
  while (!signal?.aborted) {
    let status: ControlLoopStatus;
    try {
      status = await getControlLoopStatus(start, signal);
      transientFailures = 0;
    } catch (error) {
      if (signal?.aborted) throw error;
      if (!canUseFixture(error) || ++transientFailures > 3) throw error;
      await waitForNextPoll(1000 * transientFailures, signal);
      continue;
    }
    latest = loadedFromStatus(status) ?? latest;
    onProgress?.(status, loadedFromStatus(status));
    if (TERMINAL_CONTROL_STATES.has(status.status)) {
      if (status.status === "SUCCEEDED" && latest) return latest;
      throw new ApiError(
        `The durable audit ended with status ${status.status.toLowerCase()}.`,
        502,
      );
    }
    await waitForNextPoll(status.status === "AWAITING_APPROVAL" ? 3000 : 1200, signal);
  }
  throw signal?.reason ?? new DOMException("The audit was cancelled.", "AbortError");
}

export interface SubmitApprovalDecisionInput {
  approvalId: string;
  decision: ApprovalDecision;
  accessToken: string;
  comment?: string;
  signal?: AbortSignal;
}

export async function submitApprovalDecision({
  approvalId,
  decision,
  accessToken,
  comment,
  signal,
}: SubmitApprovalDecisionInput): Promise<ApprovalAck> {
  if (
    accessToken.length < 20 ||
    accessToken.length > 16_384 ||
    /[\s\u0000-\u001F\u007F]/.test(accessToken)
  ) {
    throw new ApiError("A valid steward access token is required.", 401);
  }
  const decisionId = crypto.randomUUID();
  const response = await fetch(
    `/api/approvals/${encodeURIComponent(approvalId)}/decisions`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": decisionId,
      },
      // The browser submits disposition only. The server rehydrates the immutable,
      // digest-bound plan; mutation tools and arguments never cross this trust boundary.
      body: JSON.stringify({
        decision,
        ...(comment?.trim() ? { comment: comment.trim().slice(0, 500) } : {}),
      }),
      signal,
    },
  );
  const value = await jsonResponse(response);
  if (
    !isRecord(value) ||
    value.approvalId !== approvalId ||
    value.decision !== decision ||
    (value.status !== "recorded" && value.status !== "queued") ||
    typeof value.decisionId !== "string"
  ) {
    throw new ApiError("The approval API returned an invalid response contract.", 502);
  }
  return value as unknown as ApprovalAck;
}
