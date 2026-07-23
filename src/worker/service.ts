import { randomBytes } from "node:crypto";
import type { DataHubClient } from "../datahub/mcp-client.js";
import type { DataHubMutationClient } from "../datahub/mutation-client.js";
import { AuditPipeline } from "../pipeline/pipeline.js";
import type {
  ApprovalRequestV1,
  ExecutionJournal,
  TagProjectionReader,
} from "../remediation/contracts.js";
import {
  createApprovalDecision,
  createApprovalRequest,
  executeApprovedRemediation,
  verifyApprovalRequest,
} from "../remediation/control-loop.js";
import {
  digest,
  verifyDigest,
  withoutDigest,
  type Sha256Digest,
} from "../remediation/integrity.js";
import {
  createTrustedRemediationPolicy,
  planG6Remediation,
  verifyEvidenceDossier,
  verifyRemediationPlan,
} from "../remediation/planner.js";
import { verifyExecutionReceipt } from "../remediation/receipt.js";
import type { Finding } from "../types.js";
import type {
  ApprovalQueueMessageV1,
  AuditCallbackOutputV1,
  AuditEvidenceV1,
  AuditQueueMessageV1,
  ExecutionEvidenceV1,
  ManualOnlyEvidenceV1,
  RemediationCallbackOutputV1,
  RemediationQueueMessageV1,
} from "./contracts.js";
import { WorkerContractError } from "./contracts.js";

const APPROVAL_WINDOW_MS = 6 * 24 * 60 * 60 * 1000;
const MAX_EVIDENCE_BYTES = 5 * 1024 * 1024;

export interface ImmutableEvidenceStore {
  put(document: AuditEvidenceV1 | ExecutionEvidenceV1): Promise<void>;
  getAuditEvidence(digest: Sha256Digest): Promise<AuditEvidenceV1>;
}

export interface ImmutableEvidenceWriter {
  put(document: AuditEvidenceV1 | ExecutionEvidenceV1): Promise<void>;
}

export interface ImmutableAuditEvidenceReader {
  getAuditEvidence(digest: Sha256Digest): Promise<AuditEvidenceV1>;
}

export interface ApprovalHandoff {
  put(input: {
    message: ApprovalQueueMessageV1;
    request: ApprovalRequestV1;
  }): Promise<"CREATED" | "ALREADY_DURABLE">;
}

export interface AuditResultCheckpoint {
  get(
    executionId: string,
    requestDigest: Sha256Digest
  ): Promise<AuditCallbackOutputV1 | null>;
  put(
    executionId: string,
    requestDigest: Sha256Digest,
    output: AuditCallbackOutputV1
  ): Promise<AuditCallbackOutputV1>;
}

export interface AuditWorkerServiceOptions {
  dataHub: DataHubClient;
  tagReader: TagProjectionReader;
  evidence: ImmutableEvidenceWriter;
  auditCheckpoint?: AuditResultCheckpoint;
  pipeline?: AuditPipeline;
  releaseSha: string;
  clock?: () => string;
  nonce?: () => string;
}

export interface ApprovalHandoffServiceOptions {
  evidence: ImmutableAuditEvidenceReader;
  approvalHandoff: ApprovalHandoff;
}

export interface ExecutionLease {
  readonly signal: AbortSignal;
  assertActive(): Promise<void>;
}

export interface RemediationWorkerServiceOptions {
  tagReader: TagProjectionReader;
  mutation: DataHubMutationClient;
  journal: ExecutionJournal;
  evidence: ImmutableEvidenceStore;
  clock?: () => string;
}

interface G6Candidate {
  finding: Finding;
  columnPath: string;
}

function asG6Candidate(finding: Finding): G6Candidate | null {
  if (
    finding.type !== "governance_violation" ||
    finding.detail["ruleId"] !== "G6" ||
    !Array.isArray(finding.detail["unclassifiedFields"])
  ) {
    return null;
  }
  const fields = finding.detail["unclassifiedFields"];
  if (
    fields.length === 0 ||
    fields.some((field) => typeof field !== "string" || field.trim().length === 0)
  ) {
    return null;
  }
  return {
    finding,
    columnPath: [...new Set(fields as string[])].sort((a, b) => a.localeCompare(b))[0]!,
  };
}

function blastRadius(finding: Finding): {
  downstreamUrns: string[];
  maxHops: 3;
  truncated: boolean;
} {
  const raw = finding.detail["blastRadius"] as
    | { downstream?: unknown; maxHops?: unknown; truncated?: unknown }
    | undefined;
  const downstream = Array.isArray(raw?.downstream)
    ? raw.downstream
        .map((entry) =>
          entry && typeof entry === "object" && typeof (entry as { urn?: unknown }).urn === "string"
            ? (entry as { urn: string }).urn
            : null
        )
        .filter((urn): urn is string => urn !== null)
    : [];
  return {
    downstreamUrns: [...new Set(downstream)].sort((a, b) => a.localeCompare(b)),
    maxHops: 3,
    truncated: raw?.truncated === true || raw?.maxHops !== 3,
  };
}

function evidencePayload(
  evidence: AuditEvidenceV1
): Omit<AuditEvidenceV1, "digest"> {
  return withoutDigest(evidence);
}

function executionEvidencePayload(
  evidence: ExecutionEvidenceV1
): Omit<ExecutionEvidenceV1, "digest"> {
  return withoutDigest(evidence);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function verifyAuditEvidence(
  value: unknown,
  expectedDigest?: Sha256Digest
): value is AuditEvidenceV1 {
  if (!isObject(value)) return false;
  const candidate = value as unknown as AuditEvidenceV1;
  if (
    candidate.schemaVersion !== "archon.audit-evidence/v1" ||
    typeof candidate.digest !== "string" ||
    (expectedDigest !== undefined && candidate.digest !== expectedDigest)
  ) {
    return false;
  }
  try {
    if (
      !verifyDigest(evidencePayload(candidate), candidate.digest) ||
      candidate.reportDigest !== digest(candidate.report) ||
      !candidate.request ||
      candidate.request.schemaVersion !== "archon.audit-request/v1" ||
      !candidate.report ||
      typeof candidate.report.scanId !== "string" ||
      !Array.isArray(candidate.report.findings) ||
      !Array.isArray(candidate.report.trace)
    ) {
      return false;
    }
    if (candidate.remediation.disposition === "MANUAL_ONLY") {
      return [
        "READ_ONLY_REQUEST",
        "NO_ACTIONABLE_G6_FINDING",
        "REMEDIATION_PRESTATE_UNAVAILABLE",
        "POLICY_REJECTED_PROPOSAL",
      ].includes(candidate.remediation.reason);
    }
    const { dossier, plan, approvalRequest } = candidate.remediation;
    return (
      candidate.remediation.disposition === "ACTIONABLE" &&
      verifyEvidenceDossier(dossier) &&
      verifyRemediationPlan(plan) &&
      verifyApprovalRequest(approvalRequest) &&
      plan.dossierDigest === dossier.digest &&
      approvalRequest.dossierDigest === dossier.digest &&
      approvalRequest.planDigest === plan.digest &&
      approvalRequest.actionCatalogDigest === plan.actionCatalogDigest &&
      approvalRequest.expectedBeforeDigest === plan.expectedBefore.digest
    );
  } catch {
    return false;
  }
}

function contentAddressedAuditEvidence(
  value: Omit<AuditEvidenceV1, "digest">
): AuditEvidenceV1 {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > MAX_EVIDENCE_BYTES) {
    throw new WorkerContractError("INVALID_EVIDENCE", "Audit evidence exceeds the worker limit.");
  }
  return { ...value, digest: digest(value) };
}

function contentAddressedExecutionEvidence(
  value: Omit<ExecutionEvidenceV1, "digest">
): ExecutionEvidenceV1 {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > MAX_EVIDENCE_BYTES) {
    throw new WorkerContractError(
      "INVALID_EVIDENCE",
      "Execution evidence exceeds the worker limit."
    );
  }
  return { ...value, digest: digest(value) };
}

function trustedPolicy() {
  return createTrustedRemediationPolicy({
    policyId: "archon.g6.pii-classification.v1",
    enabled: true,
    classificationTagUrn: "urn:li:tag:PII",
    allowedEntityUrnPrefixes: ["urn:li:dataset:"],
  });
}

export class AuditWorkerService {
  readonly #pipeline: AuditPipeline;
  readonly #clock: () => string;
  readonly #nonce: () => string;

  constructor(private readonly options: AuditWorkerServiceOptions) {
    this.#pipeline = options.pipeline ?? new AuditPipeline();
    this.#clock = options.clock ?? (() => new Date().toISOString());
    this.#nonce = options.nonce ?? (() => randomBytes(24).toString("hex"));
  }

  async audit(message: AuditQueueMessageV1): Promise<AuditCallbackOutputV1> {
    const requestDigest = digest(message.request);
    const checkpoint = await this.options.auditCheckpoint?.get(
      message.executionId,
      requestDigest
    );
    if (checkpoint) return checkpoint;

    const report = await this.#pipeline.run(
      this.options.dataHub,
      message.request.query,
      { executionProfile: "async-worker" }
    );
    const createdAt = this.#clock();
    const candidate =
      message.request.mode === "READ_ONLY"
        ? undefined
        : report.findings
            .map(asG6Candidate)
            .find((value): value is G6Candidate => value !== null);

    let remediation: AuditEvidenceV1["remediation"];
    if (message.request.mode === "READ_ONLY") {
      remediation = {
        disposition: "MANUAL_ONLY",
        reason: "READ_ONLY_REQUEST",
      };
    } else if (!candidate) {
      remediation = {
        disposition: "MANUAL_ONLY",
        reason: "NO_ACTIONABLE_G6_FINDING",
      };
    } else {
      try {
        const before = await this.options.tagReader.readTagProjection({
          entityUrn: candidate.finding.subject,
          columnPath: candidate.columnPath,
        });
        const planned = planG6Remediation({
          scanId: report.scanId,
          finding: {
            type: "governance_violation",
            severity: candidate.finding.severity,
            subject: candidate.finding.subject,
            ruleId: "G6",
            unclassifiedFields: (
              candidate.finding.detail["unclassifiedFields"] as string[]
            ).slice(),
          },
          columnPath: candidate.columnPath,
          before,
          policy: trustedPolicy(),
          observedAt: createdAt,
          provenance: [
            {
              sourceKind: "current_view",
              entityUrn: candidate.finding.subject,
              aspect: "schemaMetadata",
              observedAt: createdAt,
              valueDigest: before.digest,
            },
          ],
          blastRadius: blastRadius(candidate.finding),
        });
        if (planned.disposition === "ACTIONABLE") {
          const expiresAt = new Date(Date.parse(createdAt) + APPROVAL_WINDOW_MS).toISOString();
          remediation = {
            disposition: "ACTIONABLE",
            dossier: planned.dossier,
            plan: planned.plan,
            approvalRequest: createApprovalRequest({
              dossier: planned.dossier,
              plan: planned.plan,
              requestedAt: createdAt,
              expiresAt,
              nonce: this.#nonce(),
            }),
          };
        } else {
          remediation = {
            disposition: "MANUAL_ONLY",
            reason: "POLICY_REJECTED_PROPOSAL",
          };
        }
      } catch {
        remediation = {
          disposition: "MANUAL_ONLY",
          reason: "REMEDIATION_PRESTATE_UNAVAILABLE",
        };
      }
    }

    const unsigned: Omit<AuditEvidenceV1, "digest"> = {
      schemaVersion: "archon.audit-evidence/v1",
      executionId: message.executionId,
      request: message.request,
      releaseSha: this.options.releaseSha,
      report,
      reportDigest: digest(report),
      remediation,
      createdAt,
    };
    const evidence = contentAddressedAuditEvidence(unsigned);
    await this.options.evidence.put(evidence);

    const output: AuditCallbackOutputV1 =
      remediation.disposition === "ACTIONABLE"
        ? {
            schemaVersion: "archon.audit-result/v1",
            requiresApproval: true,
            reportDigest: evidence.reportDigest,
            evidenceDigest: evidence.digest,
            approvalId: remediation.approvalRequest.approvalId,
            planDigest: remediation.plan.digest,
            approvalRequestDigest: remediation.approvalRequest.digest,
            approvalRequestedAt: remediation.approvalRequest.requestedAt,
            approvalExpiresAt: remediation.approvalRequest.expiresAt,
          }
        : {
            schemaVersion: "archon.audit-result/v1",
            requiresApproval: false,
            reportDigest: evidence.reportDigest,
            evidenceDigest: evidence.digest,
            manualOnlyReason: remediation.reason,
          };
    return this.options.auditCheckpoint
      ? this.options.auditCheckpoint.put(message.executionId, requestDigest, output)
      : output;
  }
}

export class ApprovalHandoffService {
  constructor(private readonly options: ApprovalHandoffServiceOptions) {}

  async handoffApproval(
    message: ApprovalQueueMessageV1
  ): Promise<"CREATED" | "ALREADY_DURABLE"> {
    const evidence = await this.options.evidence.getAuditEvidence(message.evidenceDigest);
    if (
      !verifyAuditEvidence(evidence, message.evidenceDigest) ||
      evidence.executionId !== message.executionId ||
      evidence.remediation.disposition !== "ACTIONABLE" ||
      evidence.remediation.plan.digest !== message.planDigest ||
      evidence.remediation.approvalRequest.approvalId !== message.approvalId ||
      evidence.remediation.approvalRequest.digest !== message.approvalRequestDigest ||
      evidence.remediation.approvalRequest.requestedAt !== message.requestedAt ||
      evidence.remediation.approvalRequest.expiresAt !== message.expiresAt
    ) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Approval message is not bound to immutable audit evidence."
      );
    }
    return this.options.approvalHandoff.put({
      message,
      request: evidence.remediation.approvalRequest,
    });
  }
}

export class RemediationWorkerService {
  readonly #clock: () => string;

  constructor(private readonly options: RemediationWorkerServiceOptions) {
    this.#clock = options.clock ?? (() => new Date().toISOString());
  }

  async remediate(
    message: RemediationQueueMessageV1,
    lease?: ExecutionLease
  ): Promise<RemediationCallbackOutputV1> {
    const evidence = await this.options.evidence.getAuditEvidence(message.evidenceDigest);
    if (
      !verifyAuditEvidence(evidence, message.evidenceDigest) ||
      evidence.executionId !== message.executionId ||
      evidence.remediation.disposition !== "ACTIONABLE" ||
      evidence.remediation.plan.digest !== message.planDigest ||
      evidence.remediation.approvalRequest.approvalId !== message.approvalId
    ) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Remediation message is not bound to immutable audit evidence."
      );
    }

    const artifacts = evidence.remediation;
    const decision = createApprovalDecision({
      request: artifacts.approvalRequest,
      plan: artifacts.plan,
      decision: message.approvalResult.decision.decision,
      approver: message.approvalResult.decision.approver,
      decidedAt: message.approvalResult.decision.decidedAt,
    });
    const idempotencyKey = digest({
      schemaVersion: "archon.worker-execution-key/v1",
      executionId: message.executionId,
      approvalId: message.approvalId,
      decisionDigest: decision.digest,
    });
    const receipt = await executeApprovedRemediation({
      dossier: artifacts.dossier,
      plan: artifacts.plan,
      request: artifacts.approvalRequest,
      decision,
      reader: this.options.tagReader,
      mutation: {
        addTags: async (input) => {
          await lease?.assertActive();
          return this.options.mutation.addTags(input, {
            ...(lease ? { signal: lease.signal } : {}),
            timeoutMs: 120_000,
          });
        },
      },
      journal: this.options.journal,
      idempotencyKey,
      clock: this.#clock,
    });
    if (!verifyExecutionReceipt(receipt).valid) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "The remediation receipt failed local integrity verification."
      );
    }
    const executionEvidence = contentAddressedExecutionEvidence({
      schemaVersion: "archon.execution-evidence/v1",
      executionId: message.executionId,
      approvalId: message.approvalId,
      auditEvidenceDigest: evidence.digest,
      decision,
      receipt,
      createdAt: receipt.completedAt,
    });
    if (!verifyDigest(executionEvidencePayload(executionEvidence), executionEvidence.digest)) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Execution evidence could not be content-addressed."
      );
    }
    await this.options.evidence.put(executionEvidence);
    return {
      schemaVersion: "archon.remediation-result/v1",
      approvalId: message.approvalId,
      planDigest: artifacts.plan.digest,
      evidenceDigest: evidence.digest,
      receiptDigest: receipt.digest,
      executionEvidenceDigest: executionEvidence.digest,
      outcome: receipt.outcome,
    };
  }
}
