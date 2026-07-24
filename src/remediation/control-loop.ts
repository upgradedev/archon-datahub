import type {
  ApprovalDecisionV1,
  ApprovalRequestV1,
  AuthenticatedApprover,
  DataHubTagMutationPort,
  EvidenceDossierV1,
  ExecutionJournal,
  ExecutionReceiptV1,
  MutationAck,
  RemediationPlanV1,
  RollbackAnchor,
  TagProjection,
  TagProjectionReader,
  VerificationCheck,
} from "./contracts.js";
import { digest, verifyDigest, withoutDigest, type Sha256Digest } from "./integrity.js";
import {
  verifyEvidenceDossier,
  verifyRemediationPlan,
  verifyTagProjection,
} from "./planner.js";
import { createExecutionReceipt } from "./receipt.js";

export type RemediationErrorCode =
  | "INVALID_ARTIFACT"
  | "APPROVAL_BINDING_MISMATCH"
  | "APPROVAL_EXPIRED"
  | "APPROVER_UNAUTHORIZED"
  | "APPROVAL_REPLAY"
  | "EXECUTION_IN_PROGRESS"
  | "JOURNAL_STATE_ERROR";

export class RemediationError extends Error {
  constructor(
    public readonly code: RemediationErrorCode,
    message: string
  ) {
    super(message);
    this.name = "RemediationError";
  }
}

export class DefinitiveMutationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DefinitiveMutationError";
  }
}

function instant(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new RemediationError("INVALID_ARTIFACT", `${label} must be an ISO-8601 timestamp.`);
  }
  return parsed;
}

function approvalRequestPayload(
  request: ApprovalRequestV1
): Omit<ApprovalRequestV1, "approvalId" | "digest"> {
  const { approvalId: _approvalId, digest: _digest, ...payload } = request;
  return payload;
}

function approvalDecisionPayload(
  decision: ApprovalDecisionV1
): Omit<ApprovalDecisionV1, "digest"> {
  return withoutDigest(decision);
}

export function verifyApprovalRequest(request: ApprovalRequestV1): boolean {
  const expected = digest(approvalRequestPayload(request));
  return (
    request.schemaVersion === "archon.approval-request/v1" &&
    request.approvalId ===
      `approval-${expected.slice("sha256:".length, "sha256:".length + 24)}` &&
    request.digest === expected &&
    request.nonce.length >= 8 &&
    Number.isFinite(Date.parse(request.requestedAt)) &&
    Date.parse(request.expiresAt) > Date.parse(request.requestedAt)
  );
}

export function verifyApprovalDecision(decision: ApprovalDecisionV1): boolean {
  return (
    decision.schemaVersion === "archon.approval-decision/v1" &&
    decision.approver.authenticated === true &&
    decision.approver.subject.length > 0 &&
    decision.approver.issuer.length > 0 &&
    decision.approver.roles.includes("DataSteward") &&
    JSON.stringify(decision.approver.roles) ===
      JSON.stringify([...new Set(decision.approver.roles)].sort((a, b) => a.localeCompare(b))) &&
    Number.isFinite(Date.parse(decision.decidedAt)) &&
    verifyDigest(approvalDecisionPayload(decision), decision.digest)
  );
}

export function createApprovalRequest(input: {
  dossier: EvidenceDossierV1;
  plan: RemediationPlanV1;
  requestedAt: string;
  expiresAt: string;
  nonce: string;
}): ApprovalRequestV1 {
  if (
    !verifyEvidenceDossier(input.dossier) ||
    !verifyRemediationPlan(input.plan) ||
    input.plan.dossierDigest !== input.dossier.digest ||
    input.plan.policyDigest !== input.dossier.policyDigest
  ) {
    throw new RemediationError("INVALID_ARTIFACT", "Dossier and plan binding is invalid.");
  }
  if (input.nonce.length < 8) {
    throw new RemediationError("INVALID_ARTIFACT", "Approval nonce must contain at least 8 characters.");
  }
  if (instant(input.expiresAt, "expiresAt") <= instant(input.requestedAt, "requestedAt")) {
    throw new RemediationError("INVALID_ARTIFACT", "Approval expiry must follow its request time.");
  }

  const unsigned = {
    schemaVersion: "archon.approval-request/v1" as const,
    dossierDigest: input.dossier.digest,
    planDigest: input.plan.digest,
    actionCatalogDigest: input.plan.actionCatalogDigest,
    expectedBeforeDigest: input.plan.expectedBefore.digest,
    requestedAt: input.requestedAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
  const requestDigest = digest(unsigned);
  return {
    ...unsigned,
    approvalId: `approval-${requestDigest.slice("sha256:".length, "sha256:".length + 24)}`,
    digest: requestDigest,
  };
}

export function createApprovalDecision(input: {
  request: ApprovalRequestV1;
  plan: RemediationPlanV1;
  decision: "APPROVE" | "REJECT";
  approver: AuthenticatedApprover;
  decidedAt: string;
}): ApprovalDecisionV1 {
  if (
    !verifyApprovalRequest(input.request) ||
    !verifyRemediationPlan(input.plan) ||
    input.request.planDigest !== input.plan.digest ||
    input.request.actionCatalogDigest !== input.plan.actionCatalogDigest ||
    input.request.expectedBeforeDigest !== input.plan.expectedBefore.digest
  ) {
    throw new RemediationError(
      "APPROVAL_BINDING_MISMATCH",
      "Approval request does not bind the supplied plan."
    );
  }
  if (
    input.approver.authenticated !== true ||
    !input.approver.roles.includes("DataSteward") ||
    input.approver.subject.trim().length === 0 ||
    input.approver.issuer.trim().length === 0
  ) {
    throw new RemediationError(
      "APPROVER_UNAUTHORIZED",
      "An authenticated DataSteward is required."
    );
  }
  const decidedAt = instant(input.decidedAt, "decidedAt");
  if (
    decidedAt < instant(input.request.requestedAt, "requestedAt") ||
    decidedAt > instant(input.request.expiresAt, "expiresAt")
  ) {
    throw new RemediationError("APPROVAL_EXPIRED", "Approval was decided outside its validity window.");
  }

  const approver: AuthenticatedApprover = {
    subject: input.approver.subject,
    issuer: input.approver.issuer,
    roles: [...new Set(input.approver.roles)].sort((a, b) => a.localeCompare(b)),
    authenticated: true,
  };
  const unsigned = {
    schemaVersion: "archon.approval-decision/v1" as const,
    approvalId: input.request.approvalId,
    requestDigest: input.request.digest,
    planDigest: input.plan.digest,
    decision: input.decision,
    approver,
    decidedAt: input.decidedAt,
  };
  return { ...unsigned, digest: digest(unsigned) };
}

function projectionEquals(a: TagProjection, b: TagProjection): boolean {
  return a.digest === b.digest;
}

function mutationRequest(plan: RemediationPlanV1): {
  tagUrns: readonly string[];
  entityUrns: readonly string[];
  columnPaths: readonly (string | null)[];
} {
  return {
    tagUrns: [...plan.action.arguments.tag_urns],
    entityUrns: [...plan.action.arguments.entity_urns],
    columnPaths: [...plan.action.arguments.column_paths],
  };
}

export function verifyPostcondition(input: {
  plan: RemediationPlanV1;
  approvalValid: boolean;
  after: TagProjection;
  mutation?: MutationAck;
}): VerificationCheck[] {
  const { plan, after } = input;
  const before = plan.expectedBefore;
  const tag = plan.action.arguments.tag_urns[0];
  const expectedRequestDigest = digest(mutationRequest(plan));
  const targetUnchanged =
    after.entityUrn === before.entityUrn && after.columnPath === before.columnPath;
  const preserved = before.tags.every((existing) => after.tags.includes(existing));
  const tagPresent = after.tags.includes(tag);
  const exactAfter = projectionEquals(after, plan.expectedAfter);
  const approvalAndRequestValid =
    input.approvalValid &&
    input.mutation !== undefined &&
    input.mutation.requestDigest === expectedRequestDigest;

  return [
    {
      checkId: "TARGET_UNCHANGED",
      passed: targetUnchanged,
      evidence: `Observed ${after.entityUrn}#${after.columnPath}.`,
    },
    {
      checkId: "PREEXISTING_TAGS_PRESERVED",
      passed: preserved,
      evidence: `${before.tags.length} pre-existing tag(s) remain present.`,
    },
    {
      checkId: "POLICY_TAG_PRESENT",
      passed: tagPresent,
      evidence: `Policy tag ${tag} ${tagPresent ? "is" : "is not"} present.`,
    },
    {
      checkId: "NO_UNEXPECTED_TAGS",
      passed: exactAfter,
      evidence: `After-state digest ${after.digest}; expected ${plan.expectedAfter.digest}.`,
    },
    {
      checkId: "APPROVAL_BINDING_VALID",
      passed: approvalAndRequestValid,
      evidence: `Mutation request digest ${input.mutation?.requestDigest ?? "unavailable"}.`,
    },
  ];
}

function approvalArtifactsValid(input: {
  dossier: EvidenceDossierV1;
  plan: RemediationPlanV1;
  request: ApprovalRequestV1;
  decision: ApprovalDecisionV1;
}): boolean {
  return (
    verifyEvidenceDossier(input.dossier) &&
    verifyRemediationPlan(input.plan) &&
    verifyApprovalRequest(input.request) &&
    verifyApprovalDecision(input.decision) &&
    input.plan.dossierDigest === input.dossier.digest &&
    input.plan.policyDigest === input.dossier.policyDigest &&
    input.request.dossierDigest === input.dossier.digest &&
    input.request.planDigest === input.plan.digest &&
    input.request.actionCatalogDigest === input.plan.actionCatalogDigest &&
    input.request.expectedBeforeDigest === input.plan.expectedBefore.digest &&
    input.decision.approvalId === input.request.approvalId &&
    input.decision.requestDigest === input.request.digest &&
    input.decision.planDigest === input.plan.digest &&
    Date.parse(input.decision.decidedAt) >= Date.parse(input.request.requestedAt) &&
    Date.parse(input.decision.decidedAt) <= Date.parse(input.request.expiresAt)
  );
}

export class InMemoryExecutionJournal implements ExecutionJournal {
  private static readonly LEASE_MILLISECONDS = 10 * 60 * 1_000;
  private readonly byIdempotencyKey = new Map<
    string,
    {
      approvalId: string;
      approvalDecisionDigest: Sha256Digest;
      fencingToken: number;
      leaseExpiresAt: number;
      status: "IN_PROGRESS" | "RECONCILING" | "COMPLETED";
      receipt?: ExecutionReceiptV1;
    }
  >();
  private readonly approvalToIdempotencyKey = new Map<string, string>();

  constructor(
    private readonly now: () => number = () => Date.now(),
    private readonly leaseMilliseconds = InMemoryExecutionJournal.LEASE_MILLISECONDS
  ) {}

  async claim(input: {
    approvalId: string;
    approvalDecisionDigest: Sha256Digest;
    idempotencyKey: string;
  }) {
    const now = this.now();
    const existing = this.byIdempotencyKey.get(input.idempotencyKey);
    if (existing) {
      if (
        existing.approvalId !== input.approvalId ||
        existing.approvalDecisionDigest !== input.approvalDecisionDigest
      ) {
        return { disposition: "APPROVAL_ALREADY_USED" as const };
      }
      if (existing.receipt) {
        return { disposition: "COMPLETED" as const, receipt: existing.receipt };
      }
      if (existing.leaseExpiresAt > now) {
        return { disposition: "IN_PROGRESS" as const };
      }
      existing.fencingToken += 1;
      existing.leaseExpiresAt = now + this.leaseMilliseconds;
      existing.status = "RECONCILING";
      return {
        disposition: "RECONCILE" as const,
        fencingToken: existing.fencingToken,
      };
    }

    const existingKey = this.approvalToIdempotencyKey.get(input.approvalId);
    if (existingKey !== undefined) {
      return { disposition: "APPROVAL_ALREADY_USED" as const };
    }

    this.byIdempotencyKey.set(input.idempotencyKey, {
      approvalId: input.approvalId,
      approvalDecisionDigest: input.approvalDecisionDigest,
      fencingToken: 1,
      leaseExpiresAt: now + this.leaseMilliseconds,
      status: "IN_PROGRESS",
    });
    this.approvalToIdempotencyKey.set(input.approvalId, input.idempotencyKey);
    return { disposition: "CLAIMED" as const, fencingToken: 1 };
  }

  async complete(
    lease: { idempotencyKey: string; fencingToken: number },
    receipt: ExecutionReceiptV1
  ): Promise<void> {
    const existing = this.byIdempotencyKey.get(lease.idempotencyKey);
    if (!existing || existing.fencingToken !== lease.fencingToken) {
      throw new RemediationError(
        "EXECUTION_IN_PROGRESS",
        "A newer worker owns this execution lease."
      );
    }
    if (
      receipt.idempotencyKey !== lease.idempotencyKey ||
      receipt.approvalDecisionDigest !== existing.approvalDecisionDigest
    ) {
      throw new RemediationError(
        "JOURNAL_STATE_ERROR",
        "Receipt binding does not match the claimed execution."
      );
    }
    if (existing.receipt) {
      if (existing.receipt.digest === receipt.digest) return;
      throw new RemediationError(
        "JOURNAL_STATE_ERROR",
        "A completed execution cannot be replaced."
      );
    }
    if (existing.status !== "IN_PROGRESS" && existing.status !== "RECONCILING") {
      throw new RemediationError(
        "JOURNAL_STATE_ERROR",
        "Cannot complete an execution outside an active lease."
      );
    }
    existing.receipt = receipt;
    existing.status = "COMPLETED";
  }

  async resume(lease: {
    idempotencyKey: string;
    fencingToken: number;
  }): Promise<boolean> {
    const now = this.now();
    const existing = this.byIdempotencyKey.get(lease.idempotencyKey);
    if (
      !existing ||
      existing.receipt ||
      existing.status !== "RECONCILING" ||
      existing.fencingToken !== lease.fencingToken ||
      existing.leaseExpiresAt < now
    ) {
      return false;
    }
    existing.status = "IN_PROGRESS";
    existing.leaseExpiresAt = now + this.leaseMilliseconds;
    return true;
  }
}

function executionId(decision: ApprovalDecisionV1, idempotencyKey: string): string {
  const value = digest({ decisionDigest: decision.digest, idempotencyKey });
  return `execution-${value.slice("sha256:".length, "sha256:".length + 24)}`;
}

async function terminalReceipt(input: {
  dossier: EvidenceDossierV1;
  plan: RemediationPlanV1;
  decision: ApprovalDecisionV1;
  journal: ExecutionJournal;
  idempotencyKey: string;
  fencingToken: number;
  outcome: ExecutionReceiptV1["outcome"];
  startedAt: string;
  completedAt: string;
  before?: TagProjection;
  after?: TagProjection;
  mutation?: MutationAck;
  checks?: VerificationCheck[];
  rollback?: RollbackAnchor;
}): Promise<ExecutionReceiptV1> {
  const receipt = createExecutionReceipt({
    executionId: executionId(input.decision, input.idempotencyKey),
    outcome: input.outcome,
    dossierDigest: input.dossier.digest,
    planDigest: input.plan.digest,
    approvalDecisionDigest: input.decision.digest,
    action: input.plan.action,
    idempotencyKey: input.idempotencyKey,
    ...(input.before ? { before: input.before } : {}),
    ...(input.after ? { after: input.after } : {}),
    ...(input.mutation ? { mutation: input.mutation } : {}),
    checks: input.checks ?? [],
    rollback: input.rollback ?? { availability: "NOT_APPLICABLE" },
    startedAt: input.startedAt,
    completedAt: input.completedAt,
  });
  await input.journal.complete(
    {
      idempotencyKey: input.idempotencyKey,
      fencingToken: input.fencingToken,
    },
    receipt
  );
  return receipt;
}

export interface ExecuteApprovedRemediationInput {
  dossier: EvidenceDossierV1;
  plan: RemediationPlanV1;
  request: ApprovalRequestV1;
  decision: ApprovalDecisionV1;
  reader: TagProjectionReader;
  mutation: DataHubTagMutationPort;
  journal: ExecutionJournal;
  idempotencyKey: string;
  clock?: () => string;
}

export async function executeApprovedRemediation(
  input: ExecuteApprovedRemediationInput
): Promise<ExecutionReceiptV1> {
  if (!approvalArtifactsValid(input)) {
    throw new RemediationError(
      "APPROVAL_BINDING_MISMATCH",
      "Execution artifacts do not share one immutable approval binding."
    );
  }
  if (!input.idempotencyKey.trim()) {
    throw new RemediationError("INVALID_ARTIFACT", "An idempotency key is required.");
  }

  const clock = input.clock ?? (() => new Date().toISOString());
  const startedAt = clock();
  instant(startedAt, "startedAt");
  if (instant(startedAt, "startedAt") < instant(input.decision.decidedAt, "decidedAt")) {
    throw new RemediationError(
      "INVALID_ARTIFACT",
      "Execution cannot begin before the bound approval decision."
    );
  }

  const claim = await input.journal.claim({
    approvalId: input.request.approvalId,
    approvalDecisionDigest: input.decision.digest,
    idempotencyKey: input.idempotencyKey,
  });
  if (claim.disposition === "COMPLETED") return claim.receipt;
  if (claim.disposition === "IN_PROGRESS") {
    throw new RemediationError("EXECUTION_IN_PROGRESS", "This execution is already in progress.");
  }
  if (claim.disposition === "APPROVAL_ALREADY_USED") {
    throw new RemediationError("APPROVAL_REPLAY", "This approval has already been consumed.");
  }
  const receiptBinding = {
    dossier: input.dossier,
    plan: input.plan,
    decision: input.decision,
    journal: input.journal,
    idempotencyKey: input.idempotencyKey,
    fencingToken: claim.fencingToken,
  };

  if (claim.disposition === "RECONCILE") {
    let observed: TagProjection | undefined;
    try {
      observed = await input.reader.readTagProjection(input.dossier.target);
    } catch {
      return terminalReceipt({
        ...receiptBinding,
        outcome: "INDETERMINATE",
        startedAt,
        completedAt: clock(),
        rollback: {
          availability: "BLOCKED",
          reason:
            "A stale execution lease was recovered, but current DataHub state could not be read.",
        },
      });
    }
    if (
      verifyTagProjection(observed) &&
      observed.digest === input.plan.expectedBefore.digest
    ) {
      if (
        !(await input.journal.resume({
          idempotencyKey: input.idempotencyKey,
          fencingToken: claim.fencingToken,
        }))
      ) {
        throw new RemediationError(
          "EXECUTION_IN_PROGRESS",
          "Another worker acquired the recovered execution lease."
        );
      }
    } else {
      return terminalReceipt({
        ...receiptBinding,
        outcome: "INDETERMINATE",
        startedAt,
        completedAt: clock(),
        after: verifyTagProjection(observed) ? observed : undefined,
        rollback: {
          availability: "BLOCKED",
          reason:
            observed.digest === input.plan.expectedAfter.digest
              ? "The approved post-state exists, but the interrupted mutation response is unavailable."
              : "Current DataHub state diverged while recovering a stale execution lease.",
        },
      });
    }
  }

  if (input.decision.decision === "REJECT") {
    return terminalReceipt({
      ...receiptBinding,
      outcome: "REJECTED",
      startedAt,
      completedAt: clock(),
    });
  }
  if (instant(startedAt, "startedAt") > instant(input.request.expiresAt, "expiresAt")) {
    return terminalReceipt({
      ...receiptBinding,
      outcome: "EXPIRED",
      startedAt,
      completedAt: clock(),
    });
  }

  let current: TagProjection;
  try {
    current = await input.reader.readTagProjection(input.dossier.target);
  } catch {
    return terminalReceipt({
      ...receiptBinding,
      outcome: "STALE",
      startedAt,
      completedAt: clock(),
      rollback: { availability: "BLOCKED", reason: "Current DataHub state could not be read." },
    });
  }
  if (!verifyTagProjection(current) || current.digest !== input.plan.expectedBefore.digest) {
    return terminalReceipt({
      ...receiptBinding,
      outcome: "STALE",
      startedAt,
      completedAt: clock(),
      before: verifyTagProjection(current) ? current : undefined,
      rollback: {
        availability: "BLOCKED",
        reason: "The approved pre-state changed before execution.",
      },
    });
  }

  let mutation: MutationAck | undefined;
  try {
    mutation = await input.mutation.addTags(mutationRequest(input.plan));
  } catch (error) {
    let observed: TagProjection | undefined;
    try {
      observed = await input.reader.readTagProjection(input.dossier.target);
    } catch {
      // The outcome is deliberately left indeterminate when neither the mutation
      // response nor a read-after-write observation is available.
    }
    return terminalReceipt({
      ...receiptBinding,
      outcome: error instanceof DefinitiveMutationError ? "MUTATION_FAILED" : "INDETERMINATE",
      startedAt,
      completedAt: clock(),
      before: current,
      ...(observed && verifyTagProjection(observed) ? { after: observed } : {}),
      rollback: {
        availability: "BLOCKED",
        reason:
          error instanceof DefinitiveMutationError
            ? "DataHub definitively rejected the mutation."
            : "Mutation outcome could not be proven.",
      },
    });
  }

  let after: TagProjection;
  try {
    after = await input.reader.readTagProjection(input.dossier.target);
  } catch {
    return terminalReceipt({
      ...receiptBinding,
      outcome: "INDETERMINATE",
      startedAt,
      completedAt: clock(),
      before: current,
      mutation,
      rollback: {
        availability: "BLOCKED",
        reason: "Read-after-write failed; the mutation outcome is unknown.",
      },
    });
  }

  const checks = verifyPostcondition({
    plan: input.plan,
    approvalValid: true,
    after,
    mutation,
  });
  const verified = checks.every((check) => check.passed);
  const rollback: RollbackAnchor = verified
    ? {
        availability: "ELIGIBLE",
        inverseActionDigest: digest(input.plan.action.inverse),
        restoreStateDigest: current.digest,
      }
    : {
        availability: "BLOCKED",
        reason: "Postconditions did not prove the exact approved state transition.",
      };

  return terminalReceipt({
    ...receiptBinding,
    outcome: verified ? "VERIFIED" : "VERIFICATION_FAILED",
    startedAt,
    completedAt: clock(),
    before: current,
    after,
    mutation,
    checks,
    rollback,
  });
}
