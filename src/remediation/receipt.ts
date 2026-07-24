import type {
  AddClassificationTagActionV1,
  ExecutionOutcome,
  ExecutionReceiptV1,
  MutationAck,
  ReceiptEvent,
  RollbackAnchor,
  RollbackProposalV1,
  TagProjection,
  VerificationCheck,
} from "./contracts.js";
import { digest, verifyDigest, withoutDigest } from "./integrity.js";
import { verifyTagProjection } from "./planner.js";

const GENESIS_HASH = digest("archon-execution-receipt-chain-genesis-v1");

function actionValid(action: AddClassificationTagActionV1): boolean {
  try {
    return (
      action.actionId === "datahub.add-classification-tag.v1" &&
      action.tool === "add_tags" &&
      action.inverse.tool === "remove_tags" &&
      JSON.stringify(action.arguments) === JSON.stringify(action.inverse.arguments) &&
      verifyDigest(withoutDigest(action), action.digest)
    );
  } catch {
    return false;
  }
}

interface ReceiptEventPayload {
  kind: ReceiptEvent["kind"];
  payload: unknown;
  occurredAt: string;
}

function eventPayloads(input: {
  dossierDigest: ExecutionReceiptV1["dossierDigest"];
  planDigest: ExecutionReceiptV1["planDigest"];
  approvalDecisionDigest?: ExecutionReceiptV1["approvalDecisionDigest"];
  before?: TagProjection;
  after?: TagProjection;
  mutation?: MutationAck;
  checks: VerificationCheck[];
  rollback: RollbackAnchor;
  startedAt: string;
  completedAt: string;
}): ReceiptEventPayload[] {
  const values: ReceiptEventPayload[] = [
    {
      kind: "DOSSIER_BOUND",
      payload: { dossierDigest: input.dossierDigest },
      occurredAt: input.startedAt,
    },
    {
      kind: "PLAN_BOUND",
      payload: { planDigest: input.planDigest },
      occurredAt: input.startedAt,
    },
  ];
  if (input.approvalDecisionDigest) {
    values.push({
      kind: "APPROVAL_BOUND",
      payload: { approvalDecisionDigest: input.approvalDecisionDigest },
      occurredAt: input.startedAt,
    });
  }
  values.push({
    kind: "PRECONDITION_CHECKED",
    payload: { beforeDigest: input.before?.digest ?? null },
    occurredAt: input.startedAt,
  });
  if (input.mutation) {
    values.push({
      kind: "MUTATION_INVOKED",
      payload: {
        requestDigest: input.mutation.requestDigest,
        responseDigest: input.mutation.responseDigest,
      },
      occurredAt: input.completedAt,
    });
  }
  if (input.after || input.checks.length > 0) {
    values.push({
      kind: "POSTCONDITION_CHECKED",
      payload: { afterDigest: input.after?.digest ?? null, checks: input.checks },
      occurredAt: input.completedAt,
    });
  }
  values.push({
    kind: "ROLLBACK_ANCHORED",
    payload: input.rollback,
    occurredAt: input.completedAt,
  });
  return values;
}

function buildEvents(values: readonly ReceiptEventPayload[]): ReceiptEvent[] {
  let previousHash = GENESIS_HASH;
  return values.map((value, index) => {
    const unsigned = {
      sequence: index,
      kind: value.kind,
      occurredAt: value.occurredAt,
      payloadDigest: digest(value.payload),
      previousHash,
    };
    const event: ReceiptEvent = { ...unsigned, eventHash: digest(unsigned) };
    previousHash = event.eventHash;
    return event;
  });
}

function receiptPayload(
  receipt: ExecutionReceiptV1
): Omit<ExecutionReceiptV1, "receiptId" | "digest"> {
  const { receiptId: _receiptId, digest: _digest, ...payload } = receipt;
  return payload;
}

function expectedCheckPasses(receipt: ExecutionReceiptV1): Map<VerificationCheck["checkId"], boolean> {
  const before = receipt.before;
  const after = receipt.after;
  const tag = receipt.action.arguments.tag_urns[0];
  const expectedRequestDigest = digest({
    tagUrns: [...receipt.action.arguments.tag_urns],
    entityUrns: [...receipt.action.arguments.entity_urns],
    columnPaths: [...receipt.action.arguments.column_paths],
  });
  return new Map<VerificationCheck["checkId"], boolean>([
    [
      "TARGET_UNCHANGED",
      Boolean(
        before &&
          after &&
          before.entityUrn === after.entityUrn &&
          before.columnPath === after.columnPath
      ),
    ],
    [
      "PREEXISTING_TAGS_PRESERVED",
      Boolean(before && after && before.tags.every((existing) => after.tags.includes(existing))),
    ],
    ["POLICY_TAG_PRESENT", Boolean(after?.tags.includes(tag))],
    [
      "NO_UNEXPECTED_TAGS",
      Boolean(
        before &&
          after &&
          JSON.stringify(after.tags) ===
            JSON.stringify([...new Set([...before.tags, tag])].sort((a, b) => a.localeCompare(b)))
      ),
    ],
    [
      "APPROVAL_BINDING_VALID",
      Boolean(
        receipt.approvalDecisionDigest &&
          receipt.mutation?.requestDigest === expectedRequestDigest
      ),
    ],
  ]);
}

export interface CreateExecutionReceiptInput {
  executionId: string;
  outcome: ExecutionOutcome;
  dossierDigest: ExecutionReceiptV1["dossierDigest"];
  planDigest: ExecutionReceiptV1["planDigest"];
  approvalDecisionDigest?: ExecutionReceiptV1["approvalDecisionDigest"];
  action: AddClassificationTagActionV1;
  idempotencyKey: string;
  before?: TagProjection;
  after?: TagProjection;
  mutation?: MutationAck;
  checks: VerificationCheck[];
  rollback: RollbackAnchor;
  startedAt: string;
  completedAt: string;
}

export function createExecutionReceipt(input: CreateExecutionReceiptInput): ExecutionReceiptV1 {
  if (!actionValid(input.action)) throw new Error("Cannot issue a receipt for an invalid action.");
  if (!input.executionId || !input.idempotencyKey) {
    throw new Error("A receipt requires an execution id and idempotency key.");
  }
  if (input.before && !verifyTagProjection(input.before)) {
    throw new Error("Receipt before-state has an invalid digest.");
  }
  if (input.after && !verifyTagProjection(input.after)) {
    throw new Error("Receipt after-state has an invalid digest.");
  }

  const events = buildEvents(eventPayloads(input));
  const unsigned = {
    schemaVersion: "archon.execution-receipt/v1" as const,
    executionId: input.executionId,
    outcome: input.outcome,
    dossierDigest: input.dossierDigest,
    planDigest: input.planDigest,
    ...(input.approvalDecisionDigest
      ? { approvalDecisionDigest: input.approvalDecisionDigest }
      : {}),
    action: input.action,
    idempotencyKey: input.idempotencyKey,
    ...(input.before ? { before: input.before } : {}),
    ...(input.after ? { after: input.after } : {}),
    ...(input.mutation ? { mutation: input.mutation } : {}),
    checks: input.checks,
    rollback: input.rollback,
    events,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
  };
  const receiptDigest = digest(unsigned);
  return {
    ...unsigned,
    receiptId: `receipt-${receiptDigest.slice("sha256:".length, "sha256:".length + 24)}`,
    digest: receiptDigest,
  };
}

export interface ReceiptVerification {
  valid: boolean;
  issues: string[];
}

function verifyExecutionReceiptUnsafe(receipt: ExecutionReceiptV1): ReceiptVerification {
  const issues: string[] = [];
  const expectedDigest = digest(receiptPayload(receipt));
  if (receipt.schemaVersion !== "archon.execution-receipt/v1") issues.push("SCHEMA_VERSION");
  if (receipt.digest !== expectedDigest) issues.push("RECEIPT_DIGEST");
  if (
    receipt.receiptId !==
    `receipt-${expectedDigest.slice("sha256:".length, "sha256:".length + 24)}`
  ) {
    issues.push("RECEIPT_ID");
  }
  if (!actionValid(receipt.action)) issues.push("ACTION_DIGEST");
  if (receipt.before && !verifyTagProjection(receipt.before)) issues.push("BEFORE_DIGEST");
  if (receipt.after && !verifyTagProjection(receipt.after)) issues.push("AFTER_DIGEST");
  if (
    receipt.mutation &&
    receipt.mutation.requestDigest !==
      digest({
        tagUrns: [...receipt.action.arguments.tag_urns],
        entityUrns: [...receipt.action.arguments.entity_urns],
        columnPaths: [...receipt.action.arguments.column_paths],
      })
  ) {
    issues.push("MUTATION_REQUEST_BINDING");
  }

  const expectedPayloads = eventPayloads(receipt);
  if (expectedPayloads.length !== receipt.events.length) {
    issues.push("EVENT_COUNT");
  } else {
    let previousHash = GENESIS_HASH;
    for (let index = 0; index < receipt.events.length; index += 1) {
      const event = receipt.events[index]!;
      const expected = expectedPayloads[index]!;
      const expectedUnsigned = {
        sequence: index,
        kind: expected.kind,
        occurredAt: event.occurredAt,
        payloadDigest: digest(expected.payload),
        previousHash,
      };
      if (
        event.sequence !== index ||
        event.kind !== expected.kind ||
        event.payloadDigest !== expectedUnsigned.payloadDigest ||
        event.previousHash !== previousHash ||
        event.eventHash !== digest(expectedUnsigned)
      ) {
        issues.push(`EVENT_${index}`);
      }
      previousHash = event.eventHash;
    }
  }

  if (receipt.outcome === "VERIFIED") {
    if (!receipt.before || !receipt.after || !receipt.mutation) {
      issues.push("VERIFIED_COMPONENTS");
    }
    if (receipt.checks.length !== 5 || receipt.checks.some((check) => !check.passed)) {
      issues.push("VERIFIED_CHECKS");
    }
    if (receipt.rollback.availability !== "ELIGIBLE") issues.push("ROLLBACK_ANCHOR");
  }
  if (receipt.checks.length > 0) {
    const expected = expectedCheckPasses(receipt);
    const expectedIds = [...expected.keys()];
    if (
      receipt.checks.length !== expectedIds.length ||
      receipt.checks.some(
        (check, index) =>
          check.checkId !== expectedIds[index] || check.passed !== expected.get(check.checkId)
      )
    ) {
      issues.push("CHECK_SEMANTICS");
    }
  }
  if (
    receipt.rollback.availability === "ELIGIBLE" &&
    (!receipt.before ||
      !receipt.after ||
      receipt.rollback.inverseActionDigest !== digest(receipt.action.inverse) ||
      receipt.rollback.restoreStateDigest !== receipt.before.digest)
  ) {
    issues.push("ROLLBACK_BINDING");
  }

  return { valid: issues.length === 0, issues };
}

export function verifyExecutionReceipt(receipt: ExecutionReceiptV1): ReceiptVerification {
  try {
    return verifyExecutionReceiptUnsafe(receipt);
  } catch {
    return { valid: false, issues: ["MALFORMED_RECEIPT"] };
  }
}

function rollbackPayload(
  proposal: RollbackProposalV1
): Omit<RollbackProposalV1, "rollbackId" | "digest"> {
  const { rollbackId: _rollbackId, digest: _digest, ...payload } = proposal;
  return payload;
}

export function createRollbackProposal(
  receipt: ExecutionReceiptV1,
  current: TagProjection
): RollbackProposalV1 | null {
  if (!verifyExecutionReceipt(receipt).valid) return null;
  if (
    receipt.outcome !== "VERIFIED" ||
    receipt.rollback.availability !== "ELIGIBLE" ||
    !receipt.before ||
    !receipt.after ||
    !verifyTagProjection(current) ||
    current.digest !== receipt.after.digest
  ) {
    return null;
  }

  const tag = receipt.action.arguments.tag_urns[0];
  if (receipt.before.tags.includes(tag) || !receipt.after.tags.includes(tag)) return null;

  const unsigned = {
    schemaVersion: "archon.rollback-proposal/v1" as const,
    originalReceiptDigest: receipt.digest,
    expectedCurrentDigest: current.digest,
    restoreStateDigest: receipt.before.digest,
    inverseAction: receipt.action.inverse,
    requiresFreshApproval: true as const,
  };
  const proposalDigest = digest(unsigned);
  const proposal: RollbackProposalV1 = {
    ...unsigned,
    rollbackId: `rollback-${proposalDigest.slice("sha256:".length, "sha256:".length + 24)}`,
    digest: proposalDigest,
  };
  if (
    !verifyDigest(rollbackPayload(proposal), proposal.digest) ||
    proposal.rollbackId !==
      `rollback-${proposal.digest.slice("sha256:".length, "sha256:".length + 24)}`
  ) {
    throw new Error("Failed to bind rollback proposal.");
  }
  return proposal;
}
