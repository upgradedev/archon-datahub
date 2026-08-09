import type {
  DataHubTagRollbackPort,
  ExecutionReceiptV1,
  RollbackApprovalV1,
  RollbackProposalV1,
  RollbackReceiptV1,
  TagProjection,
  TagProjectionReader,
} from "./contracts.js";
import { digest, verifyDigest, withoutDigest } from "./integrity.js";
import { createRollbackProposal, verifyExecutionReceipt } from "./receipt.js";
import { verifyTagProjection } from "./planner.js";

function instant(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(`${field} must be a canonical ISO-8601 instant.`);
  }
  return parsed;
}

export function createRollbackApproval(input: {
  proposal: RollbackProposalV1;
  decision: "APPROVE" | "REJECT";
  approver: RollbackApprovalV1["approver"];
  decidedAt: string;
}): RollbackApprovalV1 {
  instant(input.decidedAt, "decidedAt");
  if (
    !input.approver.authenticated ||
    !input.approver.subject.trim() ||
    !input.approver.issuer.trim() ||
    !input.approver.roles.includes("DataSteward")
  ) {
    throw new Error("Rollback approval requires an authenticated DataSteward.");
  }
  const unsigned = {
    schemaVersion: "archon.rollback-approval/v1" as const,
    proposalDigest: input.proposal.digest,
    decision: input.decision,
    approver: input.approver,
    decidedAt: input.decidedAt,
  };
  return { ...unsigned, digest: digest(unsigned) };
}

function approvalValid(
  approval: RollbackApprovalV1,
  proposal: RollbackProposalV1
): boolean {
  try {
    return (
      approval.schemaVersion === "archon.rollback-approval/v1" &&
      approval.proposalDigest === proposal.digest &&
      approval.approver.authenticated === true &&
      approval.approver.subject.trim().length > 0 &&
      approval.approver.issuer.trim().length > 0 &&
      approval.approver.roles.includes("DataSteward") &&
      Number.isFinite(instant(approval.decidedAt, "decidedAt")) &&
      verifyDigest(withoutDigest(approval), approval.digest)
    );
  } catch {
    return false;
  }
}

function receipt(input: Omit<RollbackReceiptV1, "schemaVersion" | "digest">): RollbackReceiptV1 {
  const unsigned = { schemaVersion: "archon.rollback-receipt/v1" as const, ...input };
  return { ...unsigned, digest: digest(unsigned) };
}

export function verifyRollbackReceipt(
  value: RollbackReceiptV1,
  proposal?: RollbackProposalV1
): boolean {
  try {
    const structurallyValid =
      value.schemaVersion === "archon.rollback-receipt/v1" &&
      verifyDigest(withoutDigest(value), value.digest) &&
      (value.outcome !== "VERIFIED" ||
        (value.before !== undefined &&
          value.after !== undefined &&
          value.mutation !== undefined &&
          verifyTagProjection(value.before) &&
          verifyTagProjection(value.after)));
    if (!structurallyValid || proposal === undefined) return structurallyValid;
    return (
      value.rollbackId === proposal.rollbackId &&
      value.proposalDigest === proposal.digest &&
      value.originalReceiptDigest === proposal.originalReceiptDigest &&
      (value.outcome !== "VERIFIED" || value.after?.digest === proposal.restoreStateDigest)
    );
  } catch {
    return false;
  }
}

export async function executeApprovedRollback(input: {
  originalReceipt: ExecutionReceiptV1;
  proposal: RollbackProposalV1;
  approval: RollbackApprovalV1;
  reader: TagProjectionReader;
  mutation: DataHubTagRollbackPort;
  clock?: () => string;
}): Promise<RollbackReceiptV1> {
  if (!verifyExecutionReceipt(input.originalReceipt).valid) {
    throw new Error("Rollback requires a valid original execution receipt.");
  }
  if (!approvalValid(input.approval, input.proposal)) {
    throw new Error("Rollback approval is not bound to the exact proposal.");
  }
  if (input.proposal.originalReceiptDigest !== input.originalReceipt.digest) {
    throw new Error("Rollback proposal is not bound to the original receipt.");
  }

  const clock = input.clock ?? (() => new Date().toISOString());
  const startedAt = clock();
  instant(startedAt, "startedAt");
  if (Date.parse(startedAt) < Date.parse(input.approval.decidedAt)) {
    throw new Error("Rollback cannot begin before the approval decision.");
  }
  const base = {
    rollbackId: input.proposal.rollbackId,
    proposalDigest: input.proposal.digest,
    approvalDigest: input.approval.digest,
    originalReceiptDigest: input.originalReceipt.digest,
    startedAt,
  };
  const finish = (
    outcome: RollbackReceiptV1["outcome"],
    evidence: { before?: TagProjection; after?: TagProjection; mutation?: RollbackReceiptV1["mutation"] } = {}
  ): RollbackReceiptV1 => receipt({ ...base, outcome, ...evidence, completedAt: clock() });

  if (input.approval.decision === "REJECT") return finish("REJECTED");

  let before: TagProjection;
  try {
    before = await input.reader.readTagProjection({
      entityUrn: input.originalReceipt.action.arguments.entity_urns[0],
      columnPath: input.originalReceipt.action.arguments.column_paths[0],
    });
  } catch {
    return finish("INDETERMINATE");
  }
  const recreated = createRollbackProposal(input.originalReceipt, before);
  if (!recreated || recreated.digest !== input.proposal.digest) {
    return finish("STALE", { before });
  }

  let mutation: RollbackReceiptV1["mutation"];
  try {
    mutation = await input.mutation.removeTags({
      tagUrns: input.proposal.inverseAction.arguments.tag_urns,
      entityUrns: input.proposal.inverseAction.arguments.entity_urns,
      columnPaths: input.proposal.inverseAction.arguments.column_paths,
    });
  } catch {
    return finish("INDETERMINATE", { before });
  }

  let after: TagProjection;
  try {
    after = await input.reader.readTagProjection({
      entityUrn: input.proposal.inverseAction.arguments.entity_urns[0],
      columnPath: input.proposal.inverseAction.arguments.column_paths[0],
    });
  } catch {
    return finish("INDETERMINATE", { before, mutation });
  }
  const restored =
    verifyTagProjection(after) &&
    after.digest === input.proposal.restoreStateDigest &&
    input.originalReceipt.before?.digest === after.digest;
  return finish(restored ? "VERIFIED" : "VERIFICATION_FAILED", {
    before,
    after,
    mutation,
  });
}
