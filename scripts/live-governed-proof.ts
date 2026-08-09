import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createDataHubClient } from "../src/datahub/mcp-client.js";
import { LiveDataHubMutationClient } from "../src/datahub/mutation-client-live.js";
import { DirectGmsTagProjectionReader } from "../src/datahub/tag-projection-reader-live.js";
import type {
  AuthenticatedApprover,
  RollbackProposalV1,
  RollbackReceiptV1,
} from "../src/remediation/contracts.js";
import { InMemoryExecutionJournal } from "../src/remediation/control-loop.js";
import {
  canonicalize,
  digest,
  verifyDigest,
  withoutDigest,
} from "../src/remediation/integrity.js";
import { createRollbackProposal, verifyExecutionReceipt } from "../src/remediation/receipt.js";
import {
  createRollbackApproval,
  executeApprovedRollback,
  verifyRollbackReceipt,
} from "../src/remediation/rollback.js";
import type {
  AuditEvidenceV1,
  ExecutionEvidenceV1,
} from "../src/worker/contracts.js";
import {
  AuditWorkerService,
  type ImmutableEvidenceStore,
  RemediationWorkerService,
  verifyAuditEvidence,
} from "../src/worker/service.js";
import {
  type ApprovalOperation,
  expectedApprovalComment,
  verifiedApproverFromReceipt,
} from "./github-environment-approval.js";

type EvidenceDocument = AuditEvidenceV1 | ExecutionEvidenceV1;

function required(name: string, max = 4096): string {
  const value = process.env[name];
  if (!value || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${name} is required and must contain bounded printable text.`);
  }
  return value;
}

function instant(): string {
  return new Date().toISOString();
}

class FileEvidenceStore implements ImmutableEvidenceStore {
  constructor(readonly directory: string) {}

  async put(document: EvidenceDocument): Promise<void> {
    const name =
      document.schemaVersion === "archon.audit-evidence/v1"
        ? "audit-evidence.json"
        : "execution-evidence.json";
    await writeCanonical(this.path(name), document);
  }

  async getAuditEvidence(expectedDigest: AuditEvidenceV1["digest"]): Promise<AuditEvidenceV1> {
    const evidence = await readCanonical<AuditEvidenceV1>(this.path("audit-evidence.json"));
    if (!verifyAuditEvidence(evidence, expectedDigest)) {
      throw new Error("Audit evidence failed its content and contract verification.");
    }
    return evidence;
  }

  path(name: string): string {
    return resolve(this.directory, name);
  }
}

async function writeCanonical(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${canonicalize(value as never)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function readCanonical<T>(path: string): Promise<T> {
  const raw = await readFile(path, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 8 * 1024 * 1024 || !raw.endsWith("\n")) {
    throw new Error("Proof artifact envelope is invalid.");
  }
  const parsed = JSON.parse(raw) as T;
  if (`${canonicalize(parsed as never)}\n` !== raw) {
    throw new Error("Proof artifact is not canonical JSON.");
  }
  return parsed;
}

function reader(): DirectGmsTagProjectionReader {
  return new DirectGmsTagProjectionReader({
    gmsUrl: required("DATAHUB_GMS_URL"),
    loopbackDemo: "SYNTHETIC_DEMO_ONLY",
    requestTimeoutMs: 15_000,
  });
}

function mutation(): LiveDataHubMutationClient {
  process.env.DATAHUB_WRITE_GMS_URL = required("DATAHUB_GMS_URL");
  delete process.env.DATAHUB_WRITE_GMS_TOKEN;
  delete process.env.DATAHUB_WRITE_MCP_URL;
  return new LiveDataHubMutationClient(undefined, {
    loopbackDemo: "SYNTHETIC_DEMO_ONLY",
  });
}

async function verifiedApprover(
  store: FileEvidenceStore,
  operation: ApprovalOperation,
  planDigest: string
): Promise<AuthenticatedApprover & { roles: ["DataSteward"] }> {
  const receipt = await readCanonical<unknown>(store.path(`approval-${operation}.json`));
  return verifiedApproverFromReceipt(receipt, {
    repository: required("GITHUB_REPOSITORY", 128),
    workflowRunId: required("GITHUB_RUN_ID", 32),
    workflowRunAttempt: required("GITHUB_RUN_ATTEMPT", 8),
    environment: required("ARCHON_APPROVAL_ENVIRONMENT", 128),
    reviewerLogin: required("GITHUB_REPOSITORY_OWNER", 64),
    operation,
    planDigest,
  });
}

async function prepare(store: FileEvidenceStore): Promise<void> {
  const query = required("ARCHON_DEMO_QUERY", 512);
  const executionId = `live-proof-${required("GITHUB_RUN_ID", 32)}-${required("GITHUB_RUN_ATTEMPT", 8)}`;
  const service = new AuditWorkerService({
    dataHub: await createDataHubClient(),
    tagReader: reader(),
    evidence: store,
    releaseSha: required("GITHUB_SHA", 40),
    // This proof is deliberately scoped to one exact dataset. Reusing the
    // broad durable-worker budget would turn a 25-second canary into a
    // 90-minute execution window without increasing evidence quality.
    executionProfile: "synchronous-preview",
  });
  const result = await service.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "local-proof-task-token",
    executionId,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: `proof-${required("GITHUB_RUN_ID", 32)}`,
      requestedAt: instant(),
      query,
      mode: "GOVERNED",
    },
  });
  if (!result.requiresApproval || !result.approvalId || !result.planDigest) {
    throw new Error("Live audit did not produce one actionable G6 remediation.");
  }
  const approvalContext = {
    workflowRunId: required("GITHUB_RUN_ID", 32),
    workflowRunAttempt: required("GITHUB_RUN_ATTEMPT", 8),
    planDigest: result.planDigest,
  };
  const writeComment = expectedApprovalComment({
    ...approvalContext,
    operation: "write",
  });
  const rollbackComment = expectedApprovalComment({
    ...approvalContext,
    operation: "rollback",
  });
  await appendFile(
    required("GITHUB_STEP_SUMMARY"),
    [
      "### Exact human approval comments",
      "",
      `- Write: \`${writeComment}\``,
      `- Rollback or baseline recovery: \`${rollbackComment}\``,
      "",
      "The protected-environment reviewer must paste the matching comment exactly.",
      "",
    ].join("\n"),
    "utf8"
  );
  await writeCanonical(store.path("prepare-summary.json"), {
    schemaVersion: "archon.live-proof-prepare/v1",
    executionId,
    reportDigest: result.reportDigest,
    evidenceDigest: result.evidenceDigest,
    approvalId: result.approvalId,
    planDigest: result.planDigest,
    preparedAt: instant(),
  });
}

async function execute(store: FileEvidenceStore): Promise<void> {
  if (required("ARCHON_PROOF_CONFIRMATION", 128) !== "APPROVE SYNTHETIC G6 WRITE") {
    throw new Error("The exact forward-write confirmation is required.");
  }
  const evidence = await readCanonical<AuditEvidenceV1>(store.path("audit-evidence.json"));
  if (!verifyAuditEvidence(evidence, evidence.digest) || evidence.remediation.disposition !== "ACTIONABLE") {
    throw new Error("Actionable audit evidence is invalid.");
  }
  const artifacts = evidence.remediation;
  const approvalActor = await verifiedApprover(store, "write", artifacts.plan.digest);
  const service = new RemediationWorkerService({
    tagReader: reader(),
    mutation: mutation(),
    journal: new InMemoryExecutionJournal(),
    evidence: store,
  });
  const result = await service.remediate({
    type: "REMEDIATION_REQUESTED",
    taskToken: "local-proof-task-token",
    executionId: evidence.executionId,
    approvalId: artifacts.approvalRequest.approvalId,
    planDigest: artifacts.plan.digest,
    evidenceDigest: evidence.digest,
    approvalResult: {
      approvalId: artifacts.approvalRequest.approvalId,
      decision: {
        decision: "APPROVE",
        approver: approvalActor,
        decidedAt: instant(),
      },
    },
  });
  if (result.outcome !== "VERIFIED") {
    throw new Error(`Forward mutation was not verified (${result.outcome}).`);
  }
  const execution = await readCanonical<ExecutionEvidenceV1>(store.path("execution-evidence.json"));
  if (
    !verifyDigest(withoutDigest(execution), execution.digest) ||
    !verifyExecutionReceipt(execution.receipt).valid
  ) {
    throw new Error("Execution evidence failed local verification.");
  }
  const current = await reader().readTagProjection(artifacts.dossier.target);
  const rollback = createRollbackProposal(execution.receipt, current);
  if (!rollback) throw new Error("Verified execution did not produce a safe rollback proposal.");
  await writeCanonical(store.path("rollback-proposal.json"), rollback);
  await writeCanonical(store.path("execute-summary.json"), {
    schemaVersion: "archon.live-proof-execute/v1",
    executionEvidenceDigest: execution.digest,
    receiptDigest: execution.receipt.digest,
    rollbackProposalDigest: rollback.digest,
    outcome: result.outcome,
    executedAt: instant(),
  });
}

async function rollback(store: FileEvidenceStore): Promise<void> {
  if (required("ARCHON_PROOF_CONFIRMATION", 128) !== "APPROVE SYNTHETIC G6 ROLLBACK") {
    throw new Error("The exact rollback confirmation is required.");
  }
  const audit = await readCanonical<AuditEvidenceV1>(store.path("audit-evidence.json"));
  if (!verifyAuditEvidence(audit, audit.digest) || audit.remediation.disposition !== "ACTIONABLE") {
    throw new Error("Prepared recovery evidence is invalid.");
  }
  const approvalActor = await verifiedApprover(store, "rollback", audit.remediation.plan.digest);
  try {
    const execution = await readCanonical<ExecutionEvidenceV1>(store.path("execution-evidence.json"));
    const proposal = await readCanonical<RollbackProposalV1>(store.path("rollback-proposal.json"));
    if (
      !verifyDigest(withoutDigest(execution), execution.digest) ||
      !verifyExecutionReceipt(execution.receipt).valid ||
      !verifyDigest(withoutDigest(proposal), proposal.digest)
    ) {
      throw new Error("Rollback inputs failed local verification.");
    }
    const approval = createRollbackApproval({
      proposal,
      decision: "APPROVE",
      approver: approvalActor,
      decidedAt: instant(),
    });
    const receipt: RollbackReceiptV1 = await executeApprovedRollback({
      originalReceipt: execution.receipt,
      proposal,
      approval,
      reader: reader(),
      mutation: mutation(),
    });
    if (receipt.outcome !== "VERIFIED" || !verifyRollbackReceipt(receipt, proposal)) {
      throw new Error(`Rollback was not verified (${receipt.outcome}).`);
    }
    await writeCanonical(store.path("rollback-receipt.json"), receipt);
    await writeCanonical(store.path("rollback-summary.json"), {
      schemaVersion: "archon.live-proof-rollback/v1",
      rollbackReceiptDigest: receipt.digest,
      originalReceiptDigest: receipt.originalReceiptDigest,
      outcome: receipt.outcome,
      restoredAt: receipt.completedAt,
    });
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
    await recoverPreparedBaseline(store, audit, approvalActor);
  }
}

async function recoverPreparedBaseline(
  store: FileEvidenceStore,
  audit: AuditEvidenceV1,
  approvalActor: AuthenticatedApprover
): Promise<void> {
  if (audit.remediation.disposition !== "ACTIONABLE") {
    throw new Error("Prepared recovery evidence is not actionable.");
  }
  const { dossier, plan } = audit.remediation;
  const startedAt = instant();
  const before = await reader().readTagProjection(dossier.target);
  let mutationReceipt: Awaited<ReturnType<LiveDataHubMutationClient["removeTags"]>> | undefined;
  let disposition: "already-baseline" | "restored";
  if (before.digest === plan.expectedBefore.digest) {
    disposition = "already-baseline";
  } else if (before.digest === plan.expectedAfter.digest) {
    mutationReceipt = await mutation().removeTags({
      tagUrns: plan.action.inverse.arguments.tag_urns,
      entityUrns: plan.action.inverse.arguments.entity_urns,
      columnPaths: plan.action.inverse.arguments.column_paths,
    });
    disposition = "restored";
  } else {
    throw new Error("Current DataHub state matches neither the prepared baseline nor post-state.");
  }
  const after = await reader().readTagProjection(dossier.target);
  if (after.digest !== plan.expectedBefore.digest) {
    throw new Error("Prepared baseline recovery did not restore the exact pre-state.");
  }
  const unsigned = {
    schemaVersion: "archon.live-proof-recovery/v1" as const,
    auditEvidenceDigest: audit.digest,
    planDigest: plan.digest,
    expectedBeforeDigest: plan.expectedBefore.digest,
    observedBeforeDigest: before.digest,
    observedAfterDigest: after.digest,
    disposition,
    approvedBy: approvalActor,
    ...(mutationReceipt ? { mutation: mutationReceipt } : {}),
    startedAt,
    completedAt: instant(),
  };
  const recovery = { ...unsigned, digest: digest(unsigned) };
  await writeCanonical(store.path("rollback-summary.json"), recovery);
}

async function main(): Promise<void> {
  const root = resolve(required("ARCHON_PROOF_DIR"));
  await mkdir(root, { recursive: true });
  const store = new FileEvidenceStore(root);
  const operation = process.argv[2];
  if (operation === "prepare") await prepare(store);
  else if (operation === "execute") await execute(store);
  else if (operation === "rollback") await rollback(store);
  else throw new Error("Expected prepare, execute, or rollback.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : "Live proof failed."}\n`);
    process.exitCode = 1;
  });
}
