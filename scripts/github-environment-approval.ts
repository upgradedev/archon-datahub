import type { AuthenticatedApprover } from "../src/remediation/contracts.js";

export type ApprovalOperation = "write" | "rollback";

export interface ExpectedGitHubApproval {
  repository: string;
  workflowRunId: string;
  workflowRunAttempt: string;
  environment: string;
  reviewerLogin: string;
  operation: ApprovalOperation;
  planDigest: string;
}

export function expectedApprovalComment(
  approval: Pick<
    ExpectedGitHubApproval,
    "workflowRunId" | "workflowRunAttempt" | "operation" | "planDigest"
  >
): string {
  return `APPROVE ARCHON GOVERNED PROOF run_id=${approval.workflowRunId} run_attempt=${approval.workflowRunAttempt} operation=${approval.operation} plan_digest=${approval.planDigest}`;
}

function exactObject(
  value: unknown,
  keys: string[],
  label: string
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has unexpected fields.`);
  }
  return record;
}

export function verifiedApproverFromReceipt(
  value: unknown,
  expected: ExpectedGitHubApproval
): AuthenticatedApprover & { roles: ["DataSteward"] } {
  const receipt = exactObject(
    value,
    [
      "schemaVersion",
      "repository",
      "workflowRunId",
      "workflowRunAttempt",
      "operation",
      "planDigest",
      "state",
      "comment",
      "environment",
      "reviewer",
    ],
    "GitHub approval receipt"
  );
  const environment = exactObject(receipt["environment"], ["name", "id"], "environment");
  const reviewer = exactObject(receipt["reviewer"], ["login", "id"], "reviewer");
  const environmentId = environment["id"];
  const reviewerId = reviewer["id"];
  const reviewerLogin = reviewer["login"];
  const validEnvironmentId =
    typeof environmentId === "number" &&
    Number.isSafeInteger(environmentId) &&
    environmentId > 0;
  const validReviewerId =
    typeof reviewerId === "number" && Number.isSafeInteger(reviewerId) && reviewerId > 0;
  const validReviewerLogin =
    typeof reviewerLogin === "string" &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u.test(reviewerLogin);
  if (
    receipt["schemaVersion"] !== "archon.github-environment-approval/v1" ||
    receipt["repository"] !== expected.repository ||
    receipt["workflowRunId"] !== expected.workflowRunId ||
    receipt["workflowRunAttempt"] !== expected.workflowRunAttempt ||
    receipt["operation"] !== expected.operation ||
    receipt["planDigest"] !== expected.planDigest ||
    receipt["state"] !== "approved" ||
    receipt["comment"] !== expectedApprovalComment(expected) ||
    environment["name"] !== expected.environment ||
    !validEnvironmentId ||
    !validReviewerId ||
    !validReviewerLogin ||
    (reviewerLogin as string).toLowerCase() !== expected.reviewerLogin.toLowerCase()
  ) {
    throw new Error("GitHub approval receipt is not bound to the exact reviewer event.");
  }
  return {
    subject: `github-user:${reviewerLogin as string}#${reviewerId as number}`,
    issuer: "https://api.github.com",
    roles: ["DataSteward"],
    authenticated: true,
  };
}
