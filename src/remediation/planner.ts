import type {
  AddClassificationTagActionV1,
  BlastRadius,
  EvidenceDossierV1,
  G6FindingEvidence,
  PlanningResult,
  ProvenanceEvidence,
  RemediationPlanV1,
  TagProjection,
  TrustedRemediationPolicyV1,
} from "./contracts.js";
import { digest, verifyDigest, withoutDigest } from "./integrity.js";

export const ACTION_CATALOG_V1 = Object.freeze({
  schemaVersion: "archon.action-catalog/v1",
  actions: [
    {
      actionId: "datahub.add-classification-tag.v1",
      findingRule: "G6",
      tool: "add_tags",
      rollbackTool: "remove_tags",
      maxEntities: 1,
      maxColumns: 1,
      maxTags: 1,
      entitySource: "DATAHUB_EVIDENCE",
      columnSource: "DATAHUB_EVIDENCE",
      tagSource: "TRUSTED_POLICY",
    },
  ],
} as const);

export const ACTION_CATALOG_DIGEST = digest(ACTION_CATALOG_V1);

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isG6Finding(value: unknown): value is G6FindingEvidence {
  if (!value || typeof value !== "object") return false;
  const finding = value as Partial<G6FindingEvidence>;
  return (
    finding.type === "governance_violation" &&
    finding.ruleId === "G6" &&
    isNonEmptyString(finding.subject) &&
    (finding.severity === "low" || finding.severity === "medium" || finding.severity === "high") &&
    Array.isArray(finding.unclassifiedFields) &&
    finding.unclassifiedFields.every(isNonEmptyString)
  );
}

function sanitizeFinding(finding: G6FindingEvidence): G6FindingEvidence {
  return {
    type: "governance_violation",
    severity: finding.severity,
    subject: finding.subject,
    ruleId: "G6",
    unclassifiedFields: uniqueSorted(finding.unclassifiedFields),
  };
}

export function createTagProjection(input: {
  entityUrn: string;
  columnPath: string;
  tags: readonly string[];
}): TagProjection {
  if (!isNonEmptyString(input.entityUrn) || !isNonEmptyString(input.columnPath)) {
    throw new Error("A tag projection requires a non-empty entity URN and column path.");
  }
  if (!input.tags.every(isNonEmptyString)) {
    throw new Error("A tag projection can contain only non-empty tag identifiers.");
  }
  const unsigned = {
    entityUrn: input.entityUrn,
    columnPath: input.columnPath,
    tags: uniqueSorted(input.tags),
  };
  return { ...unsigned, digest: digest(unsigned) };
}

export function verifyTagProjection(projection: TagProjection): boolean {
  return (
    isNonEmptyString(projection.entityUrn) &&
    isNonEmptyString(projection.columnPath) &&
    Array.isArray(projection.tags) &&
    projection.tags.every(isNonEmptyString) &&
    JSON.stringify(projection.tags) === JSON.stringify(uniqueSorted(projection.tags)) &&
    verifyDigest(withoutDigest(projection), projection.digest)
  );
}

export function createTrustedRemediationPolicy(input: {
  policyId: string;
  enabled: boolean;
  classificationTagUrn: string;
  allowedEntityUrnPrefixes?: readonly string[];
}): TrustedRemediationPolicyV1 {
  if (!isNonEmptyString(input.policyId)) throw new Error("A trusted policy requires a policyId.");
  if (!/^urn:li:tag:[^,\s]+$/u.test(input.classificationTagUrn)) {
    throw new Error("The classification tag must be a DataHub tag URN.");
  }
  const prefixes = uniqueSorted(input.allowedEntityUrnPrefixes ?? []);
  if (!prefixes.every(isNonEmptyString)) {
    throw new Error("Entity allowlist prefixes must be non-empty.");
  }
  const unsigned = {
    schemaVersion: "archon.remediation-policy/v1" as const,
    policyId: input.policyId,
    enabled: input.enabled,
    classificationTagUrn: input.classificationTagUrn,
    allowedEntityUrnPrefixes: prefixes,
  };
  return { ...unsigned, digest: digest(unsigned) };
}

export function verifyTrustedRemediationPolicy(policy: TrustedRemediationPolicyV1): boolean {
  return (
    policy.schemaVersion === "archon.remediation-policy/v1" &&
    /^urn:li:tag:[^,\s]+$/u.test(policy.classificationTagUrn) &&
    JSON.stringify(policy.allowedEntityUrnPrefixes) ===
      JSON.stringify(uniqueSorted(policy.allowedEntityUrnPrefixes)) &&
    verifyDigest(withoutDigest(policy), policy.digest)
  );
}

function normalizedProvenance(values: readonly ProvenanceEvidence[]): ProvenanceEvidence[] {
  return values
    .map((value) => ({
      sourceKind: value.sourceKind,
      entityUrn: value.entityUrn,
      aspect: "schemaMetadata" as const,
      ...(value.aspectVersion === undefined ? {} : { aspectVersion: value.aspectVersion }),
      ...(value.pipelineName === undefined ? {} : { pipelineName: value.pipelineName }),
      ...(value.runId === undefined ? {} : { runId: value.runId }),
      observedAt: value.observedAt,
      valueDigest: value.valueDigest,
    }))
    .sort(
      (a, b) =>
        a.entityUrn.localeCompare(b.entityUrn) ||
        a.observedAt.localeCompare(b.observedAt) ||
        (a.pipelineName ?? "").localeCompare(b.pipelineName ?? "") ||
        (a.runId ?? "").localeCompare(b.runId ?? "")
    );
}

function normalizedBlastRadius(value?: Partial<BlastRadius>): BlastRadius {
  return {
    downstreamUrns: uniqueSorted(value?.downstreamUrns ?? []),
    maxHops: 3,
    truncated: value?.truncated === true,
  };
}

function dossierPayload(dossier: EvidenceDossierV1): Omit<EvidenceDossierV1, "dossierId" | "digest"> {
  const { dossierId: _dossierId, digest: _digest, ...payload } = dossier;
  return payload;
}

function actionPayload(
  action: AddClassificationTagActionV1
): Omit<AddClassificationTagActionV1, "digest"> {
  return withoutDigest(action);
}

function planPayload(plan: RemediationPlanV1): Omit<RemediationPlanV1, "planId" | "digest"> {
  const { planId: _planId, digest: _digest, ...payload } = plan;
  return payload;
}

export function verifyEvidenceDossier(dossier: EvidenceDossierV1): boolean {
  const expected = digest(dossierPayload(dossier));
  return (
    dossier.schemaVersion === "archon.evidence-dossier/v1" &&
    dossier.dossierId === `dossier-${expected.slice("sha256:".length, "sha256:".length + 24)}` &&
    dossier.digest === expected &&
    dossier.findingDigest === digest(dossier.finding) &&
    dossier.finding.type === "governance_violation" &&
    dossier.finding.ruleId === "G6" &&
    dossier.finding.subject === dossier.target.entityUrn &&
    dossier.finding.unclassifiedFields.includes(dossier.target.columnPath) &&
    verifyTagProjection(dossier.before) &&
    dossier.before.entityUrn === dossier.target.entityUrn &&
    dossier.before.columnPath === dossier.target.columnPath
  );
}

export function verifyRemediationPlan(plan: RemediationPlanV1): boolean {
  const expected = digest(planPayload(plan));
  const expectedAfterTags = uniqueSorted([
    ...plan.expectedBefore.tags,
    plan.action.arguments.tag_urns[0],
  ]);
  return (
    plan.schemaVersion === "archon.remediation-plan/v1" &&
    plan.planId === `plan-${expected.slice("sha256:".length, "sha256:".length + 24)}` &&
    plan.digest === expected &&
    plan.actionCatalogDigest === ACTION_CATALOG_DIGEST &&
    plan.requiresHumanApproval === true &&
    plan.risk === "low" &&
    verifyDigest(actionPayload(plan.action), plan.action.digest) &&
    plan.action.actionId === "datahub.add-classification-tag.v1" &&
    plan.action.tool === "add_tags" &&
    plan.action.inverse.tool === "remove_tags" &&
    JSON.stringify(plan.action.arguments) === JSON.stringify(plan.action.inverse.arguments) &&
    verifyTagProjection(plan.expectedBefore) &&
    verifyTagProjection(plan.expectedAfter) &&
    plan.expectedBefore.entityUrn === plan.action.arguments.entity_urns[0] &&
    plan.expectedBefore.columnPath === plan.action.arguments.column_paths[0] &&
    plan.expectedAfter.entityUrn === plan.expectedBefore.entityUrn &&
    plan.expectedAfter.columnPath === plan.expectedBefore.columnPath &&
    JSON.stringify(plan.expectedAfter.tags) === JSON.stringify(expectedAfterTags)
  );
}

export interface PlanG6RemediationInput {
  scanId: string;
  finding: unknown;
  columnPath: string;
  before: TagProjection;
  policy: TrustedRemediationPolicyV1;
  observedAt: string;
  provenance?: readonly ProvenanceEvidence[];
  blastRadius?: Partial<BlastRadius>;
}

export function planG6Remediation(input: PlanG6RemediationInput): PlanningResult {
  if (!isG6Finding(input.finding)) {
    return { disposition: "MANUAL_ONLY", reason: "UNSUPPORTED_FINDING" };
  }
  if (!verifyTrustedRemediationPolicy(input.policy) || !input.policy.enabled) {
    return { disposition: "MANUAL_ONLY", reason: "POLICY_NOT_APPLICABLE" };
  }
  if (!verifyTagProjection(input.before)) {
    return { disposition: "MANUAL_ONLY", reason: "AMBIGUOUS_EVIDENCE" };
  }

  const finding = sanitizeFinding(input.finding);
  if (
    !isNonEmptyString(input.scanId) ||
    !isNonEmptyString(input.observedAt) ||
    !isNonEmptyString(input.columnPath) ||
    finding.subject !== input.before.entityUrn ||
    input.columnPath !== input.before.columnPath ||
    !finding.unclassifiedFields.includes(input.columnPath)
  ) {
    return { disposition: "MANUAL_ONLY", reason: "NO_TRUSTED_TARGET" };
  }
  if (
    input.policy.allowedEntityUrnPrefixes.length > 0 &&
    !input.policy.allowedEntityUrnPrefixes.some((prefix) => finding.subject.startsWith(prefix))
  ) {
    return { disposition: "MANUAL_ONLY", reason: "POLICY_NOT_APPLICABLE" };
  }
  if (input.before.tags.includes(input.policy.classificationTagUrn)) {
    return { disposition: "MANUAL_ONLY", reason: "TAG_ALREADY_PRESENT" };
  }

  const findingDigest = digest(finding);
  const dossierUnsigned = {
    schemaVersion: "archon.evidence-dossier/v1" as const,
    scanId: input.scanId,
    findingDigest,
    finding,
    target: {
      entityUrn: finding.subject,
      columnPath: input.columnPath,
    },
    provenance: normalizedProvenance(input.provenance ?? []),
    blastRadius: normalizedBlastRadius(input.blastRadius),
    before: input.before,
    policyDigest: input.policy.digest,
    createdAt: input.observedAt,
  };
  const dossierDigest = digest(dossierUnsigned);
  const dossier: EvidenceDossierV1 = {
    ...dossierUnsigned,
    dossierId: `dossier-${dossierDigest.slice("sha256:".length, "sha256:".length + 24)}`,
    digest: dossierDigest,
  };

  const arguments_: AddClassificationTagActionV1["arguments"] = {
    tag_urns: [input.policy.classificationTagUrn],
    entity_urns: [finding.subject],
    column_paths: [input.columnPath],
  };
  const actionUnsigned = {
    actionId: "datahub.add-classification-tag.v1" as const,
    tool: "add_tags" as const,
    arguments: arguments_,
    inverse: {
      tool: "remove_tags" as const,
      arguments: {
        tag_urns: [...arguments_.tag_urns] as [string],
        entity_urns: [...arguments_.entity_urns] as [string],
        column_paths: [...arguments_.column_paths] as [string],
      },
    },
  };
  const action: AddClassificationTagActionV1 = {
    ...actionUnsigned,
    digest: digest(actionUnsigned),
  };
  const expectedAfter = createTagProjection({
    entityUrn: input.before.entityUrn,
    columnPath: input.before.columnPath,
    tags: [...input.before.tags, input.policy.classificationTagUrn],
  });
  const planUnsigned = {
    schemaVersion: "archon.remediation-plan/v1" as const,
    dossierDigest: dossier.digest,
    policyDigest: input.policy.digest,
    actionCatalogDigest: ACTION_CATALOG_DIGEST,
    action,
    expectedBefore: input.before,
    expectedAfter,
    risk: "low" as const,
    requiresHumanApproval: true as const,
  };
  const planDigest = digest(planUnsigned);
  const plan: RemediationPlanV1 = {
    ...planUnsigned,
    planId: `plan-${planDigest.slice("sha256:".length, "sha256:".length + 24)}`,
    digest: planDigest,
  };

  return { disposition: "ACTIONABLE", dossier, plan };
}
