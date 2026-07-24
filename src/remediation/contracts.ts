import type { Sha256Digest } from "./integrity.js";

export type RemediationSeverity = "low" | "medium" | "high";

export interface TagProjection {
  entityUrn: string;
  columnPath: string;
  tags: string[];
  digest: Sha256Digest;
}

export interface G6FindingEvidence {
  type: "governance_violation";
  severity: RemediationSeverity;
  subject: string;
  ruleId: "G6";
  unclassifiedFields: string[];
}

export interface ProvenanceEvidence {
  sourceKind: "current_view" | "aspect_version";
  entityUrn: string;
  aspect: "schemaMetadata";
  aspectVersion?: number;
  pipelineName?: string;
  runId?: string;
  observedAt: string;
  valueDigest: Sha256Digest;
}

export interface BlastRadius {
  downstreamUrns: string[];
  maxHops: 3;
  truncated: boolean;
}

export interface TrustedRemediationPolicyV1 {
  schemaVersion: "archon.remediation-policy/v1";
  policyId: string;
  enabled: boolean;
  classificationTagUrn: string;
  allowedEntityUrnPrefixes: string[];
  digest: Sha256Digest;
}

export interface EvidenceDossierV1 {
  schemaVersion: "archon.evidence-dossier/v1";
  dossierId: string;
  scanId: string;
  findingDigest: Sha256Digest;
  finding: G6FindingEvidence;
  target: {
    entityUrn: string;
    columnPath: string;
  };
  provenance: ProvenanceEvidence[];
  blastRadius: BlastRadius;
  before: TagProjection;
  policyDigest: Sha256Digest;
  createdAt: string;
  digest: Sha256Digest;
}

export interface TagMutationArguments {
  tag_urns: [string];
  entity_urns: [string];
  column_paths: [string];
}

export interface AddClassificationTagActionV1 {
  actionId: "datahub.add-classification-tag.v1";
  tool: "add_tags";
  arguments: TagMutationArguments;
  inverse: {
    tool: "remove_tags";
    arguments: TagMutationArguments;
  };
  digest: Sha256Digest;
}

export interface RemediationPlanV1 {
  schemaVersion: "archon.remediation-plan/v1";
  planId: string;
  dossierDigest: Sha256Digest;
  policyDigest: Sha256Digest;
  actionCatalogDigest: Sha256Digest;
  action: AddClassificationTagActionV1;
  expectedBefore: TagProjection;
  expectedAfter: TagProjection;
  risk: "low";
  requiresHumanApproval: true;
  digest: Sha256Digest;
}

export type ManualOnlyReason =
  | "UNSUPPORTED_FINDING"
  | "NO_TRUSTED_TARGET"
  | "TAG_ALREADY_PRESENT"
  | "POLICY_NOT_APPLICABLE"
  | "AMBIGUOUS_EVIDENCE";

export type PlanningResult =
  | {
      disposition: "ACTIONABLE";
      dossier: EvidenceDossierV1;
      plan: RemediationPlanV1;
    }
  | {
      disposition: "MANUAL_ONLY";
      reason: ManualOnlyReason;
      dossierDigest?: Sha256Digest;
    };

export interface ApprovalRequestV1 {
  schemaVersion: "archon.approval-request/v1";
  approvalId: string;
  dossierDigest: Sha256Digest;
  planDigest: Sha256Digest;
  actionCatalogDigest: Sha256Digest;
  expectedBeforeDigest: Sha256Digest;
  requestedAt: string;
  expiresAt: string;
  nonce: string;
  digest: Sha256Digest;
}

export interface AuthenticatedApprover {
  subject: string;
  issuer: string;
  roles: string[];
  authenticated: true;
}

export interface ApprovalDecisionV1 {
  schemaVersion: "archon.approval-decision/v1";
  approvalId: string;
  requestDigest: Sha256Digest;
  planDigest: Sha256Digest;
  decision: "APPROVE" | "REJECT";
  approver: AuthenticatedApprover;
  decidedAt: string;
  digest: Sha256Digest;
}

export type ExecutionOutcome =
  | "VERIFIED"
  | "REJECTED"
  | "EXPIRED"
  | "STALE"
  | "MUTATION_FAILED"
  | "INDETERMINATE"
  | "VERIFICATION_FAILED";

export interface VerificationCheck {
  checkId:
    | "TARGET_UNCHANGED"
    | "PREEXISTING_TAGS_PRESERVED"
    | "POLICY_TAG_PRESENT"
    | "NO_UNEXPECTED_TAGS"
    | "APPROVAL_BINDING_VALID";
  passed: boolean;
  evidence: string;
}

export interface MutationAck {
  requestDigest: Sha256Digest;
  responseDigest: Sha256Digest;
}

export interface ReceiptEvent {
  sequence: number;
  kind:
    | "DOSSIER_BOUND"
    | "PLAN_BOUND"
    | "APPROVAL_BOUND"
    | "PRECONDITION_CHECKED"
    | "MUTATION_INVOKED"
    | "POSTCONDITION_CHECKED"
    | "ROLLBACK_ANCHORED";
  occurredAt: string;
  payloadDigest: Sha256Digest;
  previousHash: Sha256Digest;
  eventHash: Sha256Digest;
}

export interface RollbackAnchor {
  availability: "ELIGIBLE" | "BLOCKED" | "NOT_APPLICABLE";
  inverseActionDigest?: Sha256Digest;
  restoreStateDigest?: Sha256Digest;
  reason?: string;
}

export interface ExecutionReceiptV1 {
  schemaVersion: "archon.execution-receipt/v1";
  receiptId: string;
  executionId: string;
  outcome: ExecutionOutcome;
  dossierDigest: Sha256Digest;
  planDigest: Sha256Digest;
  approvalDecisionDigest?: Sha256Digest;
  action: AddClassificationTagActionV1;
  idempotencyKey: string;
  before?: TagProjection;
  after?: TagProjection;
  mutation?: MutationAck;
  checks: VerificationCheck[];
  rollback: RollbackAnchor;
  events: ReceiptEvent[];
  startedAt: string;
  completedAt: string;
  digest: Sha256Digest;
}

export interface RollbackProposalV1 {
  schemaVersion: "archon.rollback-proposal/v1";
  rollbackId: string;
  originalReceiptDigest: Sha256Digest;
  expectedCurrentDigest: Sha256Digest;
  restoreStateDigest: Sha256Digest;
  inverseAction: AddClassificationTagActionV1["inverse"];
  requiresFreshApproval: true;
  digest: Sha256Digest;
}

export interface TagProjectionReader {
  readTagProjection(target: {
    entityUrn: string;
    columnPath: string;
  }): Promise<TagProjection>;
}

export interface DataHubTagMutationPort {
  addTags(input: {
    tagUrns: readonly string[];
    entityUrns: readonly string[];
    columnPaths?: readonly (string | null)[];
  }): Promise<MutationAck>;
}

export type ExecutionClaim =
  | { disposition: "CLAIMED"; fencingToken: number }
  | { disposition: "RECONCILE"; fencingToken: number }
  | { disposition: "COMPLETED"; receipt: ExecutionReceiptV1 }
  | { disposition: "IN_PROGRESS" }
  | { disposition: "APPROVAL_ALREADY_USED" };

export interface ExecutionJournalLease {
  idempotencyKey: string;
  fencingToken: number;
}

export interface ExecutionJournal {
  claim(input: {
    approvalId: string;
    approvalDecisionDigest: Sha256Digest;
    idempotencyKey: string;
  }): Promise<ExecutionClaim>;
  resume(lease: ExecutionJournalLease): Promise<boolean>;
  complete(lease: ExecutionJournalLease, receipt: ExecutionReceiptV1): Promise<void>;
}
