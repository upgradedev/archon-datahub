export type Severity = "high" | "medium" | "low";
export type FindingType = "contradiction" | "lineage_gap" | "governance_violation";
export type ApprovalDecision = "APPROVE" | "REJECT";

export interface ImpactedAsset {
  urn: string;
  minHops: number;
}

export interface BlastRadius {
  rootUrn: string;
  downstream: ImpactedAsset[];
  maxHops: number;
  truncated: boolean;
  impact: "none" | "low" | "medium" | "high" | "critical";
}

export interface ProvenanceEvent {
  source: string;
  runId: string;
  observedAt: string;
  actor?: string;
  value?: string;
  status: "trusted" | "conflicting" | "observed";
}

export interface DossierSummary {
  dossierId: string;
  digest: string;
  policyDigest: string;
  generatedAt: string;
  evidenceCount: number;
}

export interface ApprovalReview {
  approvalId: string;
  expiresAt: string;
  targetField: string;
  proposedTag: string;
  before: string[];
  after: string[];
  planDigest: string;
  risk: "low" | "medium" | "high";
}

export interface FindingDetail extends Record<string, unknown> {
  ruleId?: string;
  rule?: string;
  attribute?: string;
  values?: Record<string, unknown>;
  unclassifiedFields?: string[];
  blastRadius?: BlastRadius;
  provenance?: ProvenanceEvent[];
  dossier?: DossierSummary;
  approval?: ApprovalReview;
}

export interface Finding {
  type: FindingType;
  severity: Severity;
  subject: string;
  summary: string;
  detail: FindingDetail;
  recommendation?: string;
}

export interface Classification {
  totalEntities: number;
  withLineage: number;
  sensitiveEntities: number;
  domains: Record<string, number>;
  platforms: Record<string, number>;
}

export interface AuditReport {
  scanId: string;
  classification: Classification;
  findings: Finding[];
  narrative: string;
  trace: Array<{ agent: string; produced: string }>;
}

export interface AuditEnvelope {
  requestId: string;
  releaseSha: string;
  report: AuditReport;
}

export type ControlLoopLifecycle =
  | "RUNNING"
  | "AWAITING_APPROVAL"
  | "SUCCEEDED"
  | "FAILED"
  | "TIMED_OUT"
  | "ABORTED";

export interface ControlLoopStart {
  schemaVersion: "archon.control-loop-start/v1";
  auditId: string;
  status: "RUNNING";
  pollUrl: string;
  submittedAt: string;
}

export interface ControlLoopApproval {
  approvalId: string;
  status: "PENDING" | "DECIDED";
  expiresAt: string;
  planDigest: string;
  evidenceDigest: string;
  decision?: ApprovalDecision;
}

export type VerificationCheckId =
  | "TARGET_UNCHANGED"
  | "PREEXISTING_TAGS_PRESERVED"
  | "POLICY_TAG_PRESENT"
  | "NO_UNEXPECTED_TAGS"
  | "APPROVAL_BINDING_VALID";

export interface TerminalVerificationSummary {
  checks: Array<{
    checkId: VerificationCheckId;
    passed: true;
  }>;
  eventCount: number;
  rollbackAvailability: "ELIGIBLE" | "NOT_APPLICABLE";
}

export type ControlLoopResult =
  | {
      outcome: "READ_ONLY_COMPLETE";
    }
  | {
      outcome: "VERIFIED" | "REJECTED";
      receiptDigest: string;
      executionEvidenceDigest: string;
      completedAt: string;
      verification: TerminalVerificationSummary;
    };

export interface ControlLoopStatus {
  schemaVersion: "archon.control-loop-status/v1";
  auditId: string;
  status: ControlLoopLifecycle;
  submittedAt?: string;
  updatedAt: string;
  completedAt?: string;
  releaseSha?: string;
  report?: AuditReport;
  approval?: ControlLoopApproval;
  manualOnlyReason?: string;
  result?: ControlLoopResult;
}

export interface LoadedAudit {
  envelope: AuditEnvelope;
  source: "live" | "fixture";
  fallbackReason?: string;
  controlLoop?: ControlLoopStatus;
}

export interface ApprovalAck {
  approvalId: string;
  decision: ApprovalDecision;
  status: "recorded" | "queued";
  decisionId: string;
}
