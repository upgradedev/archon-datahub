// Core domain types for Archon-DataHub — the metadata-governance agent.
//
// These are the vocabulary the whole agent shares: the DataHub-shaped metadata it
// harvests, the audit facts the self-audit engine reasons over, and the findings
// it produces. Kept deliberately small and provider-neutral so the audit engine
// (src/audit/consistency.ts) stays a pure function over generic facts, exactly as
// it was in the ported scaffold.

// The kind of metadata fact a harvested aspect represents. A STRUCTURED fact comes
// straight from a source system's metadata (schema, ownership, a lineage edge); a
// DERIVED fact ("insight") is something the agent itself concluded ABOUT other
// facts. The audit's source-authority rule uses this distinction.
export type FactKind =
  | "schema" // a dataset's field + its type, from schemaMetadata
  | "ownership" // an owner assignment, from the ownership aspect
  | "lineage" // an upstream/downstream edge, from upstreamLineage
  | "glossary" // an attached business term, from glossaryTerms
  | "domain" // a domain membership, from the domains aspect
  | "deprecation" // lifecycle/deprecation status
  | "insight"; // a DERIVED narrative the agent wrote about other facts

// A single fact harvested from a metadata source, normalized into the neutral
// shape the audit engine reasons over. Every field maps 1:1 to metadata DataHub
// already exposes — no invented data.
export interface AuditFact {
  id: string; // stable id of this fact (harvest-run scoped)
  kind: FactKind;
  // The metadata SOURCE this fact came from — a DataHub platform/ingestion source
  // (e.g. "snowflake", "dbt", "manual-catalog"). Two sources disagreeing about one
  // entity is the classic metadata contradiction.
  source: string;
  scan: string | null; // the harvest/scan run id (a timestamp label), for scoping
  // The entity this fact is ABOUT — a DataHub URN (or a stable logical id). This is
  // the "record" the audit groups by.
  sourceRef: string | null;
  content: string; // the recallable natural-language statement of the fact
  // Structured attributes of the fact. Scalar entries are the ATTRIBUTES the audit
  // compares across sources (e.g. { owner: "team-a", fieldType: "number" }). The
  // reserved keys `record` (explicit entity id) and `refs` (referenced URNs, e.g.
  // declared lineage upstreams) are identity, never compared.
  metadata: Record<string, unknown> | null;
  createdAt: string; // ISO write-event timestamp of this harvest
  importance?: number | null; // 0..1 salience of the fact (steward-flagged, etc.)
}

// A read-only finding the agent surfaces. NEVER mutates DataHub — a human decides.
export type FindingType =
  | "contradiction" // two sources disagree on the same entity attribute
  | "lineage_gap" // a declared lineage upstream has no catalogued entity
  | "governance_violation"; // a governance policy (G-rule) is broken

export type Severity = "low" | "medium" | "high";

export interface Finding {
  type: FindingType;
  severity: Severity;
  subject: string; // the entity URN / id the finding is about
  summary: string; // one-line human-readable statement
  detail: Record<string, unknown>; // structured evidence for the finding
  // A recommended, human-gated remediation (e.g. which value to trust, which owner
  // to assign). A RECOMMENDATION only — the agent proposes, a steward disposes.
  recommendation?: string;
}
