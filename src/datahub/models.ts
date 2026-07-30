// DataHub metadata models — a minimal, provider-neutral view of the DataHub
// entities + aspects our agent reasons over.
//
// This is NOT the full DataHub metadata model (that is schema-first PDL with dozens
// of entity types). It is the SUBSET a governance/lineage agent needs: a dataset
// entity, its governance aspects (ownership, domain, description, tags, glossary
// terms, deprecation), its schema fields, and its lineage edges. Shapes mirror the
// aspects the DataHub MCP Server returns from `get_entities` / `list_schema_fields`
// / `get_lineage` (docs/DATAHUB_RESEARCH.md §2–3), normalized to plain JSON.

// A DataHub URN, e.g. urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_raw,PROD)
export type Urn = string;

// One column/field of a dataset's schema (from the schemaMetadata aspect).
export interface SchemaField {
  path: string; // fieldPath, e.g. "amount" or "address.zip"
  type: string | null; // native/normalized type, e.g. "number", "string"
  // Governance tags/terms attached at the FIELD level (e.g. a PII classification).
  tags?: string[];
  glossaryTerms?: string[];
}

// A directed lineage edge (from the upstreamLineage aspect). `upstream` is the URN
// this dataset reads from. When the referenced upstream is not itself catalogued,
// the self-audit flags a lineage gap.
export interface LineageEdge {
  upstream: Urn;
  // Whether the upstream URN resolves to a catalogued entity. The harvester sets
  // this from what DataHub actually returned; the audit uses it as ground truth.
  upstreamResolved: boolean;
  type?: string; // e.g. "TRANSFORMED", "COPY"
}

// One entity proven reachable downstream from an audited root. This is reachability,
// not a fabricated direct edge: `minHops` is the degree returned by DataHub (or derived
// from the complete Fake graph). Keeping this context outside `CatalogSnapshot.entities`
// preserves the exact audited search scope while still making G4 and blast radius honest.
export interface LineageTopologyNode {
  urn: Urn;
  minHops: number;
  entityType: string;
  // DataHub entities without an affirmative deprecation aspect are conservatively active.
  deprecated: boolean;
}

// A catalogued dataset entity with the governance aspects we audit. Every field is
// OPTIONAL where the real aspect can be absent — an absent aspect is exactly what a
// governance violation is made of (no owner, no domain, no description).
export interface CatalogEntity {
  urn: Urn;
  name: string;
  platform: string; // dataPlatform, e.g. "snowflake"
  // The metadata SOURCE that reported this entity (ingestion source id). Two
  // sources reporting the same URN with different aspects is a contradiction.
  source: string;
  fabric?: string; // PROD/DEV/QA...
  description?: string | null;
  owners?: Urn[]; // corpuser/corpGroup URNs from the ownership aspect
  domain?: Urn | null; // domain URN from the domains aspect
  tags?: string[]; // globalTags
  glossaryTerms?: string[]; // glossaryTerms
  deprecated?: boolean; // deprecation.deprecated
  fields?: SchemaField[]; // schemaMetadata
  upstreams?: LineageEdge[]; // upstreamLineage
}

// A snapshot the harvester returns: the entities plus which URNs DataHub knows
// about (used to resolve lineage edges and to detect dangling references).
export interface CatalogSnapshot {
  scanId: string; // a timestamp label for this harvest run
  entities: CatalogEntity[];
  knownUrns: Set<Urn>; // every URN DataHub returned an entity for
  // Required completeness boundary. A root key with [] proves that the bounded lineage
  // read found no downstream. A missing root key means coverage is unavailable and must
  // never be interpreted as an empty blast radius or a passing G4 result.
  downstreamByRoot: Map<Urn, LineageTopologyNode[]>;
}

// Heuristic: does a field name look like PII / sensitive data that governance
// policy would require a classification tag on? Deliberately conservative and
// data-driven (name-based), overridable by callers that pass their own matcher.
export const DEFAULT_SENSITIVE_FIELD_HINTS: readonly string[] = Object.freeze([
  "email",
  "ssn",
  "phone",
  "dob",
  "birth",
  "salary",
  "passport",
  "iban",
  "credit",
  "address",
  "national_id",
  "tax_id",
]);

export function looksSensitive(
  fieldPath: string,
  hints: readonly string[] = DEFAULT_SENSITIVE_FIELD_HINTS
): boolean {
  const p = fieldPath.toLowerCase();
  return hints.some((value) => {
    const hint = value.trim().toLowerCase();
    return hint.length > 0 && p.includes(hint);
  });
}
