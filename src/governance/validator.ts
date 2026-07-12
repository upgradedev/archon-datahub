// GovernanceValidator — the deterministic governance-policy gate.
//
// PORTED from Archon MemoryAgent's ValidatorAgent (repos/qwen-memoryagent/src/
// pipeline/validator.ts — its deterministic per-rule cross-document consistency
// checks) and RE-AIMED onto DATA-GOVERNANCE policy rules (G1–G6) over DataHub catalog
// entities. The pattern is unchanged: one deterministic ValidationResult per rule per
// entity, fixed thresholds, no LLM. Full origin disclosed in NOTICE.md.
//
// This is distinct from the self-audit consistency engine. The consistency engine
// finds where the catalog CONTRADICTS ITSELF (two sources disagree) or has a
// DANGLING lineage edge. The governance validator finds where the catalog VIOLATES
// A POLICY the organization set — an ungoverned asset. Two engines, two honest jobs.
//
//   G1  every dataset has ≥1 owner                          (ownership aspect)
//   G2  every dataset is assigned to a domain               (domains aspect)
//   G3  every dataset has a non-empty description            (datasetProperties)
//   G4  a deprecated dataset has no ACTIVE downstream        (deprecation + lineage)
//   G5  every schema field has a resolved type               (schemaMetadata)
//   G6  every SENSITIVE field carries a governance tag/term  (PII classification)

import type { CatalogEntity, CatalogSnapshot } from "../datahub/models.js";
import { looksSensitive } from "../datahub/models.js";
import type { Severity } from "../types.js";

export interface GovernanceResult {
  rule: string; // e.g. "G1: dataset has an owner"
  ruleId: "G1" | "G2" | "G3" | "G4" | "G5" | "G6";
  subject: string; // the entity URN
  passed: boolean;
  severity: Severity;
  message: string;
}

function g1(e: CatalogEntity): GovernanceResult {
  const passed = Array.isArray(e.owners) && e.owners.length > 0;
  return {
    rule: "G1: dataset has an owner",
    ruleId: "G1",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "high",
    message: passed
      ? `Owned by ${e.owners!.join(", ")}.`
      : `No owner assigned — ungoverned asset (ownership aspect empty).`,
  };
}

function g2(e: CatalogEntity): GovernanceResult {
  const passed = Boolean(e.domain);
  return {
    rule: "G2: dataset is assigned to a domain",
    ruleId: "G2",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "medium",
    message: passed ? `In domain ${e.domain}.` : `No domain assigned (domains aspect empty).`,
  };
}

function g3(e: CatalogEntity): GovernanceResult {
  const desc = (e.description ?? "").trim();
  const passed = desc.length > 0;
  return {
    rule: "G3: dataset has a description",
    ruleId: "G3",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "medium",
    message: passed ? `Documented (${desc.length} chars).` : `No description — undocumented asset.`,
  };
}

// G4 needs the whole snapshot: a deprecated dataset must not still feed live
// consumers. We look for any OTHER entity whose upstreams include this URN.
function g4(e: CatalogEntity, snapshot: CatalogSnapshot): GovernanceResult {
  const rule = "G4: deprecated dataset has no active downstream";
  if (!e.deprecated) {
    return {
      rule,
      ruleId: "G4",
      subject: e.urn,
      passed: true,
      severity: "low",
      message: "Not deprecated — skipped.",
    };
  }
  const consumers = snapshot.entities
    .filter((o) => o.urn !== e.urn)
    .filter((o) => (o.upstreams ?? []).some((u) => u.upstream === e.urn))
    .map((o) => o.urn);
  const passed = consumers.length === 0;
  return {
    rule,
    ruleId: "G4",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "high",
    message: passed
      ? "Deprecated with no downstream consumers."
      : `Deprecated but still feeds ${consumers.length} active consumer(s): ${consumers.join(", ")}.`,
  };
}

function g5(e: CatalogEntity): GovernanceResult {
  const rule = "G5: every schema field has a type";
  const fields = e.fields ?? [];
  if (fields.length === 0) {
    return {
      rule,
      ruleId: "G5",
      subject: e.urn,
      passed: true,
      severity: "low",
      message: "No schema fields — skipped.",
    };
  }
  const untyped = fields.filter((f) => !f.type || f.type.trim().length === 0).map((f) => f.path);
  const passed = untyped.length === 0;
  return {
    rule,
    ruleId: "G5",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "medium",
    message: passed
      ? `All ${fields.length} fields typed.`
      : `${untyped.length} field(s) missing a type: ${untyped.join(", ")}.`,
  };
}

function g6(e: CatalogEntity): GovernanceResult {
  const rule = "G6: sensitive fields carry a governance classification";
  const fields = e.fields ?? [];
  const sensitive = fields.filter((f) => looksSensitive(f.path));
  if (sensitive.length === 0) {
    return {
      rule,
      ruleId: "G6",
      subject: e.urn,
      passed: true,
      severity: "low",
      message: "No sensitive fields detected — skipped.",
    };
  }
  const unclassified = sensitive
    .filter((f) => (f.tags ?? []).length === 0 && (f.glossaryTerms ?? []).length === 0)
    .map((f) => f.path);
  const passed = unclassified.length === 0;
  return {
    rule,
    ruleId: "G6",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "high",
    message: passed
      ? `All ${sensitive.length} sensitive field(s) classified.`
      : `${unclassified.length} sensitive field(s) lack a tag/term: ${unclassified.join(", ")}.`,
  };
}

// Validate one entity against all G-rules (G4 needs the snapshot for downstream).
export function validateEntity(e: CatalogEntity, snapshot: CatalogSnapshot): GovernanceResult[] {
  return [g1(e), g2(e), g3(e), g4(e, snapshot), g5(e), g6(e)];
}

// Validate a whole snapshot — every entity against every rule.
export function validateSnapshot(snapshot: CatalogSnapshot): GovernanceResult[] {
  return snapshot.entities.flatMap((e) => validateEntity(e, snapshot));
}

export class GovernanceValidator {
  validate(snapshot: CatalogSnapshot): GovernanceResult[] {
    return validateSnapshot(snapshot);
  }
}
