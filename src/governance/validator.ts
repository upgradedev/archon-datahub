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
import {
  DEFAULT_SENSITIVE_FIELD_HINTS,
  looksSensitive,
} from "../datahub/models.js";
import { DataHubHarvestError } from "../datahub/harvest-policy.js";
import type { Severity } from "../types.js";

// Classification identifiers are exact, provider-normalized values. G6 must not
// treat arbitrary metadata (or substring lookalikes such as NOT_PII) as proof that
// a sensitive field has an accepted classification.
export interface GovernancePolicy {
  readonly sensitiveFieldHints: readonly string[];
  readonly acceptedClassificationTagIdentifiers: readonly string[];
  readonly acceptedClassificationTermIdentifiers: readonly string[];
}

export const DEFAULT_GOVERNANCE_POLICY: Readonly<GovernancePolicy> = Object.freeze({
  sensitiveFieldHints: DEFAULT_SENSITIVE_FIELD_HINTS,
  acceptedClassificationTagIdentifiers: Object.freeze([
    "PII",
    "pii",
    "urn:li:tag:PII",
  ]),
  acceptedClassificationTermIdentifiers: Object.freeze([
    "PII",
    "pii",
    "Classification.PII",
    "urn:li:glossaryTerm:Classification.PII",
  ]),
});

interface CompiledGovernancePolicy {
  readonly sensitiveFieldHints: readonly string[];
  readonly acceptedClassificationTagIdentifiers: ReadonlySet<string>;
  readonly acceptedClassificationTermIdentifiers: ReadonlySet<string>;
}

function compileSensitiveFieldHints(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values) || values.length === 0) {
    throw new TypeError("GovernancePolicy.sensitiveFieldHints must contain at least one hint.");
  }
  const hints = values.map((value) => {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new TypeError(
        "GovernancePolicy.sensitiveFieldHints must contain only non-empty strings."
      );
    }
    return value.trim().toLowerCase();
  });
  return Object.freeze([...new Set(hints)]);
}

function compileExactIdentifiers(
  values: readonly string[],
  property: string
): ReadonlySet<string> {
  if (!Array.isArray(values)) {
    throw new TypeError(`GovernancePolicy.${property} must be an array.`);
  }
  const identifiers = values.map((value) => {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value !== value.trim() ||
      /[\u0000-\u001f\u007f]/u.test(value)
    ) {
      throw new TypeError(
        `GovernancePolicy.${property} must contain only non-empty, exact identifiers.`
      );
    }
    return value;
  });
  return new Set(identifiers);
}

function compileGovernancePolicy(policy: GovernancePolicy): CompiledGovernancePolicy {
  if (!policy || typeof policy !== "object") {
    throw new TypeError("GovernancePolicy must be an object.");
  }
  const acceptedClassificationTagIdentifiers = compileExactIdentifiers(
    policy.acceptedClassificationTagIdentifiers,
    "acceptedClassificationTagIdentifiers"
  );
  const acceptedClassificationTermIdentifiers = compileExactIdentifiers(
    policy.acceptedClassificationTermIdentifiers,
    "acceptedClassificationTermIdentifiers"
  );
  if (
    acceptedClassificationTagIdentifiers.size === 0 &&
    acceptedClassificationTermIdentifiers.size === 0
  ) {
    throw new TypeError(
      "GovernancePolicy must accept at least one classification tag or term identifier."
    );
  }
  return {
    sensitiveFieldHints: compileSensitiveFieldHints(policy.sensitiveFieldHints),
    acceptedClassificationTagIdentifiers,
    acceptedClassificationTermIdentifiers,
  };
}

export interface GovernanceResult {
  rule: string; // e.g. "G1: dataset has an owner"
  ruleId: "G1" | "G2" | "G3" | "G4" | "G5" | "G6";
  subject: string; // the entity URN
  passed: boolean;
  severity: Severity;
  message: string;
  // Machine-readable, policy-produced evidence. Remediation planning consumes this instead
  // of parsing human prose, so free-text metadata cannot steer a write target.
  evidence?: Readonly<Record<string, unknown>>;
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

// G4 consumes provider-proven downstream topology, not the audited search result set.
// Degree one is a direct consumer; an affirmative downstream deprecation aspect makes
// that consumer inactive. Missing topology is unavailable evidence, never a passing rule.
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
  const topology = snapshot.downstreamByRoot.get(e.urn);
  if (topology === undefined) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      "Complete downstream lineage is required to evaluate G4."
    );
  }
  const consumers = topology
    .filter((node) => node.minHops === 1 && !node.deprecated)
    .map((node) => node.urn);
  const passed = consumers.length === 0;
  return {
    rule,
    ruleId: "G4",
    subject: e.urn,
    passed,
    severity: passed ? "low" : "high",
    message: passed
      ? "Deprecated with no active downstream consumers."
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

function g6(e: CatalogEntity, policy: CompiledGovernancePolicy): GovernanceResult {
  const rule = "G6: sensitive fields carry a governance classification";
  const fields = e.fields ?? [];
  const sensitive = fields.filter((f) =>
    looksSensitive(f.path, policy.sensitiveFieldHints)
  );
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
    .filter(
      (f) =>
        !(f.tags ?? []).some((identifier) =>
          policy.acceptedClassificationTagIdentifiers.has(identifier)
        ) &&
        !(f.glossaryTerms ?? []).some((identifier) =>
          policy.acceptedClassificationTermIdentifiers.has(identifier)
        )
    )
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
      : `${unclassified.length} sensitive field(s) lack an accepted classification tag/term: ${unclassified.join(", ")}.`,
    evidence: {
      sensitiveFields: sensitive.map((field) => field.path).sort(),
      unclassifiedFields: unclassified.sort(),
    },
  };
}

function validateEntityWithPolicy(
  e: CatalogEntity,
  snapshot: CatalogSnapshot,
  policy: CompiledGovernancePolicy
): GovernanceResult[] {
  return [g1(e), g2(e), g3(e), g4(e, snapshot), g5(e), g6(e, policy)];
}

// Validate one entity against all G-rules (G4 needs the snapshot for downstream).
export function validateEntity(
  e: CatalogEntity,
  snapshot: CatalogSnapshot,
  policy: GovernancePolicy = DEFAULT_GOVERNANCE_POLICY
): GovernanceResult[] {
  return validateEntityWithPolicy(e, snapshot, compileGovernancePolicy(policy));
}

// Validate a whole snapshot — every entity against every rule.
export function validateSnapshot(
  snapshot: CatalogSnapshot,
  policy: GovernancePolicy = DEFAULT_GOVERNANCE_POLICY
): GovernanceResult[] {
  const compiledPolicy = compileGovernancePolicy(policy);
  return snapshot.entities.flatMap((e) =>
    validateEntityWithPolicy(e, snapshot, compiledPolicy)
  );
}

export class GovernanceValidator {
  private readonly policy: CompiledGovernancePolicy;

  constructor(policy: GovernancePolicy = DEFAULT_GOVERNANCE_POLICY) {
    this.policy = compileGovernancePolicy(policy);
  }

  validate(snapshot: CatalogSnapshot): GovernanceResult[] {
    return snapshot.entities.flatMap((e) =>
      validateEntityWithPolicy(e, snapshot, this.policy)
    );
  }
}
