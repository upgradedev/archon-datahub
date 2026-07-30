// GovernanceAuditorAgent — runs the deterministic G1–G6 policy gate over the current
// catalog snapshot and turns each FAILED rule into a read-only governance_violation
// Finding. The rule logic lives in src/governance/validator.ts; this agent only maps
// its results into the Finding vocabulary and drops the passing (skipped) rules.

import {
  GovernanceValidator,
  type GovernancePolicy,
} from "../governance/validator.js";
import type { CatalogSnapshot } from "../datahub/models.js";
import type { Finding } from "../types.js";

export class GovernanceAuditorAgent {
  private readonly validator: GovernanceValidator;

  constructor(policy?: GovernancePolicy) {
    this.validator = new GovernanceValidator(policy);
  }

  audit(snapshot: CatalogSnapshot): Finding[] {
    return this.validator.validate(snapshot)
      .filter((r) => !r.passed)
      .map((r) => ({
        type: "governance_violation" as const,
        severity: r.severity,
        subject: r.subject,
        summary: `${r.ruleId}: ${r.message}`,
        detail: { rule: r.rule, ruleId: r.ruleId, ...(r.evidence ?? {}) },
        recommendation: `Remediate ${r.ruleId} (${r.rule}). Read-only — a steward decides.`,
      }));
  }
}
