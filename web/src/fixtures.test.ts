import { describe, expect, it } from "vitest";
import { previewAudit } from "./fixtures";

const CUSTOMER_360_URN =
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.customer_360,PROD)";
const PAYMENT_EVENTS_URN =
  "urn:li:dataset:(urn:li:dataPlatform:kafka,payment_events,PROD)";
const DAILY_REVENUE_URN =
  "urn:li:dataset:(urn:li:dataPlatform:dbt,marts.daily_revenue,PROD)";

describe("deterministic preview fixture", () => {
  it("keeps the G6 finding and exact tag projection aligned with remediation", () => {
    const finding = previewAudit.report.findings.find(
      (candidate) => candidate.detail.ruleId === "G6",
    );

    expect(finding).toBeDefined();
    expect(finding?.subject).toBe(CUSTOMER_360_URN);
    expect(finding?.detail.blastRadius?.rootUrn).toBe(CUSTOMER_360_URN);
    expect(finding?.detail.unclassifiedFields).toEqual(["email"]);
    expect(finding?.detail.approval).toEqual(
      expect.objectContaining({
        expiresAt: "2099-12-31T23:59:59.000Z",
        proposedTag: "urn:li:tag:PII",
        before: [],
        after: ["urn:li:tag:PII"],
      }),
    );
    expect(
      finding?.detail.provenance?.map((event) => event.value),
    ).not.toContainEqual(expect.stringMatching(/glossary/iu));
  });

  it("models a lineage gap from the unresolved upstream through its consumer topology", () => {
    const finding = previewAudit.report.findings.find(
      (candidate) => candidate.type === "lineage_gap",
    );

    expect(finding).toBeDefined();
    expect(finding?.subject).toBe(PAYMENT_EVENTS_URN);
    expect(finding?.detail.missingRef).toBe(PAYMENT_EVENTS_URN);
    expect(finding?.detail.blastRadius).toEqual(
      expect.objectContaining({
        rootUrn: PAYMENT_EVENTS_URN,
        impact: "medium",
        downstream: [
          { urn: DAILY_REVENUE_URN, minHops: 1 },
          { urn: "urn:li:dashboard:(looker,revenue-pulse)", minHops: 2 },
          { urn: "urn:li:dashboard:(tableau,regional-sales)", minHops: 2 },
        ],
      }),
    );
  });
});
