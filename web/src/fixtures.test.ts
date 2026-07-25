import { describe, expect, it } from "vitest";
import { previewAudit } from "./fixtures";

const CUSTOMER_360_URN =
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.customer_360,PROD)";

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
});
