import { test } from "node:test";
import assert from "node:assert/strict";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import {
  auditReportToJson,
  auditReportToMarkdown,
  auditReportToSarif,
} from "../../src/reporting/exporters.js";
import { projectPublicAuditReport } from "../../src/reporting/public-audit-report.js";

test("report exporters produce JSON, safe Markdown, and SARIF with stable fingerprints", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const json = auditReportToJson(report);
  const parsed = JSON.parse(json);
  assert.equal(parsed.findings.length, report.findings.length);
  assert.deepEqual(parsed.modelProvenance, report.modelProvenance);

  const markdown = auditReportToMarkdown({
    ...report,
    scanId: "scan`](/unsafe)",
    narrative:
      "<script>alert(1)</script> [link](javascript:alert(2)) " +
      "[payload](DATA:text/html,unsafe) vbscript:msgbox(1) `breakout` " +
      "safe\u202Efdp.exe\u2066suffix",
  });
  assert.match(markdown, /## Findings/);
  assert.match(markdown, /Runtime: deterministic-fixture/u);
  assert.match(markdown, /Model call: no/u);
  assert.doesNotMatch(markdown, /<script>/iu);
  assert.match(markdown, /&lt;script&gt;/);
  assert.doesNotMatch(markdown, /\u0000/u);
  assert.doesNotMatch(markdown, /\]\(javascript:/iu);
  assert.doesNotMatch(markdown, /\b(?:javascript|vbscript|data):/iu);
  assert.match(markdown, /blocked-active-scheme/u);
  assert.doesNotMatch(
    markdown,
    /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u
  );
  assert.doesNotMatch(markdown, /`breakout`/u);

  const first = auditReportToSarif(report);
  const second = auditReportToSarif(report);
  assert.deepEqual(first, second);
  assert.equal(first.version, "2.1.0");
  assert.deepEqual(
    first.runs[0]!.properties.modelProvenance,
    report.modelProvenance
  );
  assert.equal(first.runs[0]!.results.length, report.findings.length);
  assert.ok(
    first.runs[0]!.results.every((result) =>
      /^[a-f0-9]{64}$/u.test(result.partialFingerprints.archonFindingDigest)
    )
  );
});

test("report exporters reject provenance with unreviewed fields", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const unsafe = {
    ...report,
    modelProvenance: {
      ...report.modelProvenance,
      prompt: "raw prompt must never enter an exporter",
    },
  };
  assert.throws(
    () => auditReportToJson(unsafe),
    /audit report is absent/iu
  );
  assert.throws(
    () => auditReportToMarkdown(unsafe),
    /audit report is absent/iu
  );
  assert.throws(
    () => auditReportToSarif(unsafe),
    /audit report is absent/iu
  );
});

test("public report projection rejects aligned short secret and JWT shapes", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const unsafeValues = [
    `sk-${"x".repeat(12)}`,
    `eyJ${"a".repeat(8)}.${"b".repeat(8)}.${"c".repeat(8)}`,
  ];
  for (const unsafeValue of unsafeValues) {
    assert.throws(
      () =>
        projectPublicAuditReport({
          ...report,
          narrative: `Provider diagnostic ${unsafeValue}`,
        }),
      /cannot be represented by the public response contract/iu
    );
  }
});
