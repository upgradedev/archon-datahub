import { test } from "node:test";
import assert from "node:assert/strict";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import {
  auditReportToJson,
  auditReportToMarkdown,
  auditReportToSarif,
} from "../../src/reporting/exporters.js";

test("report exporters produce JSON, safe Markdown, and SARIF with stable fingerprints", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const json = auditReportToJson(report);
  assert.equal(JSON.parse(json).findings.length, report.findings.length);

  const markdown = auditReportToMarkdown({
    ...report,
    narrative: "<script>alert(1)</script>",
  });
  assert.match(markdown, /## Findings/);
  assert.doesNotMatch(markdown, /<script>/iu);
  assert.match(markdown, /&lt;script&gt;/);

  const first = auditReportToSarif(report);
  const second = auditReportToSarif(report);
  assert.deepEqual(first, second);
  assert.equal(first.version, "2.1.0");
  assert.equal(first.runs[0]!.results.length, report.findings.length);
  assert.ok(
    first.runs[0]!.results.every((result) =>
      /^[a-f0-9]{64}$/u.test(result.partialFingerprints.archonFindingDigest)
    )
  );
});
