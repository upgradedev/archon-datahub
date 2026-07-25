import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DATAHUB_BENCHMARK_CASES,
  dataHubBenchmarkToMarkdown,
  runDataHubBenchmark,
} from "../../src/evaluation/datahub-benchmark.js";

test("benchmark measures retained-history recovery without manufacturing conflicts", async () => {
  const report = await runDataHubBenchmark();

  assert.equal(report.schemaVersion, "archon.datahub-benchmark/v1");
  assert.equal(report.dataset.cases, DATAHUB_BENCHMARK_CASES.length);
  assert.match(report.dataset.digest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(report.controlCoverage.governanceRulesEvaluated, [
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
  ]);
  assert.ok(report.controlCoverage.lineageGapFindings > 0);
  assert.deepEqual(report.controlCoverage.agentTrace, [
    "classifier",
    "lineage-analyzer",
    "governance-auditor",
    "narrator",
  ]);

  assert.equal(report.systems.currentView.metrics.recall, 0);
  assert.equal(report.systems.currentView.metrics.falsePositives, 0);
  assert.equal(report.systems.currentView.metrics.precision, null);
  assert.equal(report.systems.retainedHistory.metrics.recall, 1);
  assert.equal(report.systems.retainedHistory.metrics.precision, 1);
  assert.equal(report.systems.retainedHistory.metrics.f1, 1);
  assert.equal(report.systems.retainedHistory.metrics.falsePositives, 0);
  assert.ok(
    report.cases
      .filter((item) => !item.expectedConflict)
      .every((item) => item.retainedHistory.detected === false)
  );

  const markdown = dataHubBenchmarkToMarkdown(report);
  assert.match(markdown, /latest-write-wins view/u);
  assert.match(markdown, /synthetic DataHub-shaped fixtures/u);
  assert.doesNotMatch(markdown, /Analytics Agent baseline/u);
});
