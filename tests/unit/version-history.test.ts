// Unit tests for the aspect VERSION-HISTORY contradiction-recovery path
// (src/datahub/version-history.ts) — the code that makes the flagship cross-source
// contradiction detection fire on a LIVE catalog, where latest-write-wins collapses the
// conflict on the current view.
//
// The load-bearing property is the HONEST semantic guard: DataHub `runId` identifies one
// execution, not a stable source. A value that changes between two executions of the SAME
// pipeline is drift and MUST NOT be reported; only DIFFERENT stable pipeline/source
// identities can form a recovered contradiction. Unknown provenance fails closed.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  versionHistoryToFacts,
  auditVersionHistory,
  detectDrift,
  type AspectVersionHistory,
} from "../../src/datahub/version-history.js";
import { FIXTURE_VERSION_HISTORY } from "../../src/datahub/fixtures.js";
import { LineageAnalyzerAgent } from "../../src/agents/lineage-analyzer.js";
import type { AuditFact } from "../../src/types.js";

const URN = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

// A minimal ownership history that flip-flops between two stable ingestion pipelines.
const crossSourceOwnership: AspectVersionHistory = {
  urn: URN,
  aspect: "ownership",
  versions: [
    {
      value: { owners: [{ owner: "urn:li:corpGroup:team-finance" }] },
      systemMetadata: {
        version: "1",
        lastObserved: 1000,
        runId: "snowflake-run-2026-06",
        pipelineName: "snowflake-prod",
      },
    },
    {
      value: { owners: [{ owner: "urn:li:corpGroup:team-ops" }] },
      systemMetadata: {
        version: "2",
        lastObserved: 2000,
        runId: "dbt-run-2026-07",
        pipelineName: "dbt-prod",
      },
    },
  ],
};

// Two different executions of ONE pipeline — drift, even though runId differs.
const sameSourceOwnership: AspectVersionHistory = {
  urn: URN,
  aspect: "ownership",
  versions: [
    {
      value: { owners: [{ owner: "urn:li:corpGroup:team-a" }] },
      systemMetadata: {
        version: "1",
        lastObserved: 1000,
        runId: "snowflake-run-2026-06",
        pipelineName: "snowflake-prod",
      },
    },
    {
      value: { owners: [{ owner: "urn:li:corpGroup:team-b" }] },
      systemMetadata: {
        version: "2",
        lastObserved: 2000,
        runId: "snowflake-run-2026-07",
        pipelineName: "snowflake-prod",
      },
    },
  ],
};

test("versionHistoryToFacts separates stable pipeline source from execution runId", () => {
  const facts = versionHistoryToFacts(crossSourceOwnership);
  assert.equal(facts.length, 2);
  assert.deepEqual(
    facts.map((f) => f.source).sort(),
    ["dbt-prod", "snowflake-prod"]
  );
  assert.deepEqual(
    facts.map((f) => f.scan).sort(),
    ["dbt-run-2026-07", "snowflake-run-2026-06"]
  );
  assert.equal(facts[0]!.metadata!["record"], URN);
  assert.ok(facts.every((f) => f.kind === "ownership"));
  // lastObserved epoch-ms → ISO createdAt (drives the recency recommendation).
  assert.equal(facts[0]!.createdAt, new Date(1000).toISOString());
});

test("auditVersionHistory FIRES on a genuine cross-source flip-flop", () => {
  const report = auditVersionHistory([crossSourceOwnership]);
  assert.equal(report.contradictions.length, 1);
  const c = report.contradictions[0]!;
  assert.equal(c.subject, URN);
  assert.equal(c.attribute, "owner");
  // the recommender still runs — recency picks the latest write's value.
  assert.equal(c.resolution.recommendedValue, "urn:li:corpGroup:team-ops");
});

test("different runIds from the SAME pipeline are drift, not a contradiction", () => {
  const report = auditVersionHistory([sameSourceOwnership]);
  assert.equal(report.contradictions.length, 0, "same-pipeline edits must be drift");
});

test("different runIds with UNKNOWN source identity fail closed to drift", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      {
        value: { owners: [{ owner: "urn:li:corpGroup:a" }] },
        systemMetadata: { version: "1", lastObserved: 1, runId: "run-1" },
      },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:b" }] },
        systemMetadata: { version: "2", lastObserved: 2, runId: "run-2" },
      },
    ],
  };
  const facts = versionHistoryToFacts(history);
  assert.ok(facts.every((fact) => fact.source === "unknown-source"));
  assert.equal(auditVersionHistory([history]).contradictions.length, 0);
});

test("trusted runId resolution supports histories without pipelineName", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    sourceIdentityByRunId: {
      "run-snowflake": "urn:li:dataHubIngestionSource:snowflake-prod",
      "run-dbt": "urn:li:dataHubIngestionSource:dbt-prod",
    },
    versions: [
      {
        value: { owners: [{ owner: "urn:li:corpGroup:a" }] },
        systemMetadata: { version: "1", lastObserved: 1, runId: "run-snowflake" },
      },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:b" }] },
        systemMetadata: { version: "2", lastObserved: 2, runId: "run-dbt" },
      },
    ],
  };
  assert.equal(auditVersionHistory([history]).contradictions.length, 1);
});

test("shipped fixture history recovers owner + field-type conflicts and ignores same-pipeline drift", () => {
  const report = auditVersionHistory(FIXTURE_VERSION_HISTORY);
  const attrs = report.contradictions.map((c) => c.attribute).sort();
  // sales_orders ownership (owner) + sales_orders.amount type (fieldType) fire;
  // raw_orders' same-pipeline ownership correction does NOT.
  assert.deepEqual(attrs, ["fieldType", "owner"]);
});

test("LineageAnalyzerAgent.analyzeVersionHistory yields findings identical in shape to the fixture path", () => {
  const findings = new LineageAnalyzerAgent().analyzeVersionHistory(FIXTURE_VERSION_HISTORY);
  const contradictions = findings.filter((f) => f.type === "contradiction");
  assert.equal(contradictions.length, 2);
  // a field-type disagreement is high severity (silent schema break); owner is medium.
  const fieldType = contradictions.find((f) =>
    (f.detail as { attribute?: string }).attribute === "fieldType"
  )!;
  assert.equal(fieldType.severity, "high");
  assert.ok(fieldType.recommendation!.includes("steward decides"));
});

test("schemaMetadata history contradicts at the FIELD level", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "schemaMetadata",
    versions: [
      {
        value: { fields: [{ fieldPath: "amount", nativeDataType: "NUMBER" }] },
        systemMetadata: {
          version: "1",
          lastObserved: 1000,
          runId: "snowflake-run",
          pipelineName: "snowflake-prod",
        },
      },
      {
        value: { fields: [{ fieldPath: "amount", nativeDataType: "STRING" }] },
        systemMetadata: {
          version: "2",
          lastObserved: 2000,
          runId: "dbt-run",
          pipelineName: "dbt-prod",
        },
      },
    ],
  };
  const report = auditVersionHistory([history]);
  assert.equal(report.contradictions.length, 1);
  assert.equal(report.contradictions[0]!.subject, `${URN}#amount`);
  assert.equal(report.contradictions[0]!.attribute, "fieldType");
});

test("domains + deprecation histories map to comparable attributes", () => {
  const domains: AspectVersionHistory = {
    urn: URN,
    aspect: "domains",
    versions: [
      { value: { domains: ["urn:li:domain:sales"] }, systemMetadata: { version: "1", lastObserved: 1, runId: "a", pipelineName: "source-a" } },
      { value: { domains: ["urn:li:domain:finance"] }, systemMetadata: { version: "2", lastObserved: 2, runId: "b", pipelineName: "source-b" } },
    ],
  };
  const dep: AspectVersionHistory = {
    urn: URN,
    aspect: "deprecation",
    versions: [
      { value: { deprecated: false }, systemMetadata: { version: "1", lastObserved: 1, runId: "a", pipelineName: "source-a" } },
      { value: { deprecated: true }, systemMetadata: { version: "2", lastObserved: 2, runId: "b", pipelineName: "source-b" } },
    ],
  };
  assert.equal(auditVersionHistory([domains]).contradictions[0]!.attribute, "domain");
  assert.equal(auditVersionHistory([dep]).contradictions[0]!.attribute, "deprecated");
});

test("missing/placeholder provenance collapses to one source → treated as drift", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:x" }] }, systemMetadata: { version: "1", lastObserved: 1 } },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:y" }] },
        systemMetadata: { version: "2", lastObserved: 2, runId: "no-run-id-provided" },
      },
    ],
  };
  // both collapse to "unknown-source" → single source → no contradiction.
  assert.equal(auditVersionHistory([history]).contradictions.length, 0);
});

test("versionHistoryToFacts skips versions with no comparable value", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value: null, systemMetadata: { version: "1", lastObserved: 1, runId: "a" } },
      { value: { owners: [] }, systemMetadata: { version: "2", lastObserved: 2, runId: "b" } },
    ],
  };
  assert.equal(versionHistoryToFacts(history).length, 0);
});

// ── Cross-scan DRIFT (the MCP-native secondary, labeled as drift) ───────────────

test("detectDrift reports an attribute that changed between two harvests", () => {
  const prior: AuditFact[] = [
    { id: "1", kind: "ownership", source: "datahub", scan: "d1", sourceRef: URN, content: "", metadata: { record: URN, owner: "team-a" }, createdAt: "2026-06-01T00:00:00.000Z" },
  ];
  const current: AuditFact[] = [
    { id: "2", kind: "ownership", source: "datahub", scan: "d2", sourceRef: URN, content: "", metadata: { record: URN, owner: "team-b" }, createdAt: "2026-07-01T00:00:00.000Z" },
  ];
  const drift = detectDrift(prior, current);
  assert.equal(drift.length, 1);
  assert.deepEqual(drift[0], { subject: URN, attribute: "owner", from: "team-a", to: "team-b" });
});

test("detectDrift is silent when nothing changed / no prior value", () => {
  const same: AuditFact[] = [
    { id: "1", kind: "domain", source: "datahub", scan: "d1", sourceRef: URN, content: "", metadata: { record: URN, domain: "sales" }, createdAt: "2026-06-01T00:00:00.000Z" },
  ];
  assert.deepEqual(detectDrift(same, same), []);
  assert.deepEqual(detectDrift([], same), []); // new attribute, no prior → not drift
});
