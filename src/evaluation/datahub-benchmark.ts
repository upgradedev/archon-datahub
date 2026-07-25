import { LineageAnalyzerAgent } from "../agents/lineage-analyzer.js";
import { NarratorAgent } from "../agents/narrator.js";
import {
  FIXTURE_REPORTS,
  FIXTURE_VERSION_HISTORY,
} from "../datahub/fixtures.js";
import { FakeDataHubMcpClient } from "../datahub/mcp-client.js";
import type {
  AspectVersionHistory,
  DhVersionedAspect,
} from "../datahub/version-history.js";
import { validateSnapshot } from "../governance/validator.js";
import { FakeLlmClient } from "../llm/fake.js";
import { AuditPipeline } from "../pipeline/pipeline.js";
import { digest, type Sha256Digest } from "../remediation/integrity.js";

export const DATAHUB_BENCHMARK_VERSION = "archon.datahub-benchmark/v1" as const;
export const DATAHUB_BENCHMARK_DATASET_VERSION = "2026-07-25" as const;
export const DATAHUB_BENCHMARK_DATASET_DIGEST =
  "sha256:ef244f25fe085245b9153814d9c36e1a5f12112a5dc0dc39a315e40df586f42" as const;

export interface DataHubBenchmarkCase {
  id: string;
  title: string;
  expectedConflict: boolean;
  rationale: string;
  histories: AspectVersionHistory[];
}

export interface BinaryMetrics {
  support: number;
  truePositives: number;
  trueNegatives: number;
  falsePositives: number;
  falseNegatives: number;
  accuracy: number;
  precision: number | null;
  recall: number;
  f1: number;
}

export interface DataHubBenchmarkResult {
  schemaVersion: typeof DATAHUB_BENCHMARK_VERSION;
  dataset: {
    name: "archon-datahub-temporal-provenance";
    version: typeof DATAHUB_BENCHMARK_DATASET_VERSION;
    digest: Sha256Digest;
    cases: number;
    positiveCases: number;
    negativeCases: number;
  };
  systems: {
    currentView: {
      name: "DataHub current-view boundary";
      description: string;
      metrics: BinaryMetrics;
    };
    retainedHistory: {
      name: "Archon retained-history audit";
      description: string;
      metrics: BinaryMetrics;
    };
  };
  cases: Array<{
    id: string;
    title: string;
    expectedConflict: boolean;
    rationale: string;
    currentView: { detected: boolean; contradictions: number };
    retainedHistory: { detected: boolean; contradictions: number };
  }>;
  controlCoverage: {
    governanceRulesEvaluated: string[];
    lineageGapFindings: number;
    agentTrace: string[];
  };
  limitations: string[];
}

const ROOT =
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,analytics.orders,PROD)";
const T1 = Date.parse("2026-07-01T09:00:00.000Z");
const T2 = Date.parse("2026-07-02T09:00:00.000Z");

function ownershipVersion(
  version: string,
  owner: string,
  runId: string,
  pipelineName?: string
): DhVersionedAspect {
  return {
    value: { owners: [{ owner }] },
    systemMetadata: {
      version,
      lastObserved: version === "1" ? T1 : T2,
      runId,
      ...(pipelineName ? { pipelineName } : {}),
    },
  };
}

function schemaVersion(
  version: string,
  nativeDataType: string,
  runId: string,
  pipelineName: string
): DhVersionedAspect {
  return {
    value: {
      fields: [{ fieldPath: "amount", nativeDataType }],
    },
    systemMetadata: {
      version,
      lastObserved: version === "1" ? T1 : T2,
      runId,
      pipelineName,
    },
  };
}

export const DATAHUB_BENCHMARK_CASES: DataHubBenchmarkCase[] = [
  {
    id: "owner-cross-pipeline-conflict",
    title: "Two stable ingestion pipelines disagree on ownership",
    expectedConflict: true,
    rationale:
      "Different stable pipeline identities assert different owners for one dataset.",
    histories: [
      {
        urn: ROOT,
        aspect: "ownership",
        versions: [
          ownershipVersion(
            "1",
            "urn:li:corpGroup:finance",
            "snowflake-run-001",
            "snowflake-prod"
          ),
          ownershipVersion(
            "2",
            "urn:li:corpGroup:operations",
            "dbt-run-001",
            "dbt-prod"
          ),
        ],
      },
    ],
  },
  {
    id: "schema-cross-pipeline-conflict",
    title: "Two stable ingestion pipelines disagree on a field type",
    expectedConflict: true,
    rationale:
      "The same field is NUMBER in one stable source and STRING in another.",
    histories: [
      {
        urn: ROOT,
        aspect: "schemaMetadata",
        versions: [
          schemaVersion("1", "NUMBER", "snowflake-run-001", "snowflake-prod"),
          schemaVersion("2", "STRING", "dbt-run-001", "dbt-prod"),
        ],
      },
    ],
  },
  {
    id: "trusted-run-map-conflict",
    title: "Trusted run-to-source mapping recovers older provenance",
    expectedConflict: true,
    rationale:
      "Historical writes without pipelineName use an explicit trusted run mapping.",
    histories: [
      {
        urn: ROOT,
        aspect: "ownership",
        sourceIdentityByRunId: {
          "legacy-run-001": "legacy-snowflake-prod",
          "legacy-run-002": "legacy-dbt-prod",
        },
        versions: [
          ownershipVersion(
            "1",
            "urn:li:corpGroup:finance",
            "legacy-run-001"
          ),
          ownershipVersion(
            "2",
            "urn:li:corpGroup:operations",
            "legacy-run-002"
          ),
        ],
      },
    ],
  },
  {
    id: "same-pipeline-drift",
    title: "Two executions of one pipeline are drift, not conflict",
    expectedConflict: false,
    rationale:
      "A run id is execution identity; the unchanged pipelineName is source identity.",
    histories: [
      {
        urn: ROOT,
        aspect: "ownership",
        versions: [
          ownershipVersion(
            "1",
            "urn:li:corpGroup:finance",
            "snowflake-run-001",
            "snowflake-prod"
          ),
          ownershipVersion(
            "2",
            "urn:li:corpGroup:operations",
            "snowflake-run-002",
            "snowflake-prod"
          ),
        ],
      },
    ],
  },
  {
    id: "unknown-provenance",
    title: "Unresolved provenance fails closed",
    expectedConflict: false,
    rationale:
      "Distinct run ids alone cannot manufacture distinct source identities.",
    histories: [
      {
        urn: ROOT,
        aspect: "ownership",
        versions: [
          ownershipVersion(
            "1",
            "urn:li:corpGroup:finance",
            "unresolved-run-001"
          ),
          ownershipVersion(
            "2",
            "urn:li:corpGroup:operations",
            "unresolved-run-002"
          ),
        ],
      },
    ],
  },
  {
    id: "cross-pipeline-agreement",
    title: "Different pipelines agree on the value",
    expectedConflict: false,
    rationale:
      "Source diversity without a value disagreement is not a conflict.",
    histories: [
      {
        urn: ROOT,
        aspect: "ownership",
        versions: [
          ownershipVersion(
            "1",
            "urn:li:corpGroup:finance",
            "snowflake-run-001",
            "snowflake-prod"
          ),
          ownershipVersion(
            "2",
            "urn:li:corpGroup:finance",
            "dbt-run-001",
            "dbt-prod"
          ),
        ],
      },
    ],
  },
  {
    id: "single-current-write",
    title: "A single retained write has no comparison",
    expectedConflict: false,
    rationale: "One observation cannot establish a disagreement.",
    histories: [
      {
        urn: ROOT,
        aspect: "schemaMetadata",
        versions: [
          schemaVersion("1", "NUMBER", "snowflake-run-001", "snowflake-prod"),
        ],
      },
    ],
  },
];

function latestVersion(versions: DhVersionedAspect[]): DhVersionedAspect {
  const sorted = [...versions].sort((left, right) => {
    const leftVersion = Number(left.systemMetadata?.version ?? 0);
    const rightVersion = Number(right.systemMetadata?.version ?? 0);
    if (leftVersion !== rightVersion) return leftVersion - rightVersion;
    return (
      Number(left.systemMetadata?.lastObserved ?? 0) -
      Number(right.systemMetadata?.lastObserved ?? 0)
    );
  });
  const latest = sorted.at(-1);
  if (!latest) throw new Error("Benchmark histories must contain at least one version.");
  return latest;
}

function currentViewOnly(
  histories: AspectVersionHistory[]
): AspectVersionHistory[] {
  return histories.map((history) => ({
    ...history,
    versions: [latestVersion(history.versions)],
  }));
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function metrics(
  expected: boolean[],
  predicted: boolean[]
): BinaryMetrics {
  let truePositives = 0;
  let trueNegatives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  for (const [index, expectedValue] of expected.entries()) {
    const predictedValue = predicted[index] ?? false;
    if (expectedValue && predictedValue) truePositives += 1;
    else if (!expectedValue && !predictedValue) trueNegatives += 1;
    else if (!expectedValue && predictedValue) falsePositives += 1;
    else falseNegatives += 1;
  }
  const precisionDenominator = truePositives + falsePositives;
  const recallDenominator = truePositives + falseNegatives;
  const precision =
    precisionDenominator === 0
      ? null
      : round(truePositives / precisionDenominator);
  const recall =
    recallDenominator === 0 ? 0 : round(truePositives / recallDenominator);
  const f1 =
    precision === null || precision + recall === 0
      ? 0
      : round((2 * precision * recall) / (precision + recall));
  return {
    support: expected.length,
    truePositives,
    trueNegatives,
    falsePositives,
    falseNegatives,
    accuracy: round((truePositives + trueNegatives) / expected.length),
    precision,
    recall,
    f1,
  };
}

export async function runDataHubBenchmark(): Promise<DataHubBenchmarkResult> {
  const analyzer = new LineageAnalyzerAgent();
  const cases = DATAHUB_BENCHMARK_CASES.map((benchmarkCase) => {
    const currentViewFindings = analyzer
      .analyzeVersionHistory(currentViewOnly(benchmarkCase.histories))
      .filter((finding) => finding.type === "contradiction");
    const retainedHistoryFindings = analyzer
      .analyzeVersionHistory(benchmarkCase.histories)
      .filter((finding) => finding.type === "contradiction");
    return {
      id: benchmarkCase.id,
      title: benchmarkCase.title,
      expectedConflict: benchmarkCase.expectedConflict,
      rationale: benchmarkCase.rationale,
      currentView: {
        detected: currentViewFindings.length > 0,
        contradictions: currentViewFindings.length,
      },
      retainedHistory: {
        detected: retainedHistoryFindings.length > 0,
        contradictions: retainedHistoryFindings.length,
      },
    };
  });

  const pipelineClient = new FakeDataHubMcpClient();
  const pipelineReport = await new AuditPipeline({
    narrator: new NarratorAgent(
      new FakeLlmClient(),
      "archon-datahub-benchmark-fixture-narrator-v1"
    ),
  }).run(pipelineClient);
  const snapshot = await new FakeDataHubMcpClient().harvestSnapshot();
  const lineageFindings = pipelineReport.findings.filter(
    (finding) => finding.type === "lineage_gap"
  );
  const expected = cases.map((item) => item.expectedConflict);
  const currentPredictions = cases.map((item) => item.currentView.detected);
  const historyPredictions = cases.map(
    (item) => item.retainedHistory.detected
  );
  const datasetDigest = digest({
    benchmarkCases: DATAHUB_BENCHMARK_CASES.map((item) => ({
      id: item.id,
      title: item.title,
      expectedConflict: item.expectedConflict,
      rationale: item.rationale,
      histories: item.histories,
    })),
    controlFixture: {
      reports: FIXTURE_REPORTS,
      versionHistories: FIXTURE_VERSION_HISTORY,
    },
  });
  if (datasetDigest !== DATAHUB_BENCHMARK_DATASET_DIGEST) {
    throw new Error(
      `Benchmark dataset drifted from ${DATAHUB_BENCHMARK_DATASET_VERSION}; ` +
        "review the fixture change and advance both the version and digest."
    );
  }

  return {
    schemaVersion: DATAHUB_BENCHMARK_VERSION,
    dataset: {
      name: "archon-datahub-temporal-provenance",
      version: DATAHUB_BENCHMARK_DATASET_VERSION,
      digest: datasetDigest,
      cases: cases.length,
      positiveCases: expected.filter(Boolean).length,
      negativeCases: expected.filter((value) => !value).length,
    },
    systems: {
      currentView: {
        name: "DataHub current-view boundary",
        description:
          "Each mutable aspect is reduced to its latest retained version, matching the evidence ceiling of a latest-write-wins current view.",
        metrics: metrics(expected, currentPredictions),
      },
      retainedHistory: {
        name: "Archon retained-history audit",
        description:
          "The production version-history mapper and consistency engine evaluate every retained version with stable source identity and fail-closed provenance.",
        metrics: metrics(expected, historyPredictions),
      },
    },
    cases,
    controlCoverage: {
      governanceRulesEvaluated: [
        ...new Set(validateSnapshot(snapshot).map((result) => result.ruleId)),
      ].sort(),
      lineageGapFindings: lineageFindings.length,
      agentTrace: pipelineReport.trace.map((step) => step.agent),
    },
    limitations: [
      "This is a deterministic capability benchmark over synthetic DataHub-shaped fixtures, not a hosted latency or production-quality claim.",
      "The current-view comparison is a boundary baseline, not DataHub Analytics Agent or another vendor product.",
      "Live superiority is not claimed until the protected live proof runs against retained history from a real DataHub instance.",
    ],
  };
}

function percent(value: number | null): string {
  return value === null ? "n/a" : `${Math.round(value * 100)}%`;
}

export function dataHubBenchmarkToMarkdown(
  report: DataHubBenchmarkResult
): string {
  const current = report.systems.currentView.metrics;
  const history = report.systems.retainedHistory.metrics;
  const lines = [
    "# Archon DataHub temporal-provenance benchmark",
    "",
    `- Dataset: \`${report.dataset.name}@${report.dataset.version}\``,
    `- Dataset digest: \`${report.dataset.digest}\``,
    `- Cases: ${report.dataset.cases} (${report.dataset.positiveCases} positive, ${report.dataset.negativeCases} negative)`,
    "",
    "## Measured comparison",
    "",
    "| System boundary | Recall | Precision | F1 | False positives |",
    "|---|---:|---:|---:|---:|",
    `| Current latest-write-wins view | ${percent(current.recall)} | ${percent(current.precision)} | ${percent(current.f1)} | ${current.falsePositives} |`,
    `| Archon retained-history audit | ${percent(history.recall)} | ${percent(history.precision)} | ${percent(history.f1)} | ${history.falsePositives} |`,
    "",
    "## Cases",
    "",
    "| Case | Expected | Current view | Retained history |",
    "|---|---|---|---|",
    ...report.cases.map(
      (item) =>
        `| ${item.title} | ${item.expectedConflict ? "conflict" : "no conflict"} | ${item.currentView.detected ? "detected" : "not detected"} | ${item.retainedHistory.detected ? "detected" : "not detected"} |`
    ),
    "",
    "## Control coverage",
    "",
    `- Governance rules evaluated: ${report.controlCoverage.governanceRulesEvaluated.join(", ")}`,
    `- Fixture lineage-gap findings: ${report.controlCoverage.lineageGapFindings}`,
    `- Agent trace: ${report.controlCoverage.agentTrace.join(" → ")}`,
    "",
    "## Limitations",
    "",
    ...report.limitations.map((limitation) => `- ${limitation}`),
    "",
  ];
  return lines.join("\n");
}
