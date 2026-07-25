import { createHash } from "node:crypto";
import { lstat, mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { NarratorAgent } from "../src/agents/narrator.js";
import {
  FIXTURE_REPORTS,
  FIXTURE_VERSION_HISTORY,
} from "../src/datahub/fixtures.js";
import { FakeDataHubMcpClient } from "../src/datahub/mcp-client.js";
import type {
  DataHubTagMutationPort,
  G6FindingEvidence,
  MutationAck,
  TagProjection,
  TagProjectionReader,
} from "../src/remediation/contracts.js";
import {
  createApprovalDecision,
  createApprovalRequest,
  executeApprovedRemediation,
  InMemoryExecutionJournal,
} from "../src/remediation/control-loop.js";
import {
  canonicalize,
  digest,
  type Sha256Digest,
} from "../src/remediation/integrity.js";
import {
  createTagProjection,
  createTrustedRemediationPolicy,
  planG6Remediation,
} from "../src/remediation/planner.js";
import {
  createRollbackProposal,
  verifyExecutionReceipt,
} from "../src/remediation/receipt.js";
import {
  auditReportToJson,
  auditReportToMarkdown,
  auditReportToSarif,
} from "../src/reporting/exporters.js";
import { FakeLlmClient } from "../src/llm/fake.js";
import { AuditPipeline, type AuditReport } from "../src/pipeline/pipeline.js";

const REPOSITORY = "upgradedev/archon-datahub";
const CI_WORKFLOW_PATH = ".github/workflows/ci.yml";
const NETWORK_DENY_MARKER = Symbol.for(
  "archon.judge-evidence.network-deny/v1"
);
const TOOL_VERSION = "0.1.0";
const EVIDENCE_CLASS = "SYNTHETIC_OFFLINE_FIXTURE";
const ENTITY_URN =
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)";
const CLASSIFICATION_TAG = "urn:li:tag:PII";
const OBSERVED_AT = "2026-07-23T10:00:00.000Z";
const APPROVAL_REQUESTED_AT = "2026-07-23T10:01:00.000Z";
const APPROVAL_EXPIRES_AT = "2026-07-23T10:11:00.000Z";
const APPROVAL_DECIDED_AT = "2026-07-23T10:02:00.000Z";
const EXECUTION_STARTED_AT = "2026-07-23T10:03:00.000Z";
const EXECUTION_COMPLETED_AT = "2026-07-23T10:03:01.000Z";
const PUBLIC_FIXTURE_URNS = new Set([
  "urn:li:corpGroup:team-data",
  "urn:li:corpGroup:team-dataeng",
  "urn:li:corpGroup:team-finance",
  "urn:li:corpGroup:team-ops",
  "urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD)",
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)",
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,raw_orders,PROD)",
  "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)",
  "urn:li:domain:sales",
  "urn:li:tag:PII",
]);
const PUBLIC_FIXTURE_SOURCES = new Set(["dbt-ingest", "snowflake-ingest"]);
const PUBLIC_FIXTURE_RUN_IDS = new Set([
  "dbt-manifest-2026-07-01",
  "snowflake-connector-2026-06-01",
  "snowflake-connector-2026-07-01",
]);
const PUBLIC_FIXTURE_PIPELINES = new Set(["dbt-prod", "snowflake-prod"]);

export const JUDGE_EVIDENCE_PAYLOAD_PATHS = [
  "README.md",
  "audit/report.json",
  "audit/report.md",
  "audit/report.sarif",
  "control/evidence-dossier.json",
  "control/remediation-plan.json",
  "control/approval-request.json",
  "control/approval-decision.json",
  "control/execution-receipt.json",
  "control/rollback-proposal.json",
] as const;

export const JUDGE_EVIDENCE_ALL_PATHS = [
  ...JUDGE_EVIDENCE_PAYLOAD_PATHS,
  "manifest.json",
  "SHA256SUMS",
] as const;

export interface JudgeEvidenceFileDescriptor {
  path: string;
  mediaType: string;
  bytes: number;
  sha256: Sha256Digest;
}

export interface JudgeEvidenceManifestV1 {
  schemaVersion: "archon.judge-evidence-pack/v1";
  evidenceClass: typeof EVIDENCE_CLASS;
  source: {
    repository: typeof REPOSITORY;
    releaseSha: string;
    fixtureDigest: Sha256Digest;
    toolVersion: typeof TOOL_VERSION;
  };
  fixtureClock: {
    observedAt: typeof OBSERVED_AT;
    approvalRequestedAt: typeof APPROVAL_REQUESTED_AT;
    approvalDecidedAt: typeof APPROVAL_DECIDED_AT;
    executionStartedAt: typeof EXECUTION_STARTED_AT;
    executionCompletedAt: typeof EXECUTION_COMPLETED_AT;
  };
  claims: {
    liveDataHub: false;
    liveMutation: false;
    mutationPort: "in-memory synthetic fixture";
  };
  summary: {
    entities: 3;
    findings: 7;
    contradictions: 2;
    lineageGaps: 1;
    governanceViolations: 4;
    receiptOutcome: "VERIFIED";
    verificationChecksPassed: 5;
    rollbackAvailability: "ELIGIBLE";
  };
  bindings: {
    reportDigest: Sha256Digest;
    dossierDigest: Sha256Digest;
    planDigest: Sha256Digest;
    approvalRequestDigest: Sha256Digest;
    approvalDecisionDigest: Sha256Digest;
    receiptDigest: Sha256Digest;
    rollbackProposalDigest: Sha256Digest;
  };
  files: JudgeEvidenceFileDescriptor[];
  digest: Sha256Digest;
}

export interface JudgeEvidencePack {
  files: ReadonlyMap<string, string>;
  manifest: JudgeEvidenceManifestV1;
}

class SyntheticTagPort implements TagProjectionReader, DataHubTagMutationPort {
  projection: TagProjection;
  writes = 0;

  constructor(before: TagProjection) {
    this.projection = before;
  }

  async readTagProjection(target: {
    entityUrn: string;
    columnPath: string;
  }): Promise<TagProjection> {
    if (
      target.entityUrn !== this.projection.entityUrn ||
      target.columnPath !== this.projection.columnPath
    ) {
      throw new Error("Synthetic evidence attempted to read outside its fixed target.");
    }
    return this.projection;
  }

  async addTags(input: {
    tagUrns: readonly string[];
    entityUrns: readonly string[];
    columnPaths?: readonly (string | null)[];
  }): Promise<MutationAck> {
    const tag = input.tagUrns[0];
    const entityUrn = input.entityUrns[0];
    const columnPaths = input.columnPaths;
    const columnPath = columnPaths?.[0];
    if (
      input.tagUrns.length !== 1 ||
      input.entityUrns.length !== 1 ||
      columnPaths === undefined ||
      columnPaths.length !== 1 ||
      tag !== CLASSIFICATION_TAG ||
      entityUrn !== this.projection.entityUrn ||
      columnPath !== this.projection.columnPath
    ) {
      throw new Error("Synthetic evidence attempted a mutation outside the fixed G6 action.");
    }
    this.writes += 1;
    this.projection = createTagProjection({
      entityUrn,
      columnPath,
      tags: [...this.projection.tags, tag],
    });
    return {
      requestDigest: digest({
        tagUrns: [...input.tagUrns],
        entityUrns: [...input.entityUrns],
        columnPaths: [...columnPaths],
      }),
      responseDigest: digest({
        fixture: "archon-judge-evidence/v1",
        success: true,
        writes: this.writes,
      }),
    };
  }
}

function assertReleaseSha(releaseSha: string): void {
  if (!/^[a-f0-9]{40}$/u.test(releaseSha)) {
    throw new Error("releaseSha must be an exact lowercase 40-character Git SHA.");
  }
}

function assertCiBindings(releaseSha: string, outputDirectory: string): void {
  if (process.env["GITHUB_ACTIONS"] !== "true") {
    throw new Error(
      "Filesystem judge evidence is CI-only; use the in-memory builder for tests."
    );
  }
  if (process.env["GITHUB_REPOSITORY"] !== REPOSITORY) {
    throw new Error(`GITHUB_REPOSITORY must equal ${REPOSITORY}.`);
  }
  if (process.env["GITHUB_WORKFLOW"] !== "CI") {
    throw new Error("Judge evidence must run from the CI workflow.");
  }
  const workflowRef = process.env["GITHUB_WORKFLOW_REF"];
  if (
    !workflowRef?.startsWith(
      `${REPOSITORY}/${CI_WORKFLOW_PATH}@refs/`
    )
  ) {
    throw new Error(
      `GITHUB_WORKFLOW_REF must bind ${CI_WORKFLOW_PATH} in the canonical repository.`
    );
  }
  if (!["push", "pull_request"].includes(process.env["GITHUB_EVENT_NAME"] ?? "")) {
    throw new Error("Judge evidence requires the CI push or pull_request event.");
  }
  if (Reflect.get(globalThis, NETWORK_DENY_MARKER) !== true) {
    throw new Error("The judge-evidence network deny preload is required.");
  }
  if (process.env["GITHUB_SHA"] !== releaseSha) {
    throw new Error("--release-sha must equal GITHUB_SHA in GitHub Actions.");
  }
  const runnerTemp = process.env["RUNNER_TEMP"];
  if (!runnerTemp) throw new Error("RUNNER_TEMP is required in GitHub Actions.");
  const temporaryRoot = resolve(runnerTemp);
  const output = resolve(outputDirectory);
  const fromTemporaryRoot = relative(temporaryRoot, output);
  if (
    fromTemporaryRoot.length === 0 ||
    fromTemporaryRoot === ".." ||
    fromTemporaryRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(fromTemporaryRoot)
  ) {
    throw new Error("--output must remain below RUNNER_TEMP in GitHub Actions.");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertPublicFixtureValue(value: unknown, path: string): void {
  if (typeof value === "string") {
    if (
      /@|https?:\/\/|-----BEGIN .*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/iu.test(
        value
      )
    ) {
      throw new Error(
        `The public fixture contains a private-identity-shaped value at ${path}.`
      );
    }
    for (const urn of value.match(/urn:li:[A-Za-z0-9:(),._-]+/gu) ?? []) {
      if (!PUBLIC_FIXTURE_URNS.has(urn)) {
        throw new Error(`The public fixture contains an unapproved URN at ${path}.`);
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertPublicFixtureValue(entry, `${path}[${index}]`)
    );
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (
      /(?:accesstoken|apikey|authorization|clientsecret|cookie|credential|idtoken|password|privatekey|refreshtoken|secretaccesskey|sessiontoken|tasktoken)/u.test(
        normalizedKey
      )
    ) {
      throw new Error(`The public fixture contains a forbidden key at ${path}.${key}.`);
    }
    assertPublicFixtureValue(entry, `${path}.${key}`);
  }
}

function assertPublicFixtureBoundary(): void {
  for (const report of FIXTURE_REPORTS) {
    if (
      !PUBLIC_FIXTURE_SOURCES.has(report.source) ||
      !/^scan-2026-(?:06|07)-01$/u.test(report.scanId)
    ) {
      throw new Error("The public report fixture identity contract changed.");
    }
  }
  for (const history of FIXTURE_VERSION_HISTORY) {
    for (const version of history.versions) {
      const runId = version.systemMetadata?.runId;
      const pipelineName = version.systemMetadata?.pipelineName;
      if (
        (runId !== undefined && !PUBLIC_FIXTURE_RUN_IDS.has(runId)) ||
        (pipelineName !== undefined &&
          !PUBLIC_FIXTURE_PIPELINES.has(pipelineName))
      ) {
        throw new Error("The public history fixture provenance contract changed.");
      }
    }
  }
  assertPublicFixtureValue(FIXTURE_REPORTS, "FIXTURE_REPORTS");
  assertPublicFixtureValue(FIXTURE_VERSION_HISTORY, "FIXTURE_VERSION_HISTORY");
}

function canonicalPrettyJson(value: unknown): string {
  return `${JSON.stringify(JSON.parse(canonicalize(value)), null, 2)}\n`;
}

function byteDigest(value: string): Sha256Digest {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function mediaType(path: string): string {
  if (path.endsWith(".sarif")) return "application/sarif+json";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".md")) return "text/markdown; charset=utf-8";
  return "text/plain; charset=utf-8";
}

function findingCounts(report: AuditReport): {
  contradictions: number;
  lineageGaps: number;
  governanceViolations: number;
} {
  let contradictions = 0;
  let lineageGaps = 0;
  let governanceViolations = 0;
  for (const finding of report.findings) {
    if (finding.type === "contradiction") contradictions += 1;
    if (finding.type === "lineage_gap") lineageGaps += 1;
    if (finding.type === "governance_violation") governanceViolations += 1;
  }
  return { contradictions, lineageGaps, governanceViolations };
}

function downstreamEvidence(finding: AuditReport["findings"][number]): {
  downstreamUrns: string[];
  truncated: boolean;
} {
  const raw = finding.detail["blastRadius"];
  if (!isRecord(raw)) return { downstreamUrns: [], truncated: false };
  const downstream = Array.isArray(raw["downstream"]) ? raw["downstream"] : [];
  const downstreamUrns = downstream
    .map((entry) =>
      isRecord(entry) && typeof entry["urn"] === "string" ? entry["urn"] : null
    )
    .filter((value): value is string => value !== null);
  return {
    downstreamUrns: [...new Set(downstreamUrns)].sort(compareCodePoints),
    truncated: raw["truncated"] === true,
  };
}

function deterministicClock(values: readonly string[]): () => string {
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)]!;
}

function judgeReadme(input: {
  releaseSha: string;
  fixtureDigest: Sha256Digest;
  report: AuditReport;
  bindings: JudgeEvidenceManifestV1["bindings"];
}): string {
  return [
    "# Archon DataHub judge evidence",
    "",
    "> **Synthetic offline fixture evidence.** This bundle is generated by the real Archon",
    "> audit, planning, approval, execution-verification, receipt, and rollback-proposal",
    "> functions over committed deterministic fixtures. It is not evidence of a live DataHub",
    "> tenant, hosted AWS deployment, or real catalog mutation.",
    "",
    `- Repository: \`${REPOSITORY}\``,
    `- Tested release SHA: \`${input.releaseSha}\``,
    `- Fixture digest: \`${input.fixtureDigest}\``,
    `- Scan: \`${input.report.scanId}\``,
    `- Findings: ${input.report.findings.length} across ${input.report.classification.totalEntities} entities`,
    "",
    "## Integrity chain",
    "",
    `1. Report: \`${input.bindings.reportDigest}\``,
    `2. Evidence dossier: \`${input.bindings.dossierDigest}\``,
    `3. Remediation plan: \`${input.bindings.planDigest}\``,
    `4. Approval request: \`${input.bindings.approvalRequestDigest}\``,
    `5. Approval decision: \`${input.bindings.approvalDecisionDigest}\``,
    `6. Verified execution receipt: \`${input.bindings.receiptDigest}\``,
    `7. Fresh-approval rollback proposal: \`${input.bindings.rollbackProposalDigest}\``,
    "",
    "Every embedded semantic digest is produced by Archon's canonical SHA-256 implementation. File-byte",
    "digests are recorded in `manifest.json` and `SHA256SUMS`. The pack contains no task",
    "tokens, provider credentials, live endpoints, raw provider responses, or real user data.",
    "",
  ].join("\n");
}

export async function buildJudgeEvidencePack(input: {
  releaseSha: string;
}): Promise<JudgeEvidencePack> {
  assertReleaseSha(input.releaseSha);
  assertPublicFixtureBoundary();

  const pipeline = new AuditPipeline({
    narrator: new NarratorAgent(
      new FakeLlmClient(),
      "archon-deterministic-fixture-narrator-v1"
    ),
  });
  const report = await pipeline.run(new FakeDataHubMcpClient());
  const counts = findingCounts(report);
  if (
    report.classification.totalEntities !== 3 ||
    report.findings.length !== 7 ||
    counts.contradictions !== 2 ||
    counts.lineageGaps !== 1 ||
    counts.governanceViolations !== 4
  ) {
    throw new Error("The committed fixture finding profile changed unexpectedly.");
  }

  const g6 = report.findings.find(
    (finding) =>
      finding.type === "governance_violation" &&
      finding.detail["ruleId"] === "G6" &&
      finding.subject === ENTITY_URN
  );
  if (!g6) throw new Error("The deterministic fixture no longer contains its G6 finding.");
  const rawFields = g6.detail["unclassifiedFields"];
  if (!Array.isArray(rawFields) || rawFields.length === 0) {
    throw new Error("The deterministic G6 finding has no structured target field.");
  }
  const validatedFields: string[] = [];
  for (const field of rawFields) {
    if (!isNonEmptyString(field)) {
      throw new Error("The deterministic G6 finding contains an invalid target field.");
    }
    validatedFields.push(field);
  }
  const unclassifiedFields = [...new Set(validatedFields)].sort(compareCodePoints);
  const columnPath = unclassifiedFields[0]!;
  const before = createTagProjection({
    entityUrn: g6.subject,
    columnPath,
    tags: [],
  });
  const findingEvidence: G6FindingEvidence = {
    type: "governance_violation",
    severity: g6.severity,
    subject: g6.subject,
    ruleId: "G6",
    unclassifiedFields,
  };
  const blastRadius = downstreamEvidence(g6);
  const planned = planG6Remediation({
    scanId: report.scanId,
    finding: findingEvidence,
    columnPath,
    before,
    policy: createTrustedRemediationPolicy({
      policyId: "archon.judge-evidence.g6.v1",
      enabled: true,
      classificationTagUrn: CLASSIFICATION_TAG,
      allowedEntityUrnPrefixes: ["urn:li:dataset:"],
    }),
    observedAt: OBSERVED_AT,
    provenance: [
      {
        sourceKind: "current_view",
        entityUrn: g6.subject,
        aspect: "schemaMetadata",
        observedAt: OBSERVED_AT,
        valueDigest: before.digest,
      },
    ],
    blastRadius,
  });
  if (planned.disposition !== "ACTIONABLE") {
    throw new Error(`The fixed G6 evidence became ${planned.reason}.`);
  }

  const approvalRequest = createApprovalRequest({
    dossier: planned.dossier,
    plan: planned.plan,
    requestedAt: APPROVAL_REQUESTED_AT,
    expiresAt: APPROVAL_EXPIRES_AT,
    nonce: "archon-judge-evidence-nonce-v1",
  });
  const approvalDecision = createApprovalDecision({
    request: approvalRequest,
    plan: planned.plan,
    decision: "APPROVE",
    approver: {
      subject: "steward@example.test",
      issuer: "https://oidc.example.test",
      roles: ["DataSteward"],
      authenticated: true,
    },
    decidedAt: APPROVAL_DECIDED_AT,
  });
  const port = new SyntheticTagPort(before);
  const receipt = await executeApprovedRemediation({
    dossier: planned.dossier,
    plan: planned.plan,
    request: approvalRequest,
    decision: approvalDecision,
    reader: port,
    mutation: port,
    journal: new InMemoryExecutionJournal(
      () => Date.parse(EXECUTION_STARTED_AT)
    ),
    idempotencyKey: "archon-judge-evidence-g6-v1",
    clock: deterministicClock([
      EXECUTION_STARTED_AT,
      EXECUTION_COMPLETED_AT,
    ]),
  });
  const receiptVerification = verifyExecutionReceipt(receipt);
  if (
    port.writes !== 1 ||
    receipt.outcome !== "VERIFIED" ||
    !receiptVerification.valid ||
    receipt.checks.length !== 5 ||
    receipt.checks.some((check) => !check.passed) ||
    receipt.rollback.availability !== "ELIGIBLE"
  ) {
    throw new Error(
      `The deterministic governed action did not verify: ${receiptVerification.issues.join(",")}`
    );
  }
  const rollbackProposal = createRollbackProposal(receipt, port.projection);
  if (!rollbackProposal || rollbackProposal.requiresFreshApproval !== true) {
    throw new Error("The verified receipt did not produce a fresh-approval rollback proposal.");
  }

  const fixtureDigest = digest({
    reports: FIXTURE_REPORTS,
    versionHistories: FIXTURE_VERSION_HISTORY,
  });
  const bindings: JudgeEvidenceManifestV1["bindings"] = {
    reportDigest: digest(report),
    dossierDigest: planned.dossier.digest,
    planDigest: planned.plan.digest,
    approvalRequestDigest: approvalRequest.digest,
    approvalDecisionDigest: approvalDecision.digest,
    receiptDigest: receipt.digest,
    rollbackProposalDigest: rollbackProposal.digest,
  };

  const payload = new Map<string, string>();
  payload.set(
    "README.md",
    judgeReadme({
      releaseSha: input.releaseSha,
      fixtureDigest,
      report,
      bindings,
    })
  );
  payload.set("audit/report.json", auditReportToJson(report));
  payload.set("audit/report.md", auditReportToMarkdown(report));
  payload.set(
    "audit/report.sarif",
    canonicalPrettyJson(auditReportToSarif(report, TOOL_VERSION))
  );
  payload.set(
    "control/evidence-dossier.json",
    canonicalPrettyJson(planned.dossier)
  );
  payload.set(
    "control/remediation-plan.json",
    canonicalPrettyJson(planned.plan)
  );
  payload.set(
    "control/approval-request.json",
    canonicalPrettyJson(approvalRequest)
  );
  payload.set(
    "control/approval-decision.json",
    canonicalPrettyJson(approvalDecision)
  );
  payload.set(
    "control/execution-receipt.json",
    canonicalPrettyJson(receipt)
  );
  payload.set(
    "control/rollback-proposal.json",
    canonicalPrettyJson(rollbackProposal)
  );

  const payloadFiles = [...payload.entries()]
    .map(([path, content]): JudgeEvidenceFileDescriptor => ({
      path,
      mediaType: mediaType(path),
      bytes: Buffer.byteLength(content, "utf8"),
      sha256: byteDigest(content),
    }))
    .sort((a, b) => compareCodePoints(a.path, b.path));
  const manifestUnsigned: Omit<JudgeEvidenceManifestV1, "digest"> = {
    schemaVersion: "archon.judge-evidence-pack/v1",
    evidenceClass: EVIDENCE_CLASS,
    source: {
      repository: REPOSITORY,
      releaseSha: input.releaseSha,
      fixtureDigest,
      toolVersion: TOOL_VERSION,
    },
    fixtureClock: {
      observedAt: OBSERVED_AT,
      approvalRequestedAt: APPROVAL_REQUESTED_AT,
      approvalDecidedAt: APPROVAL_DECIDED_AT,
      executionStartedAt: EXECUTION_STARTED_AT,
      executionCompletedAt: EXECUTION_COMPLETED_AT,
    },
    claims: {
      liveDataHub: false,
      liveMutation: false,
      mutationPort: "in-memory synthetic fixture",
    },
    summary: {
      entities: 3,
      findings: 7,
      contradictions: 2,
      lineageGaps: 1,
      governanceViolations: 4,
      receiptOutcome: "VERIFIED",
      verificationChecksPassed: 5,
      rollbackAvailability: "ELIGIBLE",
    },
    bindings,
    files: payloadFiles,
  };
  const manifest: JudgeEvidenceManifestV1 = {
    ...manifestUnsigned,
    digest: digest(manifestUnsigned),
  };

  const files = new Map(payload);
  files.set("manifest.json", canonicalPrettyJson(manifest));
  const checksumTargets = [...files.keys()].sort(compareCodePoints);
  files.set(
    "SHA256SUMS",
    `${checksumTargets
      .map((path) => `${byteDigest(files.get(path)!).slice("sha256:".length)}  ${path}`)
      .join("\n")}\n`
  );

  const actualPaths = [...files.keys()];
  if (
    actualPaths.length !== JUDGE_EVIDENCE_ALL_PATHS.length ||
    JUDGE_EVIDENCE_ALL_PATHS.some((path) => !files.has(path))
  ) {
    throw new Error("The judge evidence pack does not match its fixed file contract.");
  }
  return { files, manifest };
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export async function writeJudgeEvidencePack(
  outputDirectory: string,
  pack: JudgeEvidencePack
): Promise<void> {
  if (outputDirectory.trim().length === 0) {
    throw new Error("An explicit output directory is required.");
  }
  const root = resolve(outputDirectory);
  if (await pathExists(root)) {
    throw new Error("The output directory already exists; refusing to overwrite it.");
  }
  await mkdir(root, { recursive: true, mode: 0o700 });
  for (const path of JUDGE_EVIDENCE_ALL_PATHS) {
    const content = pack.files.get(path);
    if (content === undefined) throw new Error(`Missing generated evidence file: ${path}`);
    const destination = resolve(root, path);
    const fromRoot = relative(root, destination);
    if (
      fromRoot.length === 0 ||
      fromRoot === ".." ||
      fromRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
      isAbsolute(fromRoot)
    ) {
      throw new Error(`Unsafe generated evidence path: ${path}`);
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await writeFile(destination, content, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  }
}

function parseCliArguments(argv: readonly string[]): {
  output: string;
  releaseSha: string;
} {
  let output: string | undefined;
  let releaseSha: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument !== "--output" && argument !== "--release-sha") {
      throw new Error(`Unsupported argument: ${argument ?? "(missing)"}`);
    }
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${argument} requires a value.`);
    }
    if (argument === "--output") {
      if (output !== undefined) throw new Error("--output may be supplied only once.");
      output = value;
    } else {
      if (releaseSha !== undefined) {
        throw new Error("--release-sha may be supplied only once.");
      }
      releaseSha = value;
    }
    index += 1;
  }
  if (output === undefined || releaseSha === undefined) {
    throw new Error("--output and --release-sha are required.");
  }
  return { output, releaseSha };
}

async function main(): Promise<void> {
  const args = parseCliArguments(process.argv.slice(2));
  assertCiBindings(args.releaseSha, args.output);
  const pack = await buildJudgeEvidencePack({ releaseSha: args.releaseSha });
  await writeJudgeEvidencePack(args.output, pack);
  console.log(`Wrote ${pack.files.size} verified-shape evidence files to ${resolve(args.output)}.`);
}

const isMain =
  Boolean(process.argv[1]) &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]!);

if (isMain) {
  main().catch((error: unknown) => {
    console.error(`judge evidence generation failed: ${(error as Error).message}`);
    process.exitCode = 1;
  });
}
