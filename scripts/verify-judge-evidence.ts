import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditReport } from "../src/pipeline/pipeline.js";
import type {
  ApprovalDecisionV1,
  ApprovalRequestV1,
  EvidenceDossierV1,
  ExecutionReceiptV1,
  RemediationPlanV1,
  RollbackProposalV1,
} from "../src/remediation/contracts.js";
import {
  verifyApprovalDecision,
  verifyApprovalRequest,
} from "../src/remediation/control-loop.js";
import {
  canonicalize,
  digest,
  verifyDigest,
  type Sha256Digest,
} from "../src/remediation/integrity.js";
import {
  verifyEvidenceDossier,
  verifyRemediationPlan,
} from "../src/remediation/planner.js";
import {
  createRollbackProposal,
  verifyExecutionReceipt,
} from "../src/remediation/receipt.js";
import {
  buildJudgeEvidencePack,
  JUDGE_EVIDENCE_ALL_PATHS,
  JUDGE_EVIDENCE_PAYLOAD_PATHS,
  type JudgeEvidenceFileDescriptor,
  type JudgeEvidenceManifestV1,
} from "./generate-judge-evidence.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_PACK_BYTES = 8 * 1024 * 1024;
const REPOSITORY = "upgradedev/archon-datahub";
const CI_WORKFLOW_PATH = ".github/workflows/ci.yml";
const NETWORK_DENY_MARKER = Symbol.for(
  "archon.judge-evidence.network-deny/v1"
);
const FORBIDDEN_NORMALIZED_JSON_KEYS = new Set([
  "accesstoken",
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "idtoken",
  "password",
  "privatekey",
  "rawresponse",
  "refreshtoken",
  "secretaccesskey",
  "sessiontoken",
  "tasktoken",
  "token",
]);
const CREDENTIAL_PATTERNS: ReadonlyArray<{
  name: string;
  pattern: RegExp;
}> = [
  { name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u },
  { name: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/u },
  {
    name: "GitHub fine-grained token",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  },
  { name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u },
  { name: "Google API key", pattern: /\bAIza[A-Za-z0-9_-]{30,}\b/u },
  {
    name: "OpenAI or compatible API key",
    pattern: /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/u,
  },
  {
    name: "JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  },
  {
    name: "private key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  },
  { name: "bearer credential", pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/iu },
];
const PUBLIC_HTTPS_URLS = new Set([
  "https://github.com/upgradedev/archon-datahub",
  "https://json.schemastore.org/sarif-2.1.0.json",
  "https://oidc.example.test",
]);
const PUBLIC_EMAILS = new Set(["steward@example.test"]);
const PUBLIC_URNS = new Set([
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
const PUBLIC_DATASET_DERIVED_SUFFIXES = [
  "#amount:schema",
  "#amount",
  ":deprecation",
  ":domain",
  ":lineage",
  ":ownership",
] as const;

interface LoadedFile {
  bytes: Buffer;
  text: string;
}

function fail(message: string): never {
  throw new Error(`Judge evidence verification failed: ${message}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value).sort(compareCodePoints);
  const wanted = [...expected].sort(compareCodePoints);
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index])
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function hasPublicUrnBoundary(urn: string, suffix: string): boolean {
  if (suffix.length === 0) return true;
  const next = suffix[0]!;
  if (next === ":" && /^\s/u.test(suffix[1] ?? "")) return true;
  if (next !== ":" && next !== "#") {
    return !/[A-Za-z0-9_.-]/u.test(next);
  }
  if (!urn.startsWith("urn:li:dataset:")) return false;

  // Audit fact IDs deterministically embed an already-approved entity URN before
  // one closed field/aspect suffix (for example `<urn>#amount:schema` or
  // `<urn>:ownership`). Treat only those exact derived-ID suffixes as boundaries;
  // extensions remain fail-closed.
  return PUBLIC_DATASET_DERIVED_SUFFIXES.some((derivedSuffix) => {
    if (!suffix.startsWith(derivedSuffix)) return false;
    const remainder = suffix.slice(derivedSuffix.length);
    if (remainder.length === 0 || /^:\s/u.test(remainder)) return true;
    return !/[A-Za-z0-9_.:#-]/u.test(remainder[0]!);
  });
}

export function assertPublicJudgeEvidenceIdentifiers(
  text: string,
  path: string
): void {
  for (
    const url of text.match(
      /https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._~:/?@!$&'()*+,;=%#-]*)?/gu
    ) ?? []
  ) {
    if (!PUBLIC_HTTPS_URLS.has(url)) {
      fail(`${path} contains an unapproved HTTPS identity.`);
    }
  }
  if (text.includes("http://")) fail(`${path} contains a plaintext HTTP identity.`);
  for (
    const email of text.match(
      /[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gu
    ) ?? []
  ) {
    if (!PUBLIC_EMAILS.has(email)) {
      fail(`${path} contains an unapproved email identity.`);
    }
  }
  let urnOffset = 0;
  while ((urnOffset = text.indexOf("urn:li:", urnOffset)) >= 0) {
    const allowed = [...PUBLIC_URNS]
      .sort((left, right) => right.length - left.length)
      .find((urn) => {
        if (!text.startsWith(urn, urnOffset)) return false;
        const suffix = text.slice(urnOffset + urn.length);
        return hasPublicUrnBoundary(urn, suffix);
      });
    if (!allowed) fail(`${path} contains an unapproved DataHub URN.`);
    urnOffset += allowed.length;
  }
}

function parseJson<T>(content: string, path: string): T {
  try {
    return JSON.parse(content) as T;
  } catch {
    fail(`${path} is not valid JSON.`);
  }
}

function byteDigest(bytes: Buffer): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertReleaseSha(releaseSha: string): void {
  if (!/^[a-f0-9]{40}$/u.test(releaseSha)) {
    fail("release SHA must be an exact lowercase 40-character Git SHA.");
  }
}

function assertCiBindings(releaseSha: string, inputDirectory: string): void {
  if (process.env["GITHUB_ACTIONS"] !== "true") {
    fail("filesystem judge-evidence verification is CI-only.");
  }
  if (process.env["GITHUB_REPOSITORY"] !== REPOSITORY) {
    fail(`GITHUB_REPOSITORY must equal ${REPOSITORY}.`);
  }
  if (process.env["GITHUB_WORKFLOW"] !== "CI") {
    fail("judge evidence must run from the CI workflow.");
  }
  const workflowRef = process.env["GITHUB_WORKFLOW_REF"];
  if (
    !workflowRef?.startsWith(
      `${REPOSITORY}/${CI_WORKFLOW_PATH}@refs/`
    )
  ) {
    fail(
      `GITHUB_WORKFLOW_REF must bind ${CI_WORKFLOW_PATH} in the canonical repository.`
    );
  }
  if (!["push", "pull_request"].includes(process.env["GITHUB_EVENT_NAME"] ?? "")) {
    fail("judge evidence requires the CI push or pull_request event.");
  }
  if (Reflect.get(globalThis, NETWORK_DENY_MARKER) !== true) {
    fail("the judge-evidence network deny preload is required.");
  }
  if (process.env["GITHUB_SHA"] !== releaseSha) {
    fail("--release-sha must equal GITHUB_SHA in GitHub Actions.");
  }
  const runnerTemp = process.env["RUNNER_TEMP"];
  if (!runnerTemp) fail("RUNNER_TEMP is required in GitHub Actions.");
  const temporaryRoot = resolve(runnerTemp);
  const input = resolve(inputDirectory);
  const fromTemporaryRoot = relative(temporaryRoot, input);
  if (
    fromTemporaryRoot.length === 0 ||
    fromTemporaryRoot === ".." ||
    fromTemporaryRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(fromTemporaryRoot)
  ) {
    fail("--input must remain below RUNNER_TEMP in GitHub Actions.");
  }
}

function assertNoForbiddenJsonKeys(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoForbiddenJsonKeys(entry, `${path}[${index}]`)
    );
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (FORBIDDEN_NORMALIZED_JSON_KEYS.has(normalizedKey)) {
      fail(`${path} contains forbidden key ${key}.`);
    }
    assertNoForbiddenJsonKeys(entry, `${path}.${key}`);
  }
}

async function collectRegularFiles(
  root: string,
  directory = root,
  prefix = ""
): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((a, b) => compareCodePoints(a.name, b.name));
  const paths: string[] = [];
  for (const entry of entries) {
    const relativePath = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
    const absolutePath = resolve(directory, entry.name);
    const metadata = await lstat(absolutePath);
    if (metadata.isSymbolicLink()) fail(`${relativePath} is a symbolic link.`);
    if (metadata.isDirectory()) {
      paths.push(...(await collectRegularFiles(root, absolutePath, relativePath)));
      continue;
    }
    if (!metadata.isFile()) fail(`${relativePath} is not a regular file.`);
    paths.push(relativePath);
  }
  return paths;
}

function assertManifest(
  value: unknown,
  releaseSha: string
): asserts value is JudgeEvidenceManifestV1 {
  if (!isRecord(value)) fail("manifest.json must contain an object.");
  if (
    !hasExactKeys(value, [
      "schemaVersion",
      "evidenceClass",
      "source",
      "fixtureClock",
      "claims",
      "summary",
      "bindings",
      "files",
      "digest",
    ])
  ) {
    fail("manifest contains missing or unexpected top-level fields.");
  }
  if (
    value["schemaVersion"] !== "archon.judge-evidence-pack/v1" ||
    value["evidenceClass"] !== "SYNTHETIC_OFFLINE_FIXTURE"
  ) {
    fail("manifest schema or evidence class is unsupported.");
  }
  const source = value["source"];
  if (
    !isRecord(source) ||
    !hasExactKeys(source, [
      "repository",
      "releaseSha",
      "fixtureDigest",
      "toolVersion",
    ]) ||
    source["repository"] !== "upgradedev/archon-datahub" ||
    source["releaseSha"] !== releaseSha ||
    source["toolVersion"] !== "0.1.0" ||
    !isDigest(source["fixtureDigest"])
  ) {
    fail("manifest source binding is invalid.");
  }
  const fixtureClock = value["fixtureClock"];
  if (
    !isRecord(fixtureClock) ||
    !hasExactKeys(fixtureClock, [
      "observedAt",
      "approvalRequestedAt",
      "approvalDecidedAt",
      "executionStartedAt",
      "executionCompletedAt",
    ]) ||
    fixtureClock["observedAt"] !== "2026-07-23T10:00:00.000Z" ||
    fixtureClock["approvalRequestedAt"] !== "2026-07-23T10:01:00.000Z" ||
    fixtureClock["approvalDecidedAt"] !== "2026-07-23T10:02:00.000Z" ||
    fixtureClock["executionStartedAt"] !== "2026-07-23T10:03:00.000Z" ||
    fixtureClock["executionCompletedAt"] !== "2026-07-23T10:03:01.000Z"
  ) {
    fail("manifest fixture clock is invalid.");
  }
  const claims = value["claims"];
  if (
    !isRecord(claims) ||
    !hasExactKeys(claims, [
      "liveDataHub",
      "liveMutation",
      "mutationPort",
    ]) ||
    claims["liveDataHub"] !== false ||
    claims["liveMutation"] !== false ||
    claims["mutationPort"] !== "in-memory synthetic fixture"
  ) {
    fail("manifest overclaims the synthetic evidence class.");
  }
  const summary = value["summary"];
  if (
    !isRecord(summary) ||
    !hasExactKeys(summary, [
      "entities",
      "findings",
      "contradictions",
      "lineageGaps",
      "governanceViolations",
      "receiptOutcome",
      "verificationChecksPassed",
      "rollbackAvailability",
    ]) ||
    summary["entities"] !== 3 ||
    summary["findings"] !== 7 ||
    summary["contradictions"] !== 2 ||
    summary["lineageGaps"] !== 1 ||
    summary["governanceViolations"] !== 4 ||
    summary["receiptOutcome"] !== "VERIFIED" ||
    summary["verificationChecksPassed"] !== 5 ||
    summary["rollbackAvailability"] !== "ELIGIBLE"
  ) {
    fail("manifest summary is invalid.");
  }
  const bindings = value["bindings"];
  const bindingKeys = [
    "reportDigest",
    "dossierDigest",
    "planDigest",
    "approvalRequestDigest",
    "approvalDecisionDigest",
    "receiptDigest",
    "rollbackProposalDigest",
  ] as const;
  if (
    !isRecord(bindings) ||
    !hasExactKeys(bindings, bindingKeys) ||
    bindingKeys.some((key) => !isDigest(bindings[key]))
  ) {
    fail("manifest semantic bindings are malformed.");
  }
  if (
    !isDigest(value["digest"]) ||
    !Array.isArray(value["files"]) ||
    value["files"].length !== JUDGE_EVIDENCE_PAYLOAD_PATHS.length
  ) {
    fail("manifest integrity fields are malformed.");
  }
}

function assertManifestDigest(manifest: JudgeEvidenceManifestV1): void {
  const { digest: manifestDigest, ...unsigned } = manifest;
  if (!verifyDigest(unsigned, manifestDigest)) {
    fail("manifest canonical digest does not verify.");
  }
}

function assertFileDescriptors(
  manifest: JudgeEvidenceManifestV1,
  files: ReadonlyMap<string, LoadedFile>
): void {
  const expectedPaths = [...JUDGE_EVIDENCE_PAYLOAD_PATHS].sort(compareCodePoints);
  const rawDescriptors: unknown[] = manifest.files;
  for (const descriptor of rawDescriptors) {
    if (
      !isRecord(descriptor) ||
      !hasExactKeys(descriptor, [
        "path",
        "mediaType",
        "bytes",
        "sha256",
      ]) ||
      typeof descriptor["path"] !== "string" ||
      typeof descriptor["mediaType"] !== "string" ||
      typeof descriptor["bytes"] !== "number" ||
      !Number.isSafeInteger(descriptor["bytes"]) ||
      descriptor["bytes"] < 1 ||
      !isDigest(descriptor["sha256"])
    ) {
      fail("manifest contains a malformed file descriptor.");
    }
  }
  const descriptors = rawDescriptors as JudgeEvidenceFileDescriptor[];
  const actualPaths = descriptors.map((descriptor) => descriptor.path);
  if (
    new Set(actualPaths).size !== actualPaths.length ||
    canonicalize([...actualPaths].sort(compareCodePoints)) !==
      canonicalize(expectedPaths)
  ) {
    fail("manifest payload file set is incomplete or duplicated.");
  }
  for (const descriptor of descriptors) {
    const observed = files.get(descriptor.path);
    if (!observed) fail(`manifest references missing payload ${descriptor.path}.`);
    if (
      descriptor.bytes !== observed.bytes.byteLength ||
      descriptor.sha256 !== byteDigest(observed.bytes)
    ) {
      fail(`manifest byte binding failed for ${descriptor.path}.`);
    }
  }
}

function assertSha256Sums(files: ReadonlyMap<string, LoadedFile>): void {
  const checksumFile = files.get("SHA256SUMS");
  if (!checksumFile) fail("SHA256SUMS is missing.");
  const lines = checksumFile.text.trimEnd().split("\n");
  const expectedTargets = [...JUDGE_EVIDENCE_ALL_PATHS]
    .filter((path) => path !== "SHA256SUMS")
    .sort(compareCodePoints);
  if (lines.length !== expectedTargets.length) {
    fail("SHA256SUMS has an unexpected entry count.");
  }
  const seen = new Set<string>();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9./-]+)$/u.exec(line);
    if (!match) fail("SHA256SUMS contains a malformed line.");
    const [, expectedHex, path] = match;
    if (!path || seen.has(path) || path === "SHA256SUMS") {
      fail("SHA256SUMS contains a duplicate or self-referential path.");
    }
    seen.add(path);
    const observed = files.get(path);
    if (!observed) fail(`SHA256SUMS references missing file ${path}.`);
    if (byteDigest(observed.bytes) !== `sha256:${expectedHex}`) {
      fail(`SHA256SUMS does not match ${path}.`);
    }
  }
  if (expectedTargets.some((path) => !seen.has(path))) {
    fail("SHA256SUMS omitted a required file.");
  }
}

function assertReportProfile(report: AuditReport): void {
  if (
    typeof report.scanId !== "string" ||
    !isRecord(report.classification) ||
    report.classification.totalEntities !== 3 ||
    !Array.isArray(report.findings) ||
    report.findings.length !== 7 ||
    !Array.isArray(report.trace)
  ) {
    fail("audit report structure or entity/finding totals changed.");
  }
  const counts = {
    contradiction: 0,
    lineage_gap: 0,
    governance_violation: 0,
  };
  for (const finding of report.findings) counts[finding.type] += 1;
  if (
    counts.contradiction !== 2 ||
    counts.lineage_gap !== 1 ||
    counts.governance_violation !== 4
  ) {
    fail("audit report no longer contains the expected 2/1/4 finding profile.");
  }
}

function assertSarif(content: string, findingCount: number): void {
  const sarif = parseJson<Record<string, unknown>>(content, "audit/report.sarif");
  const runs = sarif["runs"];
  if (sarif["version"] !== "2.1.0" || !Array.isArray(runs)) {
    fail("SARIF version or runs collection is invalid.");
  }
  const run = runs[0];
  if (runs.length !== 1 || !isRecord(run)) {
    fail("SARIF must contain exactly one run.");
  }
  const results = run["results"];
  if (!Array.isArray(results) || results.length !== findingCount) {
    fail("SARIF result count is not bound to the audit report.");
  }
  for (const result of results) {
    if (!isRecord(result)) {
      fail("SARIF result is missing its Archon fingerprint.");
    }
    const fingerprints = result["partialFingerprints"];
    if (!isRecord(fingerprints)) {
      fail("SARIF result is missing its Archon fingerprint.");
    }
    const fingerprint = fingerprints["archonFindingDigest"];
    if (
      typeof fingerprint !== "string" ||
      !/^[a-f0-9]{64}$/u.test(fingerprint)
    ) {
      fail("SARIF result has an invalid Archon fingerprint.");
    }
  }
}

function assertSemanticChain(
  files: ReadonlyMap<string, LoadedFile>,
  manifest: JudgeEvidenceManifestV1
): void {
  const report = parseJson<AuditReport>(
    files.get("audit/report.json")!.text,
    "audit/report.json"
  );
  const dossier = parseJson<EvidenceDossierV1>(
    files.get("control/evidence-dossier.json")!.text,
    "control/evidence-dossier.json"
  );
  const plan = parseJson<RemediationPlanV1>(
    files.get("control/remediation-plan.json")!.text,
    "control/remediation-plan.json"
  );
  const request = parseJson<ApprovalRequestV1>(
    files.get("control/approval-request.json")!.text,
    "control/approval-request.json"
  );
  const decision = parseJson<ApprovalDecisionV1>(
    files.get("control/approval-decision.json")!.text,
    "control/approval-decision.json"
  );
  const receipt = parseJson<ExecutionReceiptV1>(
    files.get("control/execution-receipt.json")!.text,
    "control/execution-receipt.json"
  );
  const rollback = parseJson<RollbackProposalV1>(
    files.get("control/rollback-proposal.json")!.text,
    "control/rollback-proposal.json"
  );

  assertReportProfile(report);
  assertSarif(files.get("audit/report.sarif")!.text, report.findings.length);
  if (!verifyEvidenceDossier(dossier)) fail("evidence dossier digest is invalid.");
  if (!verifyRemediationPlan(plan)) fail("remediation plan digest is invalid.");
  if (!verifyApprovalRequest(request)) fail("approval request digest is invalid.");
  if (!verifyApprovalDecision(decision)) fail("approval decision digest is invalid.");
  const receiptVerification = verifyExecutionReceipt(receipt);
  if (!receiptVerification.valid) {
    fail(`execution receipt is invalid: ${receiptVerification.issues.join(",")}.`);
  }
  const {
    rollbackId,
    digest: rollbackDigest,
    ...rollbackPayload
  } = rollback;
  if (
    rollback.schemaVersion !== "archon.rollback-proposal/v1" ||
    rollbackId !==
      `rollback-${rollbackDigest.slice("sha256:".length, "sha256:".length + 24)}` ||
    !verifyDigest(rollbackPayload, rollbackDigest) ||
    rollback.requiresFreshApproval !== true
  ) {
    fail("rollback proposal digest or fresh-approval requirement is invalid.");
  }
  if (
    plan.dossierDigest !== dossier.digest ||
    request.dossierDigest !== dossier.digest ||
    request.planDigest !== plan.digest ||
    decision.requestDigest !== request.digest ||
    decision.planDigest !== plan.digest ||
    receipt.dossierDigest !== dossier.digest ||
    receipt.planDigest !== plan.digest ||
    receipt.approvalDecisionDigest !== decision.digest ||
    rollback.originalReceiptDigest !== receipt.digest
  ) {
    fail("dossier/plan/approval/receipt/rollback bindings are inconsistent.");
  }
  if (
    receipt.outcome !== "VERIFIED" ||
    receipt.checks.length !== 5 ||
    receipt.checks.some((check) => !check.passed) ||
    receipt.rollback.availability !== "ELIGIBLE" ||
    !receipt.after
  ) {
    fail("execution receipt does not prove the exact verified transition.");
  }
  const recreatedRollback = createRollbackProposal(receipt, receipt.after);
  if (
    !recreatedRollback ||
    canonicalize(recreatedRollback) !== canonicalize(rollback)
  ) {
    fail("rollback proposal cannot be reproduced from the verified receipt.");
  }
  if (
    manifest.bindings.reportDigest !== digest(report) ||
    manifest.bindings.dossierDigest !== dossier.digest ||
    manifest.bindings.planDigest !== plan.digest ||
    manifest.bindings.approvalRequestDigest !== request.digest ||
    manifest.bindings.approvalDecisionDigest !== decision.digest ||
    manifest.bindings.receiptDigest !== receipt.digest ||
    manifest.bindings.rollbackProposalDigest !== rollback.digest
  ) {
    fail("manifest semantic bindings do not match the evidence chain.");
  }
  if (
    decision.approver.subject !== "steward@example.test" ||
    decision.approver.issuer !== "https://oidc.example.test"
  ) {
    fail("approval identity is not the fixed synthetic identity.");
  }
}

export async function verifyJudgeEvidenceDirectory(input: {
  directory: string;
  releaseSha: string;
}): Promise<JudgeEvidenceManifestV1> {
  assertReleaseSha(input.releaseSha);
  const root = resolve(input.directory);
  const rootMetadata = await lstat(root);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
    fail("input path must be a regular directory, not a symlink.");
  }

  const actualPaths = await collectRegularFiles(root);
  const expectedPaths = [...JUDGE_EVIDENCE_ALL_PATHS].sort(compareCodePoints);
  actualPaths.sort(compareCodePoints);
  if (canonicalize(actualPaths) !== canonicalize(expectedPaths)) {
    fail("directory contains missing, extra, or misplaced files.");
  }

  const files = new Map<string, LoadedFile>();
  let totalBytes = 0;
  for (const path of actualPaths) {
    const bytes = await readFile(resolve(root, path));
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_FILE_BYTES) {
      fail(`${path} is empty or exceeds the per-file size limit.`);
    }
    totalBytes += bytes.byteLength;
    if (totalBytes > MAX_PACK_BYTES) fail("evidence pack exceeds its total size limit.");
    const text = bytes.toString("utf8");
    if (text.includes("\u0000")) fail(`${path} contains a NUL byte.`);
    for (const credential of CREDENTIAL_PATTERNS) {
      if (credential.pattern.test(text)) {
        fail(`${path} contains a ${credential.name}-shaped value.`);
      }
    }
    assertPublicJudgeEvidenceIdentifiers(text, path);
    files.set(path, { bytes, text });
  }

  for (const path of actualPaths.filter(
    (candidate) =>
      candidate.endsWith(".json") || candidate.endsWith(".sarif")
  )) {
    const parsed = parseJson<unknown>(files.get(path)!.text, path);
    assertNoForbiddenJsonKeys(parsed, path);
  }

  const manifestValue = parseJson<unknown>(
    files.get("manifest.json")!.text,
    "manifest.json"
  );
  assertManifest(manifestValue, input.releaseSha);
  const manifest = manifestValue;
  assertManifestDigest(manifest);
  assertFileDescriptors(manifest, files);
  assertSha256Sums(files);
  assertSemanticChain(files, manifest);

  const replay = await buildJudgeEvidencePack({ releaseSha: input.releaseSha });
  for (const path of JUDGE_EVIDENCE_ALL_PATHS) {
    if (files.get(path)!.text !== replay.files.get(path)) {
      fail(`${path} is not byte-for-byte reproducible from production functions.`);
    }
  }
  return manifest;
}

function parseCliArguments(argv: readonly string[]): {
  input: string;
  releaseSha: string;
} {
  let input: string | undefined;
  let releaseSha: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument !== "--input" && argument !== "--release-sha") {
      throw new Error(`Unsupported argument: ${argument ?? "(missing)"}`);
    }
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${argument} requires a value.`);
    }
    if (argument === "--input") {
      if (input !== undefined) throw new Error("--input may be supplied only once.");
      input = value;
    } else {
      if (releaseSha !== undefined) {
        throw new Error("--release-sha may be supplied only once.");
      }
      releaseSha = value;
    }
    index += 1;
  }
  if (input === undefined || releaseSha === undefined) {
    throw new Error("--input and --release-sha are required.");
  }
  return { input, releaseSha };
}

async function main(): Promise<void> {
  const args = parseCliArguments(process.argv.slice(2));
  assertCiBindings(args.releaseSha, args.input);
  const manifest = await verifyJudgeEvidenceDirectory({
    directory: args.input,
    releaseSha: args.releaseSha,
  });
  console.log(
    `Verified ${JUDGE_EVIDENCE_ALL_PATHS.length} judge evidence files; manifest ${manifest.digest}.`
  );
}

const isMain =
  Boolean(process.argv[1]) &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]!);

if (isMain) {
  main().catch((error: unknown) => {
    console.error((error as Error).message);
    process.exitCode = 1;
  });
}
