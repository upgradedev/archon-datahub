import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve("contrib/datahub-audit");
const requiredFiles = [
  "README.md",
  "SKILL.md",
  "commands/catalog-audit.md",
  "evaluations/audit-governance-coverage.json",
  "evaluations/audit-sensitive-and-lineage.json",
];

for (const relativePath of requiredFiles) {
  const file = resolve(root, relativePath);
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${relativePath} must be a regular, non-symlink file.`);
  }
}

const skill = await readFile(resolve(root, "SKILL.md"), "utf8");
const skillFrontmatter = skill.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
if (!skillFrontmatter) {
  throw new Error("SKILL.md must begin with YAML frontmatter.");
}
for (const contract of [
  /^name:\s*datahub-audit\s*$/m,
  /^user-invocable:\s*true\s*$/m,
  /^allowed-tools:\s*Bash\(datahub \*\)\s*$/m,
]) {
  if (!contract.test(skillFrontmatter[1])) {
    throw new Error(`SKILL.md frontmatter is missing ${contract}.`);
  }
}
if (!skill.includes("read-only") || !skill.includes("never mutate")) {
  throw new Error("SKILL.md must preserve its explicit read-only boundary.");
}

const command = await readFile(resolve(root, "commands/catalog-audit.md"), "utf8");
if (
  !/^---\r?\n[\s\S]*?^name:\s*catalog-audit\s*$[\s\S]*?\r?\n---\r?\n/m.test(
    command
  ) ||
  !command.includes('skill: "datahub-skills:datahub-audit"')
) {
  throw new Error("catalog-audit command is not bound to the datahub-audit skill.");
}

for (const relativePath of requiredFiles.filter((file) => file.endsWith(".json"))) {
  const document = JSON.parse(await readFile(resolve(root, relativePath), "utf8"));
  if (
    !Array.isArray(document.skills) ||
    document.skills.length !== 1 ||
    document.skills[0] !== "datahub-audit" ||
    typeof document.query !== "string" ||
    document.query.trim().length === 0 ||
    !Array.isArray(document.expected_behavior) ||
    document.expected_behavior.length < 5 ||
    document.expected_behavior.some(
      (expectation) =>
        typeof expectation !== "string" || expectation.trim().length === 0
    )
  ) {
    throw new Error(`${relativePath} does not satisfy the evaluation contract.`);
  }
}

const aspectHistoryRoot = resolve("contrib/mcp-get-aspect-history");
const aspectHistoryRequiredFiles = [
  "README.md",
  "manifest.json",
  "integration.patch",
  "scripts/render-validation-receipt.mjs",
  "tests/validation-receipt.test.mjs",
  "upstream/src/mcp_server_datahub/openapi_client.py",
  "upstream/src/mcp_server_datahub/tools/aspect_history.py",
  "upstream/tests/test_mcp/test_get_aspect_history.py",
];

for (const relativePath of aspectHistoryRequiredFiles) {
  const file = resolve(aspectHistoryRoot, relativePath);
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(
      `mcp-get-aspect-history/${relativePath} must be a regular, non-symlink file.`
    );
  }
}

const manifest = JSON.parse(
  await readFile(resolve(aspectHistoryRoot, "manifest.json"), "utf8")
);
const pinnedCommit = "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9";
if (
  manifest.schemaVersion !== 2 ||
  manifest.name !== "get-aspect-history" ||
  manifest.target?.repository !==
    "https://github.com/acryldata/mcp-server-datahub" ||
  manifest.target?.branch !== "main" ||
  manifest.target?.baseCommit !== pinnedCommit ||
  manifest.target?.baseCommitUrl !==
    `https://github.com/acryldata/mcp-server-datahub/commit/${pinnedCommit}` ||
  manifest.target?.license !== "Apache-2.0"
) {
  throw new Error(
    "get-aspect-history manifest does not pin the authoritative upstream target."
  );
}

const expectedArtifacts = new Map([
  [
    "upstream/src/mcp_server_datahub/openapi_client.py",
    "src/mcp_server_datahub/openapi_client.py",
  ],
  [
    "upstream/src/mcp_server_datahub/tools/aspect_history.py",
    "src/mcp_server_datahub/tools/aspect_history.py",
  ],
  [
    "upstream/tests/test_mcp/test_get_aspect_history.py",
    "tests/test_mcp/test_get_aspect_history.py",
  ],
]);
if (
  !Array.isArray(manifest.artifacts) ||
  manifest.artifacts.length !== expectedArtifacts.size ||
  manifest.artifacts.some(
    (artifact) =>
      expectedArtifacts.get(artifact.source) !== artifact.destination ||
      !["source", "test"].includes(artifact.kind)
  ) ||
  manifest.integrationPatch !== "integration.patch"
) {
  throw new Error(
    "get-aspect-history manifest copy map or integration patch is incomplete."
  );
}

if (
  manifest.upstreamInspection?.performedAt !== "2026-07-25" ||
  manifest.upstreamInspection?.method !==
    "read-only GitHub API and official source inspection" ||
  JSON.stringify(manifest.upstreamInspection?.pullRequestStatesInspected) !==
    JSON.stringify(["open", "closed"]) ||
  JSON.stringify(manifest.upstreamInspection?.issueStatesInspected) !==
    JSON.stringify(["open"]) ||
  manifest.upstreamInspection?.codeSearched !== true ||
  manifest.upstreamInspection?.openPullRequestOverlapFound !== false ||
  manifest.upstreamInspection?.closedPullRequestOverlapFound !== false ||
  manifest.upstreamInspection?.issueOverlapFound !== false ||
  manifest.upstreamInspection?.existingSymbolFound !== false ||
  !Array.isArray(manifest.upstreamInspection?.queries) ||
  !manifest.upstreamInspection.queries.includes("get_aspect_history")
) {
  throw new Error(
    "get-aspect-history manifest must preserve the dated, read-only uniqueness inspection."
  );
}

const expectedCiEnvironment = {
  runner: "ubuntu-24.04",
  uvVersion: "0.11.31",
  setupCommand: "uv sync --frozen --all-groups --no-cache",
};
const expectedRequiredCi = [
  {
    id: "candidate-lint",
    kind: "lint",
    scope: "candidate",
    command:
      "uv run --frozen ruff check src/mcp_server_datahub/openapi_client.py src/mcp_server_datahub/tools/aspect_history.py tests/test_mcp/test_get_aspect_history.py",
  },
  {
    id: "candidate-typecheck",
    kind: "typecheck",
    scope: "candidate",
    command:
      "uv run --frozen mypy src/mcp_server_datahub/openapi_client.py src/mcp_server_datahub/tools/aspect_history.py",
  },
  {
    id: "candidate-tests",
    kind: "test",
    scope: "candidate",
    command:
      "uv run --frozen pytest tests/test_mcp/test_get_aspect_history.py --quiet",
  },
  {
    id: "read-only-regression",
    kind: "test",
    scope: "candidate",
    command:
      "uv run --frozen pytest tests/test_mcp/test_read_only.py --quiet",
  },
  {
    id: "repository-format-check",
    kind: "lint",
    scope: "repository",
    command: "uv run --frozen ruff format --check src tests scripts",
  },
  {
    id: "repository-lint",
    kind: "lint",
    scope: "repository",
    command: "uv run --frozen ruff check src tests scripts",
  },
  {
    id: "repository-typecheck",
    kind: "typecheck",
    scope: "repository",
    command: "uv run --frozen mypy src tests scripts",
  },
  {
    id: "repository-test-suite",
    kind: "test",
    scope: "repository",
    command: "uv run --frozen pytest --quiet",
  },
];

const status = manifest.status;
const stagedStatus = {
  state: "staged-not-submitted",
  pullRequestOpened: false,
  appliedToUpstream: false,
  localBuildRun: false,
  localTestsRun: false,
  localSecurityScanRun: false,
};
const openStatusKeys = [
  "appliedToUpstream",
  "headSha",
  "localBuildRun",
  "localSecurityScanRun",
  "localTestsRun",
  "pullRequestNumber",
  "pullRequestOpened",
  "state",
  "url",
];
const mergedStatusKeys = [
  "appliedToUpstream",
  "headSha",
  "localBuildRun",
  "localSecurityScanRun",
  "localTestsRun",
  "mergeCommitSha",
  "mergedAt",
  "pullRequestNumber",
  "pullRequestOpened",
  "state",
  "url",
];
const statusKeys =
  status !== null && typeof status === "object" && !Array.isArray(status)
    ? Object.keys(status).sort()
    : [];
const localExecutionAbsent =
  status?.localBuildRun === false &&
  status?.localTestsRun === false &&
  status?.localSecurityScanRun === false;
const stagedStatusValid =
  JSON.stringify(statusKeys) ===
    JSON.stringify(Object.keys(stagedStatus).sort()) &&
  status?.state === stagedStatus.state &&
  status?.pullRequestOpened === stagedStatus.pullRequestOpened &&
  status?.appliedToUpstream === stagedStatus.appliedToUpstream &&
  localExecutionAbsent;
const openStatusValid =
  JSON.stringify(statusKeys) === JSON.stringify(openStatusKeys) &&
  status?.state === "public-pull-request-open" &&
  status?.pullRequestOpened === true &&
  status?.appliedToUpstream === false &&
  status?.pullRequestNumber === 183 &&
  status?.url === "https://github.com/acryldata/mcp-server-datahub/pull/183" &&
  status?.headSha === "16d53a580001ca02fa0ba96c45f3f58ecfacdd71" &&
  localExecutionAbsent;
const mergedAtPattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const mergedAtMilliseconds =
  typeof status?.mergedAt === "string" && mergedAtPattern.test(status.mergedAt)
    ? Date.parse(status.mergedAt)
    : Number.NaN;
const mergedAtIsCanonical =
  Number.isFinite(mergedAtMilliseconds) &&
  new Date(mergedAtMilliseconds).toISOString().replace(".000Z", "Z") ===
    status.mergedAt;
const mergedStatusValid =
  JSON.stringify(statusKeys) === JSON.stringify(mergedStatusKeys) &&
  status?.state === "merged-upstream" &&
  status?.pullRequestOpened === true &&
  status?.appliedToUpstream === true &&
  Number.isSafeInteger(status?.pullRequestNumber) &&
  status.pullRequestNumber > 0 &&
  status.url ===
    `https://github.com/acryldata/mcp-server-datahub/pull/${status.pullRequestNumber}` &&
  typeof status?.headSha === "string" &&
  /^[0-9a-f]{40}$/.test(status.headSha) &&
  typeof status?.mergeCommitSha === "string" &&
  /^[0-9a-f]{40}$/.test(status.mergeCommitSha) &&
  mergedAtIsCanonical &&
  mergedAtMilliseconds >= Date.parse("2026-07-06T13:00:00Z") &&
  mergedAtMilliseconds <= Date.parse("2026-08-10T21:00:00Z") &&
  localExecutionAbsent;
if (!stagedStatusValid && !openStatusValid && !mergedStatusValid) {
  throw new Error(
    "get-aspect-history manifest must use the exact staged, public-open, or merged-upstream status contract."
  );
}
if (
  JSON.stringify(manifest.ciEnvironment) !==
    JSON.stringify(expectedCiEnvironment) ||
  JSON.stringify(manifest.requiredCi) !== JSON.stringify(expectedRequiredCi) ||
  JSON.stringify(manifest.validationReceipt) !==
    JSON.stringify({
      schemaVersion: "archon.oss-validation-receipt/v1",
      artifactNamePrefix: "oss-validation-receipt-",
      retentionDays: 90,
    })
) {
  throw new Error(
    "get-aspect-history manifest must preserve the exact environment, command list, and receipt contract."
  );
}

const aspectHistorySource = await readFile(
  resolve(
    aspectHistoryRoot,
    "upstream/src/mcp_server_datahub/tools/aspect_history.py"
  ),
  "utf8"
);
for (const contract of [
  "@read_only\n@min_version(cloud=\"0.3.16\", oss=\"1.4.0\")\ndef get_aspect_history(",
  "ASPECT_HISTORY_ALLOWLIST = frozenset(",
  "MAX_ASPECT_HISTORY_LIMIT = 20",
  "MAX_ASPECT_HISTORY_START_VERSION = 1_000_000",
  "MAX_ASPECT_HISTORY_URN_CHARS = 2_048",
  "MAX_ASPECT_HISTORY_URNS = 10",
  "MAX_ASPECT_HISTORY_ASPECTS = 8",
  "MAX_ASPECT_HISTORY_PAIRS = 40",
  "MAX_ASPECT_VALUE_CHARS = 12_000",
  "MAX_ASPECT_HISTORY_RESPONSE_CHARS = 60_000",
  "VersionedOpenApiClient(graph)",
  '"boundedBy"',
  '"truncatedByResponseBudget"',
  '"dataHandling"',
  "untrusted catalog data",
]) {
  if (!aspectHistorySource.includes(contract)) {
    throw new Error(
      `get-aspect-history source is missing required contract: ${contract}`
    );
  }
}

const openApiSource = await readFile(
  resolve(
    aspectHistoryRoot,
    "upstream/src/mcp_server_datahub/openapi_client.py"
  ),
  "utf8"
);
for (const contract of [
  "class VersionedOpenApiClient:",
  '"If-Version-Match"',
  'f"{entity_name}/batchGet"',
  "self._graph._session.post(",
  'params={"systemMetadata": str(with_system_metadata).lower()}',
  "response.raise_for_status()",
]) {
  if (!openApiSource.includes(contract)) {
    throw new Error(
      `version-aware OpenAPI seam is missing required contract: ${contract}`
    );
  }
}

for (const aspectName of [
  "datasetProperties",
  "deprecation",
  "domains",
  "editableDatasetProperties",
  "editableSchemaMetadata",
  "globalTags",
  "glossaryTerms",
  "ownership",
  "schemaMetadata",
  "status",
  "structuredProperties",
  "upstreamLineage",
]) {
  if (!aspectHistorySource.includes(`"${aspectName}"`)) {
    throw new Error(
      `get-aspect-history governance allowlist is missing ${aspectName}.`
    );
  }
}

for (const forbiddenMutation of [
  "._session.delete(",
  "._session.patch(",
  "._session.put(",
  ".emit(",
  ".ingest(",
]) {
  if (aspectHistorySource.includes(forbiddenMutation)) {
    throw new Error(
      `get-aspect-history source contains forbidden mutation surface: ${forbiddenMutation}`
    );
  }
}

const integrationPatch = await readFile(
  resolve(aspectHistoryRoot, "integration.patch"),
  "utf8"
);
const patchedFiles = [
  ...integrationPatch.matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gm),
].map((match) => [match[1], match[2]]);
const expectedPatchedFiles = [
  [
    "src/mcp_server_datahub/mcp_server.py",
    "src/mcp_server_datahub/mcp_server.py",
  ],
  [
    "src/mcp_server_datahub/tools/__init__.py",
    "src/mcp_server_datahub/tools/__init__.py",
  ],
];
if (
  JSON.stringify(patchedFiles) !== JSON.stringify(expectedPatchedFiles) ||
  !integrationPatch.includes(
    "from .tools.aspect_history import get_aspect_history"
  ) ||
  !integrationPatch.includes('        "get_aspect_history",') ||
  !integrationPatch.includes("        get_aspect_history,") ||
  !integrationPatch.includes("        tags={ToolType.SEARCH.value},") ||
  !integrationPatch.includes(
    "from .aspect_history import get_aspect_history"
  ) ||
  !integrationPatch.includes('    "get_aspect_history",')
) {
  throw new Error(
    "get-aspect-history integration patch does not export and register only the intended tool."
  );
}

const aspectHistoryTests = await readFile(
  resolve(
    aspectHistoryRoot,
    "upstream/tests/test_mcp/test_get_aspect_history.py"
  ),
  "utf8"
);
const testCount = (aspectHistoryTests.match(/^def test_/gm) || []).length;
for (const testContract of [
  "test_is_read_only_and_version_gated",
  "test_cross_product_batches_pairs_once_per_version_and_orders_results",
  "test_accepts_single_or_json_stringified_lists",
  "test_limit_and_start_version_are_per_pair_with_honest_lookahead",
  "test_pair_local_validation_and_missing_entity_do_not_abort_batch",
  "test_transport_failure_is_pair_local_across_entity_types",
  "test_provenance_is_allowlisted_and_values_are_bounded",
  "test_oversized_value_returns_preview_instead_of_raw_value",
  "test_global_budget_reports_dropped_pairs",
  "test_rejects_unbounded_or_ambiguous_arguments",
  "test_response_explains_retention_and_untrusted_data",
  "test_404_at_versioned_seam_is_stable_pair_error",
]) {
  if (!aspectHistoryTests.includes(testContract)) {
    throw new Error(
      `get-aspect-history tests are missing required coverage: ${testContract}`
    );
  }
}
if (testCount < 11) {
  throw new Error(
    `get-aspect-history must stage at least 11 focused tests; found ${testCount}.`
  );
}

const aspectHistoryReadme = await readFile(
  resolve(aspectHistoryRoot, "README.md"),
  "utf8"
);
const normalizedAspectHistoryReadme = aspectHistoryReadme.replace(/\s+/gu, " ");
for (const documentationContract of [
  pinnedCommit,
  "Security and hard bounds",
  "Provenance contract",
  "Exact upstream CI contract",
  "Deterministic CI validation receipt",
  "ossContributionValidationArtifactDigest",
  "90 days",
  "does not depend on Codex Security",
]) {
  if (!normalizedAspectHistoryReadme.includes(documentationContract)) {
    throw new Error(
      `get-aspect-history README is missing honest documentation: ${documentationContract}`
    );
  }
}
const stagedReadmeStatus =
  "**Staged, not submitted.** No pull request was opened, the patch was not applied to upstream, and no local build, test suite, or security scan was run.";
const mergedReadmeStatus =
  `**Merged upstream.** Pull request [#${status.pullRequestNumber}](${status.url}) ` +
  `was merged by an independent upstream maintainer at \`${status.mergedAt}\`. ` +
  `Head commit: \`${status.headSha}\`. Merge commit: \`${status.mergeCommitSha}\`. ` +
  "No local build, test suite, or security scan was run; all validation and security evidence was produced by CI/CD.";
const openReadmeStatus =
  `**Public pull request open.** Pull request [#${status.pullRequestNumber}](${status.url}) ` +
  `contains head commit \`${status.headSha}\` and is not merged. ` +
  "No accepted-contribution bonus is claimed. No local build, test suite, or security scan was run; all validation and security evidence is produced by CI/CD.";
const stagedReadmeStatusValid =
  normalizedAspectHistoryReadme.includes(stagedReadmeStatus) &&
  !normalizedAspectHistoryReadme.includes("**Merged upstream.**");
const mergedReadmeStatusValid =
  normalizedAspectHistoryReadme.includes(mergedReadmeStatus) &&
  !normalizedAspectHistoryReadme.includes("**Staged, not submitted.**") &&
  !normalizedAspectHistoryReadme.includes("No pull request was opened");
const openReadmeStatusValid =
  normalizedAspectHistoryReadme.includes(openReadmeStatus) &&
  !normalizedAspectHistoryReadme.includes("**Staged, not submitted.**") &&
  !normalizedAspectHistoryReadme.includes("**Merged upstream.**");
if (stagedStatusValid && !stagedReadmeStatusValid) {
  throw new Error(
    "get-aspect-history README must preserve the exact truthful staged status."
  );
}
if (mergedStatusValid && !mergedReadmeStatusValid) {
  throw new Error(
    "get-aspect-history README must record the exact truthful merged status."
  );
}
if (openStatusValid && !openReadmeStatusValid) {
  throw new Error(
    "get-aspect-history README must record the exact truthful public-open status."
  );
}
for (const { command } of expectedRequiredCi) {
  if (!aspectHistoryReadme.includes(command)) {
    throw new Error(
      `get-aspect-history README is missing exact required CI command: ${command}`
    );
  }
}

const receiptRenderer = await readFile(
  resolve(
    aspectHistoryRoot,
    "scripts/render-validation-receipt.mjs"
  ),
  "utf8"
);
for (const receiptContract of [
  "archon.oss-validation-receipt/v1",
  "credentialsIncluded: false",
  "git-diff-binary-full-index",
  "pullRequestHeadSha must equal sourceHeadSha",
  'result: "pass"',
]) {
  if (!receiptRenderer.includes(receiptContract)) {
    throw new Error(
      `validation receipt renderer is missing contract: ${receiptContract}`
    );
  }
}

console.log("DataHub contribution contracts verified.");
