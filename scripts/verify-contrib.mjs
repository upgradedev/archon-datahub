import { readFile, stat } from "node:fs/promises";
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
  const metadata = await stat(file);
  if (!metadata.isFile()) {
    throw new Error(`${relativePath} must be a regular file.`);
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
  "upstream/src/mcp_server_datahub/tools/aspect_history.py",
  "upstream/tests/test_mcp/test_get_aspect_history.py",
];

for (const relativePath of aspectHistoryRequiredFiles) {
  const file = resolve(aspectHistoryRoot, relativePath);
  const metadata = await stat(file);
  if (!metadata.isFile()) {
    throw new Error(
      `mcp-get-aspect-history/${relativePath} must be a regular file.`
    );
  }
}

const manifest = JSON.parse(
  await readFile(resolve(aspectHistoryRoot, "manifest.json"), "utf8")
);
const pinnedCommit = "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9";
if (
  manifest.schemaVersion !== 1 ||
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

if (
  manifest.status?.state !== "staged-not-submitted" ||
  manifest.status?.pullRequestOpened !== false ||
  manifest.status?.appliedToUpstream !== false ||
  manifest.status?.localBuildRun !== false ||
  manifest.status?.localTestsRun !== false ||
  manifest.status?.localSecurityScanRun !== false ||
  !Array.isArray(manifest.requiredCi) ||
  manifest.requiredCi.length < 4
) {
  throw new Error(
    "get-aspect-history manifest must report its honest staged and CI-required status."
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
  "@read_only\ndef get_aspect_history(",
  "ASPECT_HISTORY_ALLOWLIST = frozenset(",
  "MAX_ASPECT_HISTORY_LIMIT = 20",
  "MAX_ASPECT_HISTORY_START_VERSION = 1_000_000",
  "MAX_ASPECT_HISTORY_URN_CHARS = 2_048",
  "MAX_ASPECT_VALUE_CHARS = 12_000",
  "MAX_ASPECT_HISTORY_RESPONSE_CHARS = 60_000",
  '"If-Version-Match"',
  '"?systemMetadata=true"',
  "response.raise_for_status()",
  "if body == []:",
  "graph.exists(normalized_urn)",
  '"truncatedByResponseBudget"',
  '"systemMetadataFields"',
  '"auditStampFields"',
  '"dataHandling"',
  "untrusted catalog data",
]) {
  if (!aspectHistorySource.includes(contract)) {
    throw new Error(
      `get-aspect-history source is missing required contract: ${contract}`
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
    "src/mcp_server_datahub/tools/__init__.py",
    "src/mcp_server_datahub/tools/__init__.py",
  ],
  [
    "src/mcp_server_datahub/mcp_server.py",
    "src/mcp_server_datahub/mcp_server.py",
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
  "test_is_marked_read_only",
  "test_returns_current_history_pagination_and_bounded_provenance",
  "test_lookahead_produces_honest_next_start_version",
  "test_rejects_unbounded_or_ambiguous_arguments",
  "test_rejects_aspects_outside_governance_allowlist",
  "test_http_and_authorization_errors_are_not_silenced",
  "test_missing_openapi_capability_fails_explicitly",
  "test_malformed_success_responses_fail_closed",
  "test_oversized_single_value_becomes_an_explicit_preview",
  "test_total_response_budget_stops_with_resumable_cursor",
]) {
  if (!aspectHistoryTests.includes(testContract)) {
    throw new Error(
      `get-aspect-history tests are missing required coverage: ${testContract}`
    );
  }
}
if (testCount < 12) {
  throw new Error(
    `get-aspect-history must stage at least 12 focused tests; found ${testCount}.`
  );
}

const aspectHistoryReadme = await readFile(
  resolve(aspectHistoryRoot, "README.md"),
  "utf8"
);
for (const documentationContract of [
  pinnedCommit,
  "Staged, not submitted",
  "no local build, test suite, or security scan was run",
  "Security and hard bounds",
  "Provenance contract",
  "Required upstream CI commands",
  "does not depend on Codex Security",
]) {
  if (!aspectHistoryReadme.includes(documentationContract)) {
    throw new Error(
      `get-aspect-history README is missing honest documentation: ${documentationContract}`
    );
  }
}

console.log("DataHub contribution contracts verified.");
