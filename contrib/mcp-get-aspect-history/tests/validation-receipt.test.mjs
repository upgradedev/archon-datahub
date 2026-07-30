import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildValidationReceipt,
  serializeValidationReceipt,
} from "../scripts/render-validation-receipt.mjs";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const contributionRoot = resolve(testDirectory, "..");
const repositoryRoot = resolve(contributionRoot, "../..");
const manifestPath = resolve(contributionRoot, "manifest.json");
const sourceHeadSha = "a".repeat(40);

const expectedCommands = [
  {
    command:
      "uv run --frozen ruff check src/mcp_server_datahub/tools/aspect_history.py tests/test_mcp/test_get_aspect_history.py",
    id: "candidate-lint",
    kind: "lint",
    scope: "candidate",
  },
  {
    command:
      "uv run --frozen mypy src/mcp_server_datahub/tools/aspect_history.py",
    id: "candidate-typecheck",
    kind: "typecheck",
    scope: "candidate",
  },
  {
    command:
      "uv run --frozen pytest tests/test_mcp/test_get_aspect_history.py --quiet",
    id: "candidate-tests",
    kind: "test",
    scope: "candidate",
  },
  {
    command:
      "uv run --frozen pytest tests/test_mcp/test_read_only.py --quiet",
    id: "read-only-regression",
    kind: "test",
    scope: "candidate",
  },
  {
    command: "uv run --frozen ruff format --check src tests scripts",
    id: "repository-format-check",
    kind: "lint",
    scope: "repository",
  },
  {
    command: "uv run --frozen ruff check src tests scripts",
    id: "repository-lint",
    kind: "lint",
    scope: "repository",
  },
  {
    command: "uv run --frozen mypy src tests scripts",
    id: "repository-typecheck",
    kind: "typecheck",
    scope: "repository",
  },
  {
    command: "uv run --frozen pytest --quiet",
    id: "repository-test-suite",
    kind: "test",
    scope: "repository",
  },
];

test("validation receipt is canonical, deterministic, and source-bound", async (t) => {
  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "archon-oss-receipt-test-")
  );
  t.after(async () => {
    await rm(temporaryDirectory, { force: true, recursive: true });
  });
  const appliedDiffPath = resolve(temporaryDirectory, "applied.diff");
  const appliedDiff = [
    "diff --git a/example.py b/example.py",
    "index 0000000..1111111 100644",
    "--- a/example.py",
    "+++ b/example.py",
    "@@ -0,0 +1 @@",
    "+example = True",
    "",
  ].join("\n");
  await writeFile(appliedDiffPath, appliedDiff, "utf8");

  const input = {
    appliedDiffPath,
    eventName: "pull_request",
    manifestPath,
    pullRequestHeadSha: sourceHeadSha,
    sourceHeadSha,
    sourceRepository: "upgradedev/archon-datahub",
  };
  const first = await buildValidationReceipt(input);
  const second = await buildValidationReceipt(input);

  assert.deepEqual(first, second);
  assert.equal(
    serializeValidationReceipt(first),
    serializeValidationReceipt(second)
  );
  assert.equal(first.schemaVersion, "archon.oss-validation-receipt/v1");
  assert.deepEqual(first.source, {
    eventName: "pull_request",
    headSha: sourceHeadSha,
    pullRequestHeadSha: sourceHeadSha,
    repository: "upgradedev/archon-datahub",
  });
  assert.equal(first.target.baseCommit, "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9");
  assert.equal(first.candidate.files.length, 2);
  assert.equal(
    first.candidate.appliedDiff.sha256,
    createHash("sha256").update(appliedDiff).digest("hex")
  );
  assert.deepEqual(
    first.validation.commands,
    expectedCommands.map((command) => ({ ...command, result: "pass" }))
  );
  assert.deepEqual(first.dataHandling, {
    credentialsIncluded: false,
    payload: "public source metadata, digests, commands, and pass results only",
  });
  assert.equal(first.validation.result, "pass");
});

test("pull-request receipt rejects a head SHA mismatch", async (t) => {
  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "archon-oss-receipt-mismatch-")
  );
  t.after(async () => {
    await rm(temporaryDirectory, { force: true, recursive: true });
  });
  const appliedDiffPath = resolve(temporaryDirectory, "applied.diff");
  await writeFile(appliedDiffPath, "non-empty deterministic diff\n", "utf8");

  await assert.rejects(
    buildValidationReceipt({
      appliedDiffPath,
      eventName: "pull_request",
      manifestPath,
      pullRequestHeadSha: "b".repeat(40),
      sourceHeadSha,
      sourceRepository: "upgradedev/archon-datahub",
    }),
    /pullRequestHeadSha must equal sourceHeadSha/
  );
});

test("CI binds, exercises, seals, and retains the receipt contract", async () => {
  const workflow = await readFile(
    resolve(repositoryRoot, ".github/workflows/ci.yml"),
    "utf8"
  );
  const contributionStart = workflow.indexOf("\n  contrib:");
  const contributionEnd = workflow.indexOf("\n  security:", contributionStart);
  assert.ok(contributionStart > 0 && contributionEnd > contributionStart);
  const contributionJob = workflow.slice(contributionStart, contributionEnd);

  for (const contract of [
    "runs-on: ubuntu-24.04",
    "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
    "persist-credentials: false",
    'version: "0.11.31"',
    '"uv sync --frozen --all-groups --no-cache"',
    "node --test contrib/mcp-get-aspect-history/tests/validation-receipt.test.mjs",
    "jq -er '.requiredCi[] | [.id, .command] | @tsv'",
    "render-validation-receipt.mjs",
    "sha256sum --check --strict SHA256SUMS",
    "name: oss-validation-receipt-${{ steps.source.outputs.head_sha }}",
    "retention-days: 90",
  ]) {
    assert.ok(
      contributionJob.includes(contract),
      `contribution job is missing ${contract}`
    );
  }
  assert.ok(!contributionJob.includes("secrets."));
  assert.ok(!contributionJob.includes("continue-on-error"));
  assert.ok(
    contributionJob.indexOf("Run every manifest-declared upstream command") <
      contributionJob.indexOf("Seal the source-bound OSS validation receipt")
  );
  assert.ok(
    contributionJob.indexOf("Seal the source-bound OSS validation receipt") <
      contributionJob.indexOf("Upload immutable OSS validation receipt")
  );
  assert.ok(
    workflow.includes(
      "CONTRIB_ARTIFACT_DIGEST: ${{ needs.contrib.outputs.validation_receipt_digest }}"
    )
  );
  assert.ok(
    workflow.includes("ossContributionValidationArtifactDigest:")
  );
});
