import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const RECEIPT_SCHEMA = "archon.oss-validation-receipt/v1";
const VALID_EVENTS = new Set(["pull_request", "push"]);
const VALID_COMMAND_KINDS = new Set(["lint", "test", "typecheck"]);
const VALID_COMMAND_SCOPES = new Set(["candidate", "repository"]);

function fail(message) {
  throw new Error(message);
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string.`);
  }
  if (/[\0\r\n]/u.test(value)) {
    fail(`${label} must be a single line without NUL bytes.`);
  }
  return value;
}

function requireSha(value, label) {
  const sha = requireString(value, label);
  if (!SHA_PATTERN.test(sha)) {
    fail(`${label} must be a lowercase 40-character Git SHA.`);
  }
  return sha;
}

function requireRepository(value, label) {
  const repository = requireString(value, label);
  if (!REPOSITORY_PATTERN.test(repository)) {
    fail(`${label} must be an owner/repository identifier.`);
  }
  return repository;
}

function resolveManifestPath(root, value, label) {
  const manifestPath = requireString(value, label);
  if (isAbsolute(manifestPath) || manifestPath.includes("\\")) {
    fail(`${label} must be a portable path relative to the contribution root.`);
  }
  const absolutePath = resolve(root, manifestPath);
  const relativePath = relative(root, absolutePath);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(relativePath)
  ) {
    fail(`${label} must stay inside the contribution root.`);
  }
  return absolutePath;
}

async function readRegularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(`${label} must be a regular, non-symlink file.`);
  }
  return readFile(path);
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function serializeValidationReceipt(receipt) {
  return `${JSON.stringify(canonicalize(receipt), null, 2)}\n`;
}

function validateCommands(requiredCi) {
  if (!Array.isArray(requiredCi) || requiredCi.length === 0) {
    fail("manifest.requiredCi must be a non-empty array.");
  }
  const ids = new Set();
  return requiredCi.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      fail(`manifest.requiredCi[${index}] must be an object.`);
    }
    const id = requireString(entry.id, `manifest.requiredCi[${index}].id`);
    const kind = requireString(
      entry.kind,
      `manifest.requiredCi[${index}].kind`
    );
    const scope = requireString(
      entry.scope,
      `manifest.requiredCi[${index}].scope`
    );
    const command = requireString(
      entry.command,
      `manifest.requiredCi[${index}].command`
    );
    if (ids.has(id)) {
      fail(`manifest.requiredCi contains duplicate command id ${id}.`);
    }
    if (!VALID_COMMAND_KINDS.has(kind)) {
      fail(`manifest.requiredCi command ${id} has unsupported kind ${kind}.`);
    }
    if (!VALID_COMMAND_SCOPES.has(scope)) {
      fail(`manifest.requiredCi command ${id} has unsupported scope ${scope}.`);
    }
    ids.add(id);
    return { command, id, kind, scope };
  });
}

function validateEnvironment(environment) {
  if (
    environment === null ||
    typeof environment !== "object" ||
    Array.isArray(environment)
  ) {
    fail("manifest.ciEnvironment must be an object.");
  }
  return {
    runner: requireString(environment.runner, "manifest.ciEnvironment.runner"),
    setupCommand: requireString(
      environment.setupCommand,
      "manifest.ciEnvironment.setupCommand"
    ),
    uvVersion: requireString(
      environment.uvVersion,
      "manifest.ciEnvironment.uvVersion"
    ),
  };
}

export async function buildValidationReceipt({
  appliedDiffPath,
  eventName,
  manifestPath,
  pullRequestHeadSha = "",
  sourceHeadSha,
  sourceRepository,
}) {
  const manifestBytes = await readRegularFile(manifestPath, "manifest");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (manifest.schemaVersion !== 2) {
    fail("manifest.schemaVersion must be 2.");
  }
  if (
    manifest.validationReceipt?.schemaVersion !== RECEIPT_SCHEMA ||
    manifest.validationReceipt?.artifactNamePrefix !==
      "oss-validation-receipt-" ||
    manifest.validationReceipt?.retentionDays !== 90
  ) {
    fail("manifest.validationReceipt does not match the sealed receipt contract.");
  }

  const normalizedEvent = requireString(eventName, "eventName");
  if (!VALID_EVENTS.has(normalizedEvent)) {
    fail(`eventName ${normalizedEvent} is not supported.`);
  }
  const normalizedHeadSha = requireSha(sourceHeadSha, "sourceHeadSha");
  const normalizedPullRequestHeadSha =
    pullRequestHeadSha === ""
      ? null
      : requireSha(pullRequestHeadSha, "pullRequestHeadSha");
  if (
    normalizedEvent === "pull_request" &&
    normalizedPullRequestHeadSha !== normalizedHeadSha
  ) {
    fail("pullRequestHeadSha must equal sourceHeadSha for pull_request receipts.");
  }
  if (normalizedEvent === "push" && normalizedPullRequestHeadSha !== null) {
    fail("push receipts must not claim a pullRequestHeadSha.");
  }

  const manifestRoot = dirname(resolve(manifestPath));
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
    fail("manifest.artifacts must be a non-empty array.");
  }
  const candidateFiles = [];
  for (const [index, artifact] of manifest.artifacts.entries()) {
    if (
      artifact === null ||
      typeof artifact !== "object" ||
      Array.isArray(artifact)
    ) {
      fail(`manifest.artifacts[${index}] must be an object.`);
    }
    const source = requireString(
      artifact.source,
      `manifest.artifacts[${index}].source`
    );
    const destination = requireString(
      artifact.destination,
      `manifest.artifacts[${index}].destination`
    );
    const kind = requireString(
      artifact.kind,
      `manifest.artifacts[${index}].kind`
    );
    const content = await readRegularFile(
      resolveManifestPath(
        manifestRoot,
        source,
        `manifest.artifacts[${index}].source`
      ),
      `candidate file ${source}`
    );
    candidateFiles.push({
      destination,
      kind,
      path: source,
      sha256: sha256(content),
    });
  }

  const integrationPatch = requireString(
    manifest.integrationPatch,
    "manifest.integrationPatch"
  );
  const integrationPatchBytes = await readRegularFile(
    resolveManifestPath(
      manifestRoot,
      integrationPatch,
      "manifest.integrationPatch"
    ),
    "integration patch"
  );
  const appliedDiffBytes = await readRegularFile(
    appliedDiffPath,
    "applied diff"
  );
  if (appliedDiffBytes.length === 0) {
    fail("applied diff must not be empty.");
  }

  const commands = validateCommands(manifest.requiredCi).map((entry) => ({
    ...entry,
    result: "pass",
  }));
  const environment = validateEnvironment(manifest.ciEnvironment);

  return {
    candidate: {
      appliedDiff: {
        format: "git-diff-binary-full-index",
        path: "applied.diff",
        sha256: sha256(appliedDiffBytes),
      },
      files: candidateFiles,
      integrationPatch: {
        path: integrationPatch,
        sha256: sha256(integrationPatchBytes),
      },
      manifest: {
        path: "manifest.json",
        sha256: sha256(manifestBytes),
      },
      name: requireString(manifest.name, "manifest.name"),
    },
    dataHandling: {
      credentialsIncluded: false,
      payload: "public source metadata, digests, commands, and pass results only",
    },
    schemaVersion: RECEIPT_SCHEMA,
    source: {
      eventName: normalizedEvent,
      headSha: normalizedHeadSha,
      pullRequestHeadSha: normalizedPullRequestHeadSha,
      repository: requireRepository(sourceRepository, "sourceRepository"),
    },
    target: {
      baseCommit: requireSha(
        manifest.target?.baseCommit,
        "manifest.target.baseCommit"
      ),
      baseCommitUrl: requireString(
        manifest.target?.baseCommitUrl,
        "manifest.target.baseCommitUrl"
      ),
      branch: requireString(manifest.target?.branch, "manifest.target.branch"),
      license: requireString(
        manifest.target?.license,
        "manifest.target.license"
      ),
      repository: requireString(
        manifest.target?.repository,
        "manifest.target.repository"
      ),
    },
    validation: {
      commands,
      environment: {
        ...environment,
        setupResult: "pass",
      },
      result: "pass",
    },
  };
}

function parseArguments(argv) {
  const allowed = new Set([
    "applied-diff",
    "event-name",
    "manifest",
    "output",
    "pull-request-head-sha",
    "source-head-sha",
    "source-repository",
  ]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (
      typeof option !== "string" ||
      !option.startsWith("--") ||
      value === undefined
    ) {
      fail("receipt renderer arguments must be --name value pairs.");
    }
    const name = option.slice(2);
    if (!allowed.has(name) || values.has(name)) {
      fail(`unsupported or duplicate receipt renderer option: ${option}`);
    }
    values.set(name, value);
  }
  for (const required of [
    "applied-diff",
    "event-name",
    "manifest",
    "output",
    "pull-request-head-sha",
    "source-head-sha",
    "source-repository",
  ]) {
    if (!values.has(required)) {
      fail(`missing receipt renderer option: --${required}`);
    }
  }
  return values;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const receipt = await buildValidationReceipt({
    appliedDiffPath: resolve(args.get("applied-diff")),
    eventName: args.get("event-name"),
    manifestPath: resolve(args.get("manifest")),
    pullRequestHeadSha: args.get("pull-request-head-sha"),
    sourceHeadSha: args.get("source-head-sha"),
    sourceRepository: args.get("source-repository"),
  });
  await writeFile(
    resolve(args.get("output")),
    serializeValidationReceipt(receipt),
    {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    }
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
