import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { DirectGmsTagProjectionReader } from "../src/datahub/tag-projection-reader-live.js";
import { LiveDataHubMutationClient } from "../src/datahub/mutation-client-live.js";
import type { DataHubMutationClient } from "../src/datahub/mutation-client.js";
import type { TagProjection, TagProjectionReader } from "../src/remediation/contracts.js";

const RECOVERY_SCHEMA = "archon.governed-canary-recovery/v4" as const;
const EVIDENCE_SCHEMA = "archon.governed-canary-recovery-evidence/v2" as const;
const ENDPOINT_SCHEMA = "archon.datahub-cloud-endpoint-binding/v1" as const;
const CANONICAL_DATASET_URN =
  "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)";
const CANONICAL_COLUMN_PATH = "customer_email";
const PII_TAG_URN = "urn:li:tag:PII";
const CLOUD_STACK = "Archon-staging-Judge";
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const RELEASE_SHA = /^[a-f0-9]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RUN_ATTEMPT = /^[1-9][0-9]{0,9}$/u;
const DNS_MARKER = /^[a-z0-9][a-z0-9-]{6,61}[a-z0-9]$/u;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type RecordValue = Record<string, unknown>;

export interface EndpointBinding {
  readonly schemaVersion: typeof ENDPOINT_SCHEMA;
  readonly isolationMarker: string;
  readonly readGmsUrl: string;
  readonly readMcpUrl: string;
  readonly writeGmsUrl: string;
  readonly writeMcpUrl: string;
}

export interface RecoveryManifest {
  readonly schemaVersion: typeof RECOVERY_SCHEMA;
  readonly repository: string;
  readonly sourceWorkflow: {
    readonly runId: string;
    readonly runAttempt: string;
    readonly controlPlaneSha: string;
    readonly controlPlaneGatesSha256: string;
  };
  readonly deployment: {
    readonly runId: string;
    readonly artifactId: string;
    readonly artifactDigest: string;
    readonly evidenceSha256: string;
    readonly observationSha256: string;
    readonly applicationUrl: string;
  };
  readonly runtime: {
    readonly profileId: "cloud";
    readonly resolution: "explicit";
    readonly stackName: typeof CLOUD_STACK;
    readonly cloudImageDigest: string;
  };
  readonly target: {
    readonly entityUrn: typeof CANONICAL_DATASET_URN;
    readonly columnPath: typeof CANONICAL_COLUMN_PATH;
    readonly tagUrn: typeof PII_TAG_URN;
  };
  readonly endpointBindingSha256: string;
  readonly preparedAt: string;
  readonly digest: string;
}

export interface RecoveryEvidence {
  readonly schemaVersion: typeof EVIDENCE_SCHEMA;
  readonly recoveryDigest: string;
  readonly sourceWorkflow: RecoveryManifest["sourceWorkflow"];
  readonly deploymentEvidenceSha256: string;
  readonly runtimeProfile: "cloud";
  readonly target: RecoveryManifest["target"];
  readonly endpointBindingSha256: string;
  readonly beforeDigest: string;
  readonly afterDigest: string;
  readonly mutation:
    | { readonly performed: false }
    | {
        readonly performed: true;
        readonly requestDigest: string;
        readonly responseDigest: string;
      };
  readonly disposition: "already-baseline" | "restored";
  readonly recoveredAt: string;
  readonly digest: string;
}

function fail(message: string): never {
  throw new Error(`Governed canary rejected the operation: ${message}`);
}

function record(value: unknown, label: string): RecordValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  return value as RecordValue;
}

function exactKeys(value: RecordValue, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index]);
}

function required(
  source: NodeJS.ProcessEnv | Record<string, string | undefined>,
  name: string,
  maximum = 4096
): string {
  const value = source[name]?.trim();
  if (!value || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail(`${name} is required and must be bounded.`);
  }
  return value;
}

function instant(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

export function canonicalize(value: Json): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("canonical JSON contains a non-finite number.");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalize(value[key]!)}`).join(",")}}`;
}

export async function sha256(value: string): Promise<string> {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

export async function digest(value: Json): Promise<string> {
  return sha256(canonicalize(value));
}

function exactHttpsUrl(value: string, label: string, rootOnly = false): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} is not a URL.`);
  }
  if (
    parsed.protocol !== "https:" || parsed.username || parsed.password ||
    parsed.hash || (rootOnly && (parsed.pathname !== "/" || parsed.search))
  ) {
    fail(`${label} must be an exact HTTPS ${rootOnly ? "origin" : "URL"}.`);
  }
  const normalized = rootOnly ? parsed.origin : parsed.toString().replace(/\/$/u, "");
  return normalized;
}

export async function endpointBinding(
  source: NodeJS.ProcessEnv | Record<string, string | undefined>
): Promise<{ binding: EndpointBinding; digest: string }> {
  const isolationMarker = required(source, "CANARY_ISOLATION_MARKER", 63).toLowerCase();
  if (!DNS_MARKER.test(isolationMarker)) {
    fail("CANARY_ISOLATION_MARKER is invalid.");
  }
  const binding: EndpointBinding = {
    schemaVersion: ENDPOINT_SCHEMA,
    isolationMarker,
    readGmsUrl: exactHttpsUrl(required(source, "CANARY_DATAHUB_READ_GMS_URL"), "read GMS URL"),
    readMcpUrl: exactHttpsUrl(required(source, "CANARY_DATAHUB_READ_MCP_URL"), "read MCP URL"),
    writeGmsUrl: exactHttpsUrl(required(source, "CANARY_DATAHUB_WRITE_GMS_URL"), "write GMS URL"),
    writeMcpUrl: exactHttpsUrl(required(source, "CANARY_DATAHUB_WRITE_MCP_URL"), "write MCP URL"),
  };
  for (const [name, value] of Object.entries(binding).filter(([name]) => name.endsWith("Url"))) {
    if (!new URL(String(value)).hostname.toLowerCase().split(".").includes(isolationMarker)) {
      fail(`${name} is outside the isolated DataHub Cloud tenant.`);
    }
  }
  if (
    new URL(binding.readGmsUrl).origin !== new URL(binding.writeGmsUrl).origin ||
    new URL(binding.readMcpUrl).origin !== new URL(binding.writeMcpUrl).origin ||
    new URL(binding.readGmsUrl).origin !== new URL(binding.readMcpUrl).origin
  ) {
    fail("all canary endpoints must bind one isolated DataHub Cloud tenant.");
  }
  return { binding, digest: await digest(binding as unknown as Json) };
}

function digestField(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(`${label} is invalid.`);
  return value;
}

function runId(value: unknown, label: string, attempt = false): string {
  if (typeof value !== "string" || !(attempt ? RUN_ATTEMPT : RUN_ID).test(value)) {
    fail(`${label} is invalid.`);
  }
  return value;
}

export async function sealRecoveryManifest(
  source: NodeJS.ProcessEnv | Record<string, string | undefined>,
  preparedAt = new Date().toISOString()
): Promise<RecoveryManifest> {
  const endpoints = await endpointBinding(source);
  const releaseSha = required(source, "CANARY_RELEASE_SHA", 40);
  const controlPlaneSha = required(source, "GITHUB_SHA", 40);
  if (!RELEASE_SHA.test(releaseSha) || !RELEASE_SHA.test(controlPlaneSha)) {
    fail("release and control-plane SHAs must be full lowercase commit SHAs.");
  }
  const applicationUrl = exactHttpsUrl(
    required(source, "CANARY_APPLICATION_URL"), "application URL", true
  );
  const stackName = required(source, "CANARY_STACK_NAME", 128);
  if (stackName !== CLOUD_STACK) fail("the governed canary may target only Archon-staging-Judge.");
  if (!instant(preparedAt)) fail("preparedAt is invalid.");
  const unsigned = {
    schemaVersion: RECOVERY_SCHEMA,
    repository: required(source, "GITHUB_REPOSITORY", 256),
    sourceWorkflow: {
      runId: runId(required(source, "CANARY_SOURCE_WORKFLOW_RUN_ID", 20), "source run ID"),
      runAttempt: runId(required(source, "CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT", 10), "source run attempt", true),
      controlPlaneSha,
      controlPlaneGatesSha256: digestField(
        required(source, "CANARY_CONTROL_PLANE_GATES_SHA256", 71),
        "control-plane gate digest"
      ),
    },
    deployment: {
      runId: runId(required(source, "CANARY_DEPLOYMENT_RUN_ID", 20), "deployment run ID"),
      artifactId: runId(required(source, "CANARY_DEPLOYMENT_ARTIFACT_ID", 20), "deployment artifact ID"),
      artifactDigest: digestField(required(source, "CANARY_DEPLOYMENT_ARTIFACT_DIGEST", 71), "artifact digest"),
      evidenceSha256: digestField(required(source, "CANARY_DEPLOYMENT_EVIDENCE_SHA256", 71), "deployment evidence digest"),
      observationSha256: digestField(required(source, "CANARY_OBSERVATION_SHA256", 71), "runtime observation digest"),
      applicationUrl,
    },
    runtime: {
      profileId: "cloud" as const,
      resolution: "explicit" as const,
      stackName: CLOUD_STACK as typeof CLOUD_STACK,
      cloudImageDigest: digestField(required(source, "CANARY_CLOUD_IMAGE_DIGEST", 71), "Cloud image digest"),
    },
    target: {
      entityUrn: CANONICAL_DATASET_URN,
      columnPath: CANONICAL_COLUMN_PATH,
      tagUrn: PII_TAG_URN,
    },
    endpointBindingSha256: endpoints.digest,
    preparedAt,
  };
  return { ...unsigned, digest: await digest(unsigned as unknown as Json) };
}

export async function parseRecoveryManifest(value: unknown): Promise<RecoveryManifest> {
  const manifest = record(value, "recovery manifest");
  if (!exactKeys(manifest, [
    "schemaVersion", "repository", "sourceWorkflow", "deployment", "runtime",
    "target", "endpointBindingSha256", "preparedAt", "digest"
  ]) || manifest["schemaVersion"] !== RECOVERY_SCHEMA) {
    fail("recovery manifest schema is invalid.");
  }
  const source = record(manifest["sourceWorkflow"], "source workflow binding");
  const deployment = record(manifest["deployment"], "deployment binding");
  const runtime = record(manifest["runtime"], "runtime binding");
  const target = record(manifest["target"], "recovery target");
  if (
    !exactKeys(source, ["runId", "runAttempt", "controlPlaneSha", "controlPlaneGatesSha256"]) ||
    !exactKeys(deployment, ["runId", "artifactId", "artifactDigest", "evidenceSha256", "observationSha256", "applicationUrl"]) ||
    !exactKeys(runtime, ["profileId", "resolution", "stackName", "cloudImageDigest"]) ||
    !exactKeys(target, ["entityUrn", "columnPath", "tagUrn"])
  ) fail("recovery manifest bindings are not exact.");
  const typed = manifest as unknown as RecoveryManifest;
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(typed.repository) ||
    !RUN_ID.test(typed.sourceWorkflow.runId) || !RUN_ATTEMPT.test(typed.sourceWorkflow.runAttempt) ||
    !RELEASE_SHA.test(typed.sourceWorkflow.controlPlaneSha) ||
    !RUN_ID.test(typed.deployment.runId) || !RUN_ID.test(typed.deployment.artifactId) ||
    typed.runtime.profileId !== "cloud" || typed.runtime.resolution !== "explicit" ||
    typed.runtime.stackName !== CLOUD_STACK ||
    typed.target.entityUrn !== CANONICAL_DATASET_URN ||
    typed.target.columnPath !== CANONICAL_COLUMN_PATH || typed.target.tagUrn !== PII_TAG_URN ||
    !instant(typed.preparedAt)
  ) fail("recovery manifest identity is invalid.");
  [
    typed.sourceWorkflow.controlPlaneGatesSha256, typed.deployment.artifactDigest,
    typed.deployment.evidenceSha256, typed.deployment.observationSha256,
    typed.runtime.cloudImageDigest, typed.endpointBindingSha256, typed.digest
  ].forEach((candidate) => digestField(candidate, "manifest digest"));
  exactHttpsUrl(typed.deployment.applicationUrl, "sealed application URL", true);
  const { digest: manifestDigest, ...unsigned } = typed;
  if (await digest(unsigned as unknown as Json) !== manifestDigest) {
    fail("recovery manifest digest does not verify.");
  }
  return typed;
}

function exactProjection(value: TagProjection, target: RecoveryManifest["target"]): void {
  if (
    value.entityUrn !== target.entityUrn || value.columnPath !== target.columnPath ||
    !Array.isArray(value.tags) || value.tags.some((tag) => typeof tag !== "string") ||
    JSON.stringify(value.tags) !== JSON.stringify([...new Set(value.tags)].sort()) ||
    !SHA256.test(value.digest)
  ) fail("DataHub returned an invalid tag projection.");
}

export async function createRecoveryEvidence(input: {
  readonly manifest: RecoveryManifest;
  readonly endpointBindingSha256: string;
  readonly before: TagProjection;
  readonly after: TagProjection;
  readonly mutation?: { readonly requestDigest: string; readonly responseDigest: string };
  readonly recoveredAt: string;
}): Promise<RecoveryEvidence> {
  if (input.endpointBindingSha256 !== input.manifest.endpointBindingSha256) {
    fail("recovery evidence is detached from the sealed endpoint binding.");
  }
  exactProjection(input.before, input.manifest.target);
  exactProjection(input.after, input.manifest.target);
  if (!instant(input.recoveredAt)) fail("recoveredAt is invalid.");
  const expectedAfter = input.before.tags.filter((tag) => tag !== PII_TAG_URN);
  if (JSON.stringify(input.after.tags) !== JSON.stringify(expectedAfter) || input.after.tags.includes(PII_TAG_URN)) {
    fail("the recovery read-back did not restore the exact pre-canary baseline.");
  }
  const performed = input.before.tags.includes(PII_TAG_URN);
  if (performed !== Boolean(input.mutation)) fail("mutation evidence does not match the observed baseline transition.");
  if (input.mutation) {
    digestField(input.mutation.requestDigest, "mutation request digest");
    digestField(input.mutation.responseDigest, "mutation response digest");
  }
  const unsigned = {
    schemaVersion: EVIDENCE_SCHEMA,
    recoveryDigest: input.manifest.digest,
    sourceWorkflow: input.manifest.sourceWorkflow,
    deploymentEvidenceSha256: input.manifest.deployment.evidenceSha256,
    runtimeProfile: "cloud" as const,
    target: input.manifest.target,
    endpointBindingSha256: input.endpointBindingSha256,
    beforeDigest: input.before.digest,
    afterDigest: input.after.digest,
    mutation: input.mutation
      ? { performed: true as const, ...input.mutation }
      : { performed: false as const },
    disposition: performed ? "restored" as const : "already-baseline" as const,
    recoveredAt: input.recoveredAt,
  };
  return { ...unsigned, digest: await digest(unsigned as unknown as Json) };
}

async function seal(): Promise<void> {
  const output = required(process.env, "CANARY_RECOVERY_PATH", 4096);
  const manifest = await sealRecoveryManifest(process.env);
  await writeFile(output, `${canonicalize(manifest as unknown as Json)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function readBoundManifest(): Promise<{
  manifest: RecoveryManifest;
  endpoints: Awaited<ReturnType<typeof endpointBinding>>;
}> {
  const manifestPath = required(process.env, "CANARY_RECOVERY_PATH", 4096);
  const raw = await readFile(manifestPath, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 64 * 1024 || !raw.endsWith("\n")) {
    fail("the recovery manifest envelope is invalid.");
  }
  const parsed = JSON.parse(raw) as unknown;
  if (`${canonicalize(parsed as Json)}\n` !== raw) fail("the recovery manifest is not canonical JSON.");
  const manifest = await parseRecoveryManifest(parsed);
  if (
    manifest.repository !== required(process.env, "GITHUB_REPOSITORY", 256) ||
    manifest.sourceWorkflow.runId !== required(process.env, "CANARY_SOURCE_WORKFLOW_RUN_ID", 20) ||
    manifest.sourceWorkflow.runAttempt !== required(process.env, "CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT", 10) ||
    manifest.sourceWorkflow.controlPlaneSha !== required(process.env, "CANARY_CONTROL_PLANE_SHA", 40)
  ) fail("the recovery artifact does not belong to the requested canary run and control plane.");
  const endpoints = await endpointBinding(process.env);
  if (endpoints.digest !== manifest.endpointBindingSha256) {
    fail("the live DataHub Cloud endpoints changed after recovery was sealed.");
  }
  return { manifest, endpoints };
}

async function verify(): Promise<void> {
  await readBoundManifest();
}

async function recover(): Promise<void> {
  const evidencePath = required(process.env, "CANARY_RECOVERY_EVIDENCE_PATH", 4096);
  const { manifest, endpoints } = await readBoundManifest();
  const readToken = required(process.env, "CANARY_DATAHUB_READ_TOKEN", 16_384);
  const writeToken = required(process.env, "CANARY_DATAHUB_WRITE_TOKEN", 16_384);
  const reader: TagProjectionReader = new DirectGmsTagProjectionReader({
    gmsUrl: endpoints.binding.readGmsUrl,
    token: readToken,
  });
  const target = { entityUrn: CANONICAL_DATASET_URN, columnPath: CANONICAL_COLUMN_PATH };
  const before = await reader.readTagProjection(target);
  exactProjection(before, manifest.target);
  let mutation: { requestDigest: string; responseDigest: string } | undefined;
  if (before.tags.includes(PII_TAG_URN)) {
    process.env["DATAHUB_WRITE_GMS_URL"] = endpoints.binding.writeGmsUrl;
    process.env["DATAHUB_WRITE_MCP_URL"] = endpoints.binding.writeMcpUrl;
    process.env["DATAHUB_WRITE_GMS_TOKEN"] = writeToken;
    try {
      const client: DataHubMutationClient = new LiveDataHubMutationClient();
      mutation = await client.removeTags({
        tagUrns: [PII_TAG_URN], entityUrns: [CANONICAL_DATASET_URN], columnPaths: [CANONICAL_COLUMN_PATH],
      });
    } finally {
      delete process.env["DATAHUB_WRITE_GMS_URL"];
      delete process.env["DATAHUB_WRITE_MCP_URL"];
      delete process.env["DATAHUB_WRITE_GMS_TOKEN"];
    }
  }
  const after = await reader.readTagProjection(target);
  exactProjection(after, manifest.target);
  const evidence = await createRecoveryEvidence({
    manifest, endpointBindingSha256: endpoints.digest, before, after, mutation,
    recoveredAt: new Date().toISOString(),
  });
  await writeFile(evidencePath, `${canonicalize(evidence as unknown as Json)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function main(): Promise<void> {
  const operation = process.argv[2];
  if (operation === "seal") await seal();
  else if (operation === "verify") await verify();
  else if (operation === "recover") await recover();
  else fail("expected seal, verify, or recover.");
}

const invoked = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (invoked === import.meta.url) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : "governed canary failed"}\n`);
    process.exitCode = 1;
  });
}