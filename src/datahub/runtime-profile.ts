import { createHash } from "node:crypto";

export const RUNTIME_PROFILE_IDS = ["cloud", "core"] as const;
export const RUNTIME_REQUESTS = ["auto", ...RUNTIME_PROFILE_IDS] as const;
export const REQUIRED_RUNTIME_CAPABILITIES = [
  "mcpRead",
  "mcpGovernedWrite",
  "agentContextKit",
  "dataHubSkills",
  "analyticsAgent",
] as const;

export type RuntimeProfileId = (typeof RUNTIME_PROFILE_IDS)[number];
export type RuntimeRequest = (typeof RUNTIME_REQUESTS)[number];
export type RuntimeCapability =
  (typeof REQUIRED_RUNTIME_CAPABILITIES)[number];
export type RuntimeHealthStatus = "ready" | "starting" | "unavailable";

export interface RuntimeCapabilities {
  mcpRead: boolean;
  mcpGovernedWrite: boolean;
  agentContextKit: boolean;
  dataHubSkills: boolean;
  analyticsAgent: boolean;
}

export interface RuntimeProfileSnapshot {
  profileId: RuntimeProfileId;
  generation: string;
  status: RuntimeHealthStatus;
  checkedAt: string;
  capabilities: RuntimeCapabilities;
}

export interface RuntimeBinding {
  schemaVersion: "archon.runtime-binding/v1";
  profileId: RuntimeProfileId;
  generation: string;
  capabilityDigest: `sha256:${string}`;
  resolution: "auto" | "explicit";
  boundAt: string;
  leaseExpiresAt: string;
}

export interface RuntimeSelectionOptions {
  now: string;
  leaseExpiresAt: string;
  maxHealthAgeMs?: number;
}

export type RuntimeSelectionErrorCode =
  | "INVALID_RUNTIME_REQUEST"
  | "INVALID_RUNTIME_SNAPSHOT"
  | "INVALID_RUNTIME_BINDING"
  | "RUNTIME_NOT_READY"
  | "NO_RUNTIME_AVAILABLE"
  | "RUNTIME_BINDING_MISMATCH";

export class RuntimeSelectionError extends Error {
  constructor(
    readonly code: RuntimeSelectionErrorCode,
    message: string
  ) {
    super(message);
    this.name = "RuntimeSelectionError";
  }
}

const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const DEFAULT_MAX_HEALTH_AGE_MS = 90_000;

function instant(
  value: unknown,
  name: string,
  code: RuntimeSelectionErrorCode = "INVALID_RUNTIME_SNAPSHOT"
): number {
  if (typeof value !== "string") {
    throw new RuntimeSelectionError(code, `${name} must be a string`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new RuntimeSelectionError(
      code,
      `${name} must be an exact ISO-8601 UTC instant`
    );
  }
  return parsed;
}

function exactStringKeys(
  value: object,
  expected: readonly string[],
  code: RuntimeSelectionErrorCode,
  message: string
): void {
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some(
      (key) => typeof key !== "string" || !expected.includes(key)
    ) ||
    expected.some(
      (key) => !Object.prototype.hasOwnProperty.call(value, key)
    )
  ) {
    throw new RuntimeSelectionError(code, message);
  }
}

function exactCapabilities(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime capabilities must be an object"
    );
  }
  exactStringKeys(
    value,
    REQUIRED_RUNTIME_CAPABILITIES,
    "INVALID_RUNTIME_SNAPSHOT",
    "runtime capabilities must use the exact allowlisted schema"
  );
  const capabilities = value as Record<RuntimeCapability, unknown>;
  for (const key of REQUIRED_RUNTIME_CAPABILITIES) {
    if (typeof capabilities[key] !== "boolean") {
      throw new RuntimeSelectionError(
        "INVALID_RUNTIME_SNAPSHOT",
        `runtime capability ${key} must be boolean`
      );
    }
  }
}

function validateSnapshot(snapshot: unknown): asserts snapshot is RuntimeProfileSnapshot {
  if (
    snapshot === null ||
    typeof snapshot !== "object" ||
    Array.isArray(snapshot)
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime snapshot must be an object"
    );
  }
  const record = snapshot as Record<string, unknown>;
  exactStringKeys(
    record,
    ["capabilities", "checkedAt", "generation", "profileId", "status"],
    "INVALID_RUNTIME_SNAPSHOT",
    "runtime snapshot must use the exact allowlisted schema"
  );
  if (
    typeof record.profileId !== "string" ||
    !RUNTIME_PROFILE_IDS.includes(record.profileId as RuntimeProfileId)
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime profile is not allowlisted"
    );
  }
  if (
    typeof record.generation !== "string" ||
    !GENERATION.test(record.generation)
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime generation is invalid"
    );
  }
  if (
    typeof record.status !== "string" ||
    !["ready", "starting", "unavailable"].includes(record.status)
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime health status is invalid"
    );
  }
  instant(record.checkedAt, "checkedAt");
  exactCapabilities(record.capabilities);
}

function canonicalCapabilities(
  capabilities: RuntimeCapabilities
): Record<RuntimeCapability, boolean> {
  return {
    mcpRead: capabilities.mcpRead,
    mcpGovernedWrite: capabilities.mcpGovernedWrite,
    agentContextKit: capabilities.agentContextKit,
    dataHubSkills: capabilities.dataHubSkills,
    analyticsAgent: capabilities.analyticsAgent,
  };
}

export function runtimeCapabilityDigest(
  snapshot: RuntimeProfileSnapshot
): `sha256:${string}` {
  validateSnapshot(snapshot);
  const canonical = JSON.stringify({
    schemaVersion: "archon.runtime-capabilities/v1",
    profileId: snapshot.profileId,
    generation: snapshot.generation,
    capabilities: canonicalCapabilities(snapshot.capabilities),
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

export function isRuntimeReady(
  snapshot: RuntimeProfileSnapshot,
  now: string,
  maxHealthAgeMs = DEFAULT_MAX_HEALTH_AGE_MS
): boolean {
  validateSnapshot(snapshot);
  const nowMs = instant(now, "now");
  const checkedAtMs = instant(snapshot.checkedAt, "checkedAt");
  if (
    !Number.isSafeInteger(maxHealthAgeMs) ||
    maxHealthAgeMs < 1_000 ||
    maxHealthAgeMs > 5 * 60_000
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "maxHealthAgeMs is outside the reviewed range"
    );
  }
  if (checkedAtMs > nowMs || nowMs - checkedAtMs > maxHealthAgeMs) {
    return false;
  }
  return (
    snapshot.status === "ready" &&
    REQUIRED_RUNTIME_CAPABILITIES.every(
      (capability) => snapshot.capabilities[capability]
    )
  );
}

function snapshotMap(
  snapshots: readonly RuntimeProfileSnapshot[]
): ReadonlyMap<RuntimeProfileId, RuntimeProfileSnapshot> {
  const mapped = new Map<RuntimeProfileId, RuntimeProfileSnapshot>();
  for (const snapshot of snapshots) {
    validateSnapshot(snapshot);
    if (mapped.has(snapshot.profileId)) {
      throw new RuntimeSelectionError(
        "INVALID_RUNTIME_SNAPSHOT",
        `duplicate runtime snapshot for ${snapshot.profileId}`
      );
    }
    mapped.set(snapshot.profileId, snapshot);
  }
  return mapped;
}

const RUNTIME_BINDING_KEYS = [
  "boundAt",
  "capabilityDigest",
  "generation",
  "leaseExpiresAt",
  "profileId",
  "resolution",
  "schemaVersion",
] as const;

function invalidBinding(message: string): never {
  throw new RuntimeSelectionError("INVALID_RUNTIME_BINDING", message);
}

function bindingInstant(value: unknown, name: string): number {
  if (typeof value !== "string") {
    return invalidBinding("runtime binding " + name + " must be a string");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    return invalidBinding(
      "runtime binding " + name + " must be an exact ISO-8601 UTC instant"
    );
  }
  return parsed;
}

export function validateRuntimeBinding(
  binding: unknown
): Readonly<RuntimeBinding> {
  if (
    binding === null ||
    typeof binding !== "object" ||
    Array.isArray(binding)
  ) {
    return invalidBinding("runtime binding must be an object");
  }
  const record = binding as Record<string, unknown>;
  exactStringKeys(
    record,
    RUNTIME_BINDING_KEYS,
    "INVALID_RUNTIME_BINDING",
    "runtime binding must use the exact public schema"
  );
  if (record.schemaVersion !== "archon.runtime-binding/v1") {
    return invalidBinding("runtime binding schema is invalid");
  }
  if (
    typeof record.profileId !== "string" ||
    !RUNTIME_PROFILE_IDS.includes(record.profileId as RuntimeProfileId)
  ) {
    return invalidBinding("runtime binding profile is not allowlisted");
  }
  if (
    typeof record.generation !== "string" ||
    !GENERATION.test(record.generation)
  ) {
    return invalidBinding("runtime binding generation is invalid");
  }
  if (
    typeof record.capabilityDigest !== "string" ||
    !DIGEST.test(record.capabilityDigest)
  ) {
    return invalidBinding("runtime binding capability digest is invalid");
  }
  if (record.resolution !== "auto" && record.resolution !== "explicit") {
    return invalidBinding("runtime binding resolution is invalid");
  }
  const boundAtMs = bindingInstant(record.boundAt, "boundAt");
  const leaseExpiresAtMs = bindingInstant(
    record.leaseExpiresAt,
    "leaseExpiresAt"
  );
  if (
    leaseExpiresAtMs <= boundAtMs ||
    leaseExpiresAtMs - boundAtMs > 2 * 60 * 60_000
  ) {
    return invalidBinding(
      "runtime binding lease must be positive and no longer than two hours"
    );
  }
  return Object.freeze({
    schemaVersion: "archon.runtime-binding/v1",
    profileId: record.profileId as RuntimeProfileId,
    generation: record.generation as string,
    capabilityDigest: record.capabilityDigest as `sha256:${string}`,
    resolution: record.resolution as "auto" | "explicit",
    boundAt: record.boundAt as string,
    leaseExpiresAt: record.leaseExpiresAt as string,
  });
}
export function selectRuntime(
  requested: RuntimeRequest,
  snapshots: readonly RuntimeProfileSnapshot[],
  options: RuntimeSelectionOptions
): Readonly<RuntimeBinding> {
  if (!RUNTIME_REQUESTS.includes(requested)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_REQUEST",
      "runtime request is not allowlisted"
    );
  }
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options)
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime selection options must be an object"
    );
  }
  const optionKeys = Reflect.ownKeys(options);
  const requiredOptionKeys = ["now", "leaseExpiresAt"] as const;
  if (
    optionKeys.some(
      (key) =>
        typeof key !== "string" ||
        !["now", "leaseExpiresAt", "maxHealthAgeMs"].includes(key)
    ) ||
    requiredOptionKeys.some(
      (key) => !Object.prototype.hasOwnProperty.call(options, key)
    )
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime selection options must use the exact schema"
    );
  }
  if (!Array.isArray(snapshots)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime snapshots must be an array"
    );
  }
  const nowMs = instant(options.now, "now");
  const leaseExpiresAtMs = instant(options.leaseExpiresAt, "leaseExpiresAt");
  if (leaseExpiresAtMs <= nowMs || leaseExpiresAtMs - nowMs > 2 * 60 * 60_000) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime lease must expire within the reviewed two-hour ceiling"
    );
  }

  const byId = snapshotMap(snapshots);
  const maxHealthAgeMs =
    options.maxHealthAgeMs ?? DEFAULT_MAX_HEALTH_AGE_MS;
  const order: readonly RuntimeProfileId[] =
    requested === "auto" ? ["cloud", "core"] : [requested];
  const selected = order
    .map((profileId) => byId.get(profileId))
    .find(
      (snapshot): snapshot is RuntimeProfileSnapshot =>
        snapshot !== undefined &&
        isRuntimeReady(snapshot, options.now, maxHealthAgeMs)
    );

  if (!selected) {
    throw new RuntimeSelectionError(
      requested === "auto" ? "NO_RUNTIME_AVAILABLE" : "RUNTIME_NOT_READY",
      requested === "auto"
        ? "no fully capable DataHub runtime is ready"
        : `requested DataHub runtime ${requested} is not ready`
    );
  }

  return validateRuntimeBinding({
    schemaVersion: "archon.runtime-binding/v1",
    profileId: selected.profileId,
    generation: selected.generation,
    capabilityDigest: runtimeCapabilityDigest(selected),
    resolution: requested === "auto" ? "auto" : "explicit",
    boundAt: options.now,
    leaseExpiresAt: options.leaseExpiresAt,
  });
}

export function assertPinnedRuntime(
  expected: unknown,
  actual: unknown
): void {
  let left: Readonly<RuntimeBinding>;
  let right: Readonly<RuntimeBinding>;
  try {
    left = validateRuntimeBinding(expected);
    right = validateRuntimeBinding(actual);
  } catch {
    throw new RuntimeSelectionError(
      "RUNTIME_BINDING_MISMATCH",
      "runtime binding is invalid after session resolution"
    );
  }
  const valid =
    left.schemaVersion === right.schemaVersion &&
    left.profileId === right.profileId &&
    left.generation === right.generation &&
    left.capabilityDigest === right.capabilityDigest &&
    left.resolution === right.resolution &&
    left.boundAt === right.boundAt &&
    left.leaseExpiresAt === right.leaseExpiresAt;

  if (!valid) {
    throw new RuntimeSelectionError(
      "RUNTIME_BINDING_MISMATCH",
      "runtime binding changed after session resolution"
    );
  }
}
