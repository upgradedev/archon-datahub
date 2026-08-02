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

function instant(value: string, name: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      `${name} must be an exact ISO-8601 UTC instant`
    );
  }
  return parsed;
}

function exactCapabilities(value: RuntimeCapabilities): void {
  const keys = Object.keys(value).sort();
  const expected = [...REQUIRED_RUNTIME_CAPABILITIES].sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime capabilities must use the exact allowlisted schema"
    );
  }
  for (const key of REQUIRED_RUNTIME_CAPABILITIES) {
    if (typeof value[key] !== "boolean") {
      throw new RuntimeSelectionError(
        "INVALID_RUNTIME_SNAPSHOT",
        `runtime capability ${key} must be boolean`
      );
    }
  }
}

function validateSnapshot(snapshot: RuntimeProfileSnapshot): void {
  if (!RUNTIME_PROFILE_IDS.includes(snapshot.profileId)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime profile is not allowlisted"
    );
  }
  if (!GENERATION.test(snapshot.generation)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime generation is invalid"
    );
  }
  if (!["ready", "starting", "unavailable"].includes(snapshot.status)) {
    throw new RuntimeSelectionError(
      "INVALID_RUNTIME_SNAPSHOT",
      "runtime health status is invalid"
    );
  }
  instant(snapshot.checkedAt, "checkedAt");
  exactCapabilities(snapshot.capabilities);
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

  return Object.freeze({
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
  expected: RuntimeBinding,
  actual: RuntimeBinding
): void {
  const valid =
    expected.schemaVersion === "archon.runtime-binding/v1" &&
    actual.schemaVersion === "archon.runtime-binding/v1" &&
    RUNTIME_PROFILE_IDS.includes(expected.profileId) &&
    RUNTIME_PROFILE_IDS.includes(actual.profileId) &&
    GENERATION.test(expected.generation) &&
    GENERATION.test(actual.generation) &&
    DIGEST.test(expected.capabilityDigest) &&
    DIGEST.test(actual.capabilityDigest) &&
    expected.profileId === actual.profileId &&
    expected.generation === actual.generation &&
    expected.capabilityDigest === actual.capabilityDigest &&
    expected.boundAt === actual.boundAt &&
    expected.leaseExpiresAt === actual.leaseExpiresAt;

  if (!valid) {
    throw new RuntimeSelectionError(
      "RUNTIME_BINDING_MISMATCH",
      "runtime binding changed after session resolution"
    );
  }
}
