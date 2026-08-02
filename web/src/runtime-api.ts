export type RuntimeRequest = "auto" | "cloud" | "core";
export type RuntimeProfileId = "cloud" | "core";
export type RuntimeProfileAvailability =
  | "READY"
  | "LAUNCHABLE"
  | "STARTING"
  | "BUSY"
  | "UNAVAILABLE";

export interface RuntimeCapabilities {
  mcpRead: boolean;
  mcpGovernedWrite: boolean;
  agentContextKit: boolean;
  dataHubSkills: boolean;
  analyticsAgent: boolean;
}

export interface RuntimeProfileProjection {
  profileId: RuntimeProfileId;
  availability: RuntimeProfileAvailability;
  generation: string | null;
  checkedAt: string | null;
  capabilities: RuntimeCapabilities;
  capabilityDigest: string | null;
}

export interface RuntimeProfilesResponse {
  schemaVersion: "archon.runtime-profiles/v1";
  serverTime: string;
  profiles: [RuntimeProfileProjection, RuntimeProfileProjection];
  autoSelection: RuntimeProfileId | null;
}

export type RuntimeSessionState =
  | "STARTING"
  | "READY"
  | "STOPPING"
  | "STOPPED"
  | "EXPIRED"
  | "UNAVAILABLE";

export interface RuntimeSessionStatus {
  schemaVersion: "archon.runtime-session-status/v1";
  sessionId: string;
  requestedProfile: RuntimeRequest;
  resolvedProfile: RuntimeProfileId;
  state: RuntimeSessionState;
  createdAt: string;
  updatedAt: string;
  idleExpiresAt: string;
  hardExpiresAt: string;
  remainingSeconds: number;
  canRun: boolean;
  canExtend: boolean;
}

const RUNTIME_PROFILES_PATH = "/api/runtime-profiles";
const RUNTIME_SESSIONS_PATH = "/api/runtime-sessions";
const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const REQUESTS = ["auto", "cloud", "core"] as const;
const PROFILE_IDS = ["cloud", "core"] as const;
const AVAILABILITY = [
  "READY",
  "LAUNCHABLE",
  "STARTING",
  "BUSY",
  "UNAVAILABLE",
] as const;
const SESSION_STATES = [
  "STARTING",
  "READY",
  "STOPPING",
  "STOPPED",
  "EXPIRED",
  "UNAVAILABLE",
] as const;
const CAPABILITY_KEYS = [
  "mcpRead",
  "mcpGovernedWrite",
  "agentContextKit",
  "dataHubSkills",
  "analyticsAgent",
] as const;
const FORBIDDEN_KEYS = new Set([
  "accesstoken",
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "idtoken",
  "jwt",
  "password",
  "privatekey",
  "refreshtoken",
  "secret",
  "sessiontoken",
  "token",
]);
const CREDENTIAL_PATTERNS = [
  /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
  /gh[pousr]_[A-Za-z0-9_]{20,}/u,
  /github_pat_[A-Za-z0-9_]{20,}/u,
  /(?:Bearer\s+|sk-(?:ant-)?)[A-Za-z0-9._~+/=-]{12,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
] as const;

export class RuntimeApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RuntimeApiError";
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every(
      (key) => typeof key === "string" && expected.includes(key),
    ) &&
    expected.every((key) =>
      Object.prototype.hasOwnProperty.call(value, key),
    )
  );
}

function safePublicValue(value: unknown): boolean {
  if (typeof value === "string") {
    return !CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) return value.every(safePublicValue);
  if (!record(value)) return true;
  return Object.entries(value).every(([key, entry]) => {
    const normalized = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    return (
      !FORBIDDEN_KEYS.has(normalized) &&
      !CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key)) &&
      safePublicValue(entry)
    );
  });
}

function instant(value: unknown): value is string {
  if (typeof value !== "string" || !RFC3339.test(value)) return false;
  const parsed = Date.parse(value);
  return (
    Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value
  );
}

function capabilities(value: unknown): value is RuntimeCapabilities {
  return (
    record(value) &&
    exactKeys(value, CAPABILITY_KEYS) &&
    CAPABILITY_KEYS.every((key) => typeof value[key] === "boolean")
  );
}

function profile(
  value: unknown,
  expectedProfileId: RuntimeProfileId,
): value is RuntimeProfileProjection {
  if (
    !record(value) ||
    !exactKeys(value, [
      "profileId",
      "availability",
      "generation",
      "checkedAt",
      "capabilities",
      "capabilityDigest",
    ]) ||
    value.profileId !== expectedProfileId ||
    !AVAILABILITY.includes(
      value.availability as RuntimeProfileAvailability,
    ) ||
    !capabilities(value.capabilities)
  ) {
    return false;
  }
  if (value.availability === "UNAVAILABLE") {
    return (
      value.generation === null &&
      value.checkedAt === null &&
      value.capabilityDigest === null &&
      CAPABILITY_KEYS.every((key) => value.capabilities[key] === false)
    );
  }
  return (
    typeof value.generation === "string" &&
    GENERATION.test(value.generation) &&
    instant(value.checkedAt) &&
    typeof value.capabilityDigest === "string" &&
    DIGEST.test(value.capabilityDigest) &&
    CAPABILITY_KEYS.every((key) => value.capabilities[key] === true)
  );
}

function parseProfiles(value: unknown): RuntimeProfilesResponse {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "serverTime",
      "profiles",
      "autoSelection",
    ]) ||
    value.schemaVersion !== "archon.runtime-profiles/v1" ||
    !instant(value.serverTime) ||
    !Array.isArray(value.profiles) ||
    value.profiles.length !== 2 ||
    !profile(value.profiles[0], "cloud") ||
    !profile(value.profiles[1], "core") ||
    !(
      value.autoSelection === null ||
      PROFILE_IDS.includes(value.autoSelection as RuntimeProfileId)
    ) ||
    (value.autoSelection === "cloud" &&
      value.profiles[0].availability !== "READY") ||
    (value.autoSelection === "core" &&
      value.profiles[0].availability === "READY") ||
    (value.autoSelection === "core" &&
      value.profiles[1].availability !== "LAUNCHABLE") ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The runtime registry returned an invalid public contract.",
      502,
    );
  }
  return value as unknown as RuntimeProfilesResponse;
}

function parseSession(value: unknown): RuntimeSessionStatus {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "sessionId",
      "requestedProfile",
      "resolvedProfile",
      "state",
      "createdAt",
      "updatedAt",
      "idleExpiresAt",
      "hardExpiresAt",
      "remainingSeconds",
      "canRun",
      "canExtend",
    ]) ||
    value.schemaVersion !== "archon.runtime-session-status/v1" ||
    typeof value.sessionId !== "string" ||
    !SESSION_ID.test(value.sessionId) ||
    !REQUESTS.includes(value.requestedProfile as RuntimeRequest) ||
    !PROFILE_IDS.includes(value.resolvedProfile as RuntimeProfileId) ||
    !SESSION_STATES.includes(value.state as RuntimeSessionState) ||
    !instant(value.createdAt) ||
    !instant(value.updatedAt) ||
    !instant(value.idleExpiresAt) ||
    !instant(value.hardExpiresAt) ||
    Date.parse(value.updatedAt) < Date.parse(value.createdAt) ||
    Date.parse(value.idleExpiresAt) <= Date.parse(value.createdAt) ||
    Date.parse(value.hardExpiresAt) < Date.parse(value.idleExpiresAt) ||
    Date.parse(value.hardExpiresAt) - Date.parse(value.createdAt) >
      2 * 60 * 60_000 ||
    !Number.isSafeInteger(value.remainingSeconds) ||
    (value.remainingSeconds as number) < 0 ||
    (value.remainingSeconds as number) > 2 * 60 * 60 ||
    typeof value.canRun !== "boolean" ||
    typeof value.canExtend !== "boolean" ||
    (value.state === "READY" ? value.canRun !== true : value.canRun !== false) ||
    (value.canExtend === true && value.state !== "READY") ||
    (value.requestedProfile === "cloud" &&
      value.resolvedProfile !== "cloud") ||
    (value.requestedProfile === "core" &&
      value.resolvedProfile !== "core") ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The runtime control plane returned an invalid session contract.",
      502,
    );
  }
  return value as unknown as RuntimeSessionStatus;
}

async function jsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new RuntimeApiError(
      "The runtime control plane returned a non-JSON response.",
      502,
    );
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new RuntimeApiError(
      "The runtime control plane returned malformed JSON.",
      502,
    );
  }
  if (!response.ok) {
    const known =
      record(value) && typeof value.error === "string"
        ? value.error
        : "runtime_request_failed";
    const messages: Record<string, string> = {
      runtime_not_ready:
        "That DataHub runtime is not fully ready with all five capabilities.",
      runtime_busy:
        "The ephemeral DataHub Core sandbox is currently leased.",
      runtime_session_not_active:
        "This runtime session is no longer active.",
      runtime_identity_mismatch:
        "The runtime identity changed; start a new pinned session.",
      runtime_provisioning_failed:
        "The DataHub Core sandbox could not be provisioned.",
      runtime_stop_failed:
        "The runtime teardown request could not be confirmed.",
      runtime_session_conflict:
        "The runtime session changed concurrently. Refresh and retry.",
    };
    throw new RuntimeApiError(
      messages[known] ??
        "Runtime control request failed (" + response.status + ").",
      response.status,
    );
  }
  return value;
}

async function request(
  path: string,
  init: RequestInit,
): Promise<unknown> {
  return jsonResponse(
    await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body === undefined
          ? {}
          : { "Content-Type": "application/json" }),
        ...init.headers,
      },
    }),
  );
}

function sessionPath(sessionId: string): string {
  if (!SESSION_ID.test(sessionId)) {
    throw new RuntimeApiError("The runtime session capability is invalid.", 400);
  }
  return RUNTIME_SESSIONS_PATH + "/" + encodeURIComponent(sessionId);
}

export async function getRuntimeProfiles(
  signal?: AbortSignal,
): Promise<RuntimeProfilesResponse> {
  return parseProfiles(
    await request(RUNTIME_PROFILES_PATH, { method: "GET", signal }),
  );
}

export async function startRuntimeSession(
  requestedProfile: RuntimeRequest,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  if (!REQUESTS.includes(requestedProfile)) {
    throw new RuntimeApiError("The runtime request is invalid.", 400);
  }
  return parseSession(
    await request(RUNTIME_SESSIONS_PATH, {
      method: "POST",
      body: JSON.stringify({ requestedProfile }),
      signal,
    }),
  );
}

export async function getRuntimeSession(
  sessionId: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId), { method: "GET", signal }),
  );
}

export async function extendRuntimeSession(
  sessionId: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId) + "/activity", {
      method: "POST",
      body: "{}",
      signal,
    }),
  );
}

export async function stopRuntimeSession(
  sessionId: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId) + "/stop", {
      method: "POST",
      body: "{}",
      signal,
    }),
  );
}