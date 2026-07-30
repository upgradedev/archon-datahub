// Privacy-safe runtime provenance for the optional narration model.
//
// This contract deliberately records only bounded, structural provider metadata. It never
// accepts prompts, credentials, endpoints, response bodies, provider errors, or arbitrary
// response fields. The discriminated union prevents deterministic fixture output from
// being represented as a live provider call (or vice versa).

export const MODEL_PROVENANCE_SCHEMA_VERSION =
  "archon.model-runtime-provenance/v1" as const;

export type LiveLlmProvider =
  | "bedrock-mantle"
  | "custom"
  | "qwen"
  | "gemini"
  | "openai"
  | "anthropic";

export type LlmRuntimeIdentity =
  | {
      source: "deterministic-fixture";
      provider: "fixture";
    }
  | {
      source: "live-provider";
      provider: LiveLlmProvider;
    };

export interface ModelTokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

interface ModelRuntimeProvenanceBase {
  schemaVersion: typeof MODEL_PROVENANCE_SCHEMA_VERSION;
  requestedModel: string;
}

export interface DeterministicFixtureModelProvenance
  extends ModelRuntimeProvenanceBase {
  source: "deterministic-fixture";
  modelCall: false;
  provider: "fixture";
  returnedModel: null;
  providerResponseId: null;
  tokenUsage: null;
  latencyMs: null;
}

export interface LiveProviderModelProvenance
  extends ModelRuntimeProvenanceBase {
  source: "live-provider";
  modelCall: true;
  provider: LiveLlmProvider;
  returnedModel: string;
  providerResponseId: string;
  tokenUsage: ModelTokenUsage | null;
  latencyMs: number;
}

export type ModelRuntimeProvenance =
  | DeterministicFixtureModelProvenance
  | LiveProviderModelProvenance;

export interface ProviderResponseMetadata {
  id?: unknown;
  model?: unknown;
  usage?: unknown;
}

const LIVE_PROVIDERS = new Set<LiveLlmProvider>([
  "bedrock-mantle",
  "custom",
  "qwen",
  "gemini",
  "openai",
  "anthropic",
]);
const PROVENANCE_KEYS = [
  "schemaVersion",
  "source",
  "modelCall",
  "provider",
  "requestedModel",
  "returnedModel",
  "providerResponseId",
  "tokenUsage",
  "latencyMs",
] as const;
const USAGE_KEYS = ["inputTokens", "outputTokens", "totalTokens"] as const;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/u;
const RESPONSE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{5,199}$/u;
// Deliberately substring-aware: provider identifiers frequently add prefixes such as
// `model_` or `resp_`. Anchoring this detector would let an embedded credential-shaped
// value pass the otherwise strict identifier allowlist and reach exported evidence.
const CREDENTIAL_SHAPED_IDENTIFIER =
  /(?:bedrock-api-key-[A-Za-z0-9_+/=-]{16,}|sk-(?:ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/u;
const MAX_LATENCY_MS = 3_600_000;

export class ModelProvenanceError extends Error {
  readonly code = "INVALID_MODEL_PROVENANCE";

  constructor() {
    super("Model runtime provenance is absent or invalid.");
    this.name = "ModelProvenanceError";
  }
}

function invalid(): never {
  throw new ModelProvenanceError();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => expected.includes(key))
  );
}

function safeModelId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !MODEL_ID_PATTERN.test(value) ||
    value.includes("://") ||
    CREDENTIAL_SHAPED_IDENTIFIER.test(value)
  ) {
    invalid();
  }
  return value;
}

function safeResponseId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !RESPONSE_ID_PATTERN.test(value) ||
    CREDENTIAL_SHAPED_IDENTIFIER.test(value)
  ) {
    invalid();
  }
  return value;
}

function safeCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalid();
  return value as number;
}

function parseTokenUsage(value: unknown): ModelTokenUsage | null {
  if (value === null) return null;
  if (!isRecord(value) || !hasExactKeys(value, USAGE_KEYS)) invalid();
  const inputTokens = safeCount(value["inputTokens"]);
  const outputTokens = safeCount(value["outputTokens"]);
  const totalTokens = safeCount(value["totalTokens"]);
  if (totalTokens !== inputTokens + outputTokens) invalid();
  return { inputTokens, outputTokens, totalTokens };
}

function normalizeProviderUsage(value: unknown): ModelTokenUsage | null {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) invalid();
  const inputTokens = safeCount(value["prompt_tokens"]);
  const outputTokens = safeCount(value["completion_tokens"]);
  const totalTokens = safeCount(value["total_tokens"]);
  if (totalTokens !== inputTokens + outputTokens) invalid();
  return { inputTokens, outputTokens, totalTokens };
}

function safeLatency(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > MAX_LATENCY_MS
  ) {
    invalid();
  }
  return value as number;
}

export function createModelRuntimeProvenance(
  runtime: LlmRuntimeIdentity,
  requestedModel: string,
  response: ProviderResponseMetadata,
  latencyMs: number | null
): ModelRuntimeProvenance {
  const safeRequestedModel = safeModelId(requestedModel);
  if (runtime.source === "deterministic-fixture") {
    return {
      schemaVersion: MODEL_PROVENANCE_SCHEMA_VERSION,
      source: "deterministic-fixture",
      modelCall: false,
      provider: "fixture",
      requestedModel: safeRequestedModel,
      returnedModel: null,
      providerResponseId: null,
      tokenUsage: null,
      latencyMs: null,
    };
  }

  if (!LIVE_PROVIDERS.has(runtime.provider) || latencyMs === null) invalid();
  return {
    schemaVersion: MODEL_PROVENANCE_SCHEMA_VERSION,
    source: "live-provider",
    modelCall: true,
    provider: runtime.provider,
    requestedModel: safeRequestedModel,
    returnedModel: safeModelId(response.model),
    providerResponseId: safeResponseId(response.id),
    tokenUsage: normalizeProviderUsage(response.usage),
    latencyMs: safeLatency(latencyMs),
  };
}

export function parseModelRuntimeProvenance(
  value: unknown
): ModelRuntimeProvenance {
  if (!isRecord(value) || !hasExactKeys(value, PROVENANCE_KEYS)) invalid();
  if (value["schemaVersion"] !== MODEL_PROVENANCE_SCHEMA_VERSION) invalid();
  const requestedModel = safeModelId(value["requestedModel"]);

  if (value["source"] === "deterministic-fixture") {
    if (
      value["modelCall"] !== false ||
      value["provider"] !== "fixture" ||
      value["returnedModel"] !== null ||
      value["providerResponseId"] !== null ||
      value["tokenUsage"] !== null ||
      value["latencyMs"] !== null
    ) {
      invalid();
    }
    return {
      schemaVersion: MODEL_PROVENANCE_SCHEMA_VERSION,
      source: "deterministic-fixture",
      modelCall: false,
      provider: "fixture",
      requestedModel,
      returnedModel: null,
      providerResponseId: null,
      tokenUsage: null,
      latencyMs: null,
    };
  }

  if (
    value["source"] !== "live-provider" ||
    value["modelCall"] !== true ||
    typeof value["provider"] !== "string" ||
    !LIVE_PROVIDERS.has(value["provider"] as LiveLlmProvider)
  ) {
    invalid();
  }
  return {
    schemaVersion: MODEL_PROVENANCE_SCHEMA_VERSION,
    source: "live-provider",
    modelCall: true,
    provider: value["provider"] as LiveLlmProvider,
    requestedModel,
    returnedModel: safeModelId(value["returnedModel"]),
    providerResponseId: safeResponseId(value["providerResponseId"]),
    tokenUsage: parseTokenUsage(value["tokenUsage"]),
    latencyMs: safeLatency(value["latencyMs"]),
  };
}

export function isModelRuntimeProvenance(
  value: unknown
): value is ModelRuntimeProvenance {
  try {
    parseModelRuntimeProvenance(value);
    return true;
  } catch {
    return false;
  }
}
