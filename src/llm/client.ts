// LLM client seam — one OpenAI-compatible entry point, provider-agnostic.
//
// The narrator (executive summary) and the optional ReAct loop talk to an LLM through
// this single OpenAI-compatible surface. Supported live providers must return the
// bounded response identity required by archon.model-runtime-provenance/v1; Qwen,
// OpenAI, Gemini, Anthropic, and explicitly configured compatible gateways are
// supported. Hosted AWS tasks use Amazon Bedrock Mantle through an interface VPC
// endpoint and mint short-term bearer tokens from their task roles in memory. Other
// providers retain the explicit API-key path for local/operator use. With no live
// provider configured the agent auto-falls back to the deterministic FakeLlmClient
// (src/llm/fake.ts), so every code path — including the function-calling tool-call
// parse — runs offline in CI with zero secrets and zero spend.
//
// The minimal interfaces below are the ONLY surface the narrator + loop need. The real
// `openai` client satisfies them, and the Fake satisfies them in tests.

import OpenAI from "openai";
import { getTokenProvider } from "@aws/bedrock-token-generator";
import { fromContainerMetadata } from "@aws-sdk/credential-providers";
import type {
  LiveLlmProvider,
  LlmRuntimeIdentity,
} from "./provenance.js";

// ── Provider auto-detection (OpenAI-compatible, provider-agnostic) ────────────
//
// The narrator + optional ReAct loop talk to an LLM through ONE OpenAI-compatible surface.
// We detect which supported provider to use from the environment, in a DETERMINISTIC
// precedence order, and route the base URL + default model accordingly.
// Each provider below exposes an OpenAI-compatible `/chat/completions` endpoint:
//   • LLM_PROVIDER=bedrock-mantle — task-role short-term authentication; wins outright.
//   • LLM_API_KEY      — generic override (honors LLM_BASE_URL / LLM_MODEL).
//   • DASHSCOPE_API_KEY — Qwen via Alibaba Model Studio (this project's default provider).
//   • GEMINI_API_KEY    — Google Gemini's OpenAI-compatible gateway.
//   • OPENAI_API_KEY    — OpenAI.
//   • ANTHROPIC_API_KEY — Anthropic's OpenAI-compatible endpoint (model claude-opus-4-8).
//
// With NONE of these set the agent auto-falls back to the deterministic FakeLlmClient, so
// every path — including the function-calling tool-call parse — runs offline in CI with
// zero secrets and zero spend. The recognized set is intentionally the named providers plus
// the LLM_API_KEY override; we do NOT invent keys, so an unrelated env var never flips an
// offline run to a live (billable) call by accident.

export const BEDROCK_MANTLE_PROVIDER = "bedrock-mantle" as const;
export const BEDROCK_MANTLE_REGION = "eu-west-1" as const;
export const BEDROCK_MANTLE_MODEL =
  "qwen.qwen3-235b-a22b-2507" as const;
export const BEDROCK_MANTLE_BASE_URL =
  `https://bedrock-mantle.${BEDROCK_MANTLE_REGION}.api.aws/v1` as const;

interface ApiKeyLlmProvider {
  auth: "api-key";
  name: LiveLlmProvider;
  apiKey: string;
  baseURL: string;
  model: string;
}

export interface BedrockMantleLlmProvider {
  auth: "aws-short-term";
  name: typeof BEDROCK_MANTLE_PROVIDER;
  region: typeof BEDROCK_MANTLE_REGION;
  baseURL: typeof BEDROCK_MANTLE_BASE_URL;
  model: typeof BEDROCK_MANTLE_MODEL;
  project: string;
}

export type LlmProvider = ApiKeyLlmProvider | BedrockMantleLlmProvider;
export type BedrockTokenProvider = () => Promise<string>;

export class BedrockMantleRequestError extends Error {
  readonly status = 400;

  constructor() {
    super("Bedrock Mantle request model differs from the approved deployment model.");
    this.name = "BedrockMantleRequestError";
  }
}

export class BedrockMantleAuthenticationError extends Error {
  readonly status = 401;

  constructor() {
    super(
      "Unable to mint a valid short-term Bedrock Mantle token from the AWS task role."
    );
    this.name = "BedrockMantleAuthenticationError";
  }
}

export class BedrockMantleTokenProviderUnavailableError extends Error {
  readonly retryable = true;
  readonly status = 503;

  constructor() {
    super(
      "The ECS task-role credential provider is temporarily unavailable for Bedrock Mantle."
    );
    this.name = "BedrockMantleTokenProviderUnavailableError";
  }
}

const FORBIDDEN_TASK_ROLE_CREDENTIAL_ENVIRONMENT = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_PROFILE",
  "AWS_DEFAULT_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_CONFIG_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
] as const;

interface ProviderSpec {
  env: string;
  name: LiveLlmProvider;
  baseURL: string;
  model: string;
}

// Precedence order: the explicit generic override first, then the named providers.
const PROVIDERS: ProviderSpec[] = [
  {
    env: "DASHSCOPE_API_KEY",
    name: "qwen",
    baseURL: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    model: "qwen-plus",
  },
  {
    env: "GEMINI_API_KEY",
    name: "gemini",
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/",
    model: "gemini-2.5-flash",
  },
  { env: "OPENAI_API_KEY", name: "openai", baseURL: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  {
    env: "ANTHROPIC_API_KEY",
    name: "anthropic",
    baseURL: "https://api.anthropic.com/v1/",
    model: "claude-opus-4-8",
  },
];

// Resolve the configured provider from the environment, or null when none is set (offline).
export function resolveLlmProvider(): LlmProvider | null {
  const explicitProvider = process.env.LLM_PROVIDER?.trim();
  const ambientBedrockToken = process.env.AWS_BEARER_TOKEN_BEDROCK?.trim();
  if (explicitProvider || ambientBedrockToken) {
    if (explicitProvider !== BEDROCK_MANTLE_PROVIDER) {
      throw new Error(
        `LLM_PROVIDER must be ${BEDROCK_MANTLE_PROVIDER} when Bedrock Mantle authentication is configured.`
      );
    }
    if (ambientBedrockToken) {
      throw new Error(
        "AWS_BEARER_TOKEN_BEDROCK is forbidden; hosted workloads mint short-term tokens from their AWS task roles."
      );
    }
    const conflictingCredential = [
      "LLM_API_KEY",
      ...PROVIDERS.map((provider) => provider.env),
    ].find((name) => process.env[name]?.trim());
    if (conflictingCredential) {
      throw new Error(
        `${conflictingCredential} is forbidden when LLM_PROVIDER=${BEDROCK_MANTLE_PROVIDER}.`
      );
    }
    if (process.env.AWS_REGION !== BEDROCK_MANTLE_REGION) {
      throw new Error(
        `AWS_REGION must be ${BEDROCK_MANTLE_REGION} for the approved Bedrock Mantle deployment.`
      );
    }
    if (process.env.LLM_BASE_URL !== BEDROCK_MANTLE_BASE_URL) {
      throw new Error(
        `LLM_BASE_URL must be ${BEDROCK_MANTLE_BASE_URL} for the approved Bedrock Mantle endpoint.`
      );
    }
    if (process.env.LLM_MODEL !== BEDROCK_MANTLE_MODEL) {
      throw new Error(
        `LLM_MODEL must be ${BEDROCK_MANTLE_MODEL} for the approved Bedrock Mantle model.`
      );
    }
    const project = process.env.LLM_PROJECT_ID?.trim();
    if (!project || !/^proj_[a-z0-9]{3,128}$/u.test(project)) {
      throw new Error(
        "LLM_PROJECT_ID must identify the stage-scoped Bedrock Mantle project."
      );
    }
    return {
      auth: "aws-short-term",
      name: BEDROCK_MANTLE_PROVIDER,
      region: BEDROCK_MANTLE_REGION,
      baseURL: BEDROCK_MANTLE_BASE_URL,
      model: BEDROCK_MANTLE_MODEL,
      project,
    };
  }

  // Generic override wins: an explicit LLM_API_KEY (+ optional LLM_BASE_URL / LLM_MODEL).
  const override = process.env.LLM_API_KEY;
  if (override) {
    return {
      auth: "api-key",
      name: "custom",
      apiKey: override,
      baseURL: process.env.LLM_BASE_URL || PROVIDERS[0]!.baseURL,
      model: process.env.LLM_MODEL || PROVIDERS[0]!.model,
    };
  }
  for (const p of PROVIDERS) {
    const key = process.env[p.env];
    if (key) {
      return {
        auth: "api-key",
        // A named credential routed through an explicit gateway is provenance-classed
        // as custom. Claiming the named provider would be misleading because the
        // configured endpoint, rather than the credential name, determines the runtime.
        name: process.env.LLM_BASE_URL ? "custom" : p.name,
        apiKey: key,
        // LLM_BASE_URL / LLM_MODEL still override a named provider's defaults if set.
        baseURL: process.env.LLM_BASE_URL || p.baseURL,
        model: process.env.LLM_MODEL || p.model,
      };
    }
  }
  return null;
}

export const DEFAULT_BASE_URL = process.env.LLM_BASE_URL || PROVIDERS[0]!.baseURL;
// Default model = whatever the resolved provider chooses (LLM_MODEL override respected).
export const DEFAULT_MODEL = resolveLlmProvider()?.model ?? process.env.LLM_MODEL ?? PROVIDERS[0]!.model;

// True when a real LLM key is configured (any recognized provider). Drives auto-selection
// of the real LLM vs. the deterministic offline Fake.
export function hasLlmCreds(): boolean {
  return resolveLlmProvider() !== null;
}

export function createLlmClient(
  apiKey?: string,
  baseURL?: string
): OpenAI {
  const provider = resolveLlmProvider();
  if (provider?.auth === "aws-short-term") {
    throw new Error(
      "Bedrock Mantle clients must use the project-bound per-request token factory."
    );
  }
  return new OpenAI({
    apiKey:
      apiKey ?? (provider?.auth === "api-key" ? provider.apiKey : ""),
    baseURL: baseURL ?? provider?.baseURL ?? DEFAULT_BASE_URL,
  });
}

// ── Chat + function-calling seam (OpenAI-compatible) ──────────────────────────

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
}

export interface ToolDef {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

// A tool call the model chose. `arguments` is a JSON STRING (OpenAI contract).
export interface ToolCall {
  id?: string;
  type?: "function";
  function: { name: string; arguments: string };
}

export type ToolChoice = "auto" | "none" | "required" | { type: "function"; function: { name: string } };

export interface ChatCreateArgs {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  tools?: ToolDef[];
  tool_choice?: ToolChoice;
}

export interface ChatResponse {
  id?: unknown;
  model?: unknown;
  usage?: unknown;
  choices: Array<{ message: { content: string | null; tool_calls?: ToolCall[] } }>;
}

export interface LlmClient {
  readonly runtime: LlmRuntimeIdentity;
  chat: { completions: { create(args: ChatCreateArgs): Promise<ChatResponse> } };
}

export type OpenAiCompatibleFactory = (options: {
  apiKey: string;
  baseURL: string;
  project: string;
}) => { chat: LlmClient["chat"] };

function safeBedrockToken(token: unknown): string {
  if (
    typeof token !== "string" ||
    token.length < 32 ||
    token.length > 16_384 ||
    !token.startsWith("bedrock-api-key-") ||
    /[\u0000-\u001f\u007f]/u.test(token)
  ) {
    throw new Error("The Bedrock Mantle token provider returned an invalid token.");
  }
  return token;
}

export function assertEcsTaskRoleCredentialEnvironment(): void {
  const conflictingCredential = FORBIDDEN_TASK_ROLE_CREDENTIAL_ENVIRONMENT.find(
    (name) => process.env[name]?.trim()
  );
  if (conflictingCredential) {
    throw new Error(
      `${conflictingCredential} is forbidden for hosted Bedrock Mantle authentication.`
    );
  }
  const relativeUri = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI?.trim();
  if (
    !relativeUri ||
    !/^\/v2\/credentials\/[A-Za-z0-9-]{1,200}$/u.test(relativeUri)
  ) {
    throw new Error(
      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must identify the ECS task-role credential endpoint."
    );
  }
}

function ecsTaskRoleTokenProvider(
  provider: BedrockMantleLlmProvider
): BedrockTokenProvider {
  assertEcsTaskRoleCredentialEnvironment();
  return getTokenProvider({
    credentials: fromContainerMetadata({
      maxRetries: 2,
      timeout: 1_000,
    }),
    region: provider.region,
    expiresInSeconds: 3_600,
  });
}

export function createBedrockMantleLlmClient(
  provider: BedrockMantleLlmProvider,
  tokenProvider?: BedrockTokenProvider,
  sdkFactory: OpenAiCompatibleFactory = (options) =>
    new OpenAI(options) as unknown as { chat: LlmClient["chat"] }
): LlmClient {
  const provideToken = tokenProvider ?? ecsTaskRoleTokenProvider(provider);
  return {
    runtime: {
      source: "live-provider",
      provider: provider.name,
    },
    chat: {
      completions: {
        async create(args: ChatCreateArgs): Promise<ChatResponse> {
          if (args.model !== provider.model) {
            throw new BedrockMantleRequestError();
          }
          let tokenCandidate: string;
          try {
            tokenCandidate = await provideToken();
          } catch {
            // Do not retain the credential-provider error as a cause: SDK errors may
            // contain metadata endpoint details. Metadata and credential refresh
            // outages remain retryable, but only through this opaque error.
            throw new BedrockMantleTokenProviderUnavailableError();
          }
          let token: string;
          try {
            token = safeBedrockToken(tokenCandidate);
          } catch {
            // A provider that returned malformed credential material is a terminal
            // authentication/configuration failure, not a transient transport error.
            throw new BedrockMantleAuthenticationError();
          }
          const sdk = sdkFactory({
            apiKey: token,
            baseURL: provider.baseURL,
            project: provider.project,
          });
          return sdk.chat.completions.create(args);
        },
      },
    },
  };
}

export function chatClient(): LlmClient {
  const provider = resolveLlmProvider();
  if (!provider) {
    throw new Error("A live LLM client requires an explicitly configured provider.");
  }
  if (provider.auth === "aws-short-term") {
    return createBedrockMantleLlmClient(provider);
  }
  const sdk = createLlmClient(provider.apiKey, provider.baseURL);
  return {
    runtime: {
      source: "live-provider",
      provider: provider.name,
    },
    chat: sdk.chat as unknown as LlmClient["chat"],
  };
}
