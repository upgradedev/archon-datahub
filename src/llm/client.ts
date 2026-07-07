// LLM client seam — one OpenAI-compatible entry point, provider-agnostic.
//
// The narrator (executive summary) and the optional ReAct loop talk to an LLM through
// this single OpenAI-compatible surface, so ANY provider works unchanged: Qwen via
// Alibaba Model Studio (DashScope), OpenAI, or Gemini behind an OpenAI-compatible
// gateway. Auth + endpoint come from the environment (LLM_API_KEY / LLM_BASE_URL /
// LLM_MODEL). With NO key configured the agent auto-falls back to the deterministic
// FakeLlmClient (src/llm/fake.ts), so every code path — including the function-calling
// tool-call parse — runs offline in CI with zero secrets and zero spend.
//
// The minimal interfaces below are the ONLY surface the narrator + loop need. The real
// `openai` client satisfies them, and the Fake satisfies them in tests.

import OpenAI from "openai";

// ── Provider auto-detection (OpenAI-compatible, provider-agnostic) ────────────
//
// The narrator + optional ReAct loop talk to an LLM through ONE OpenAI-compatible surface,
// so any provider works unchanged. We detect which real model to use from the environment,
// in a DETERMINISTIC precedence order, and route the base URL + default model accordingly.
// Each provider below exposes an OpenAI-compatible `/chat/completions` endpoint:
//   • LLM_API_KEY      — generic override (honors LLM_BASE_URL / LLM_MODEL); wins outright.
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

export interface LlmProvider {
  name: string;
  apiKey: string;
  baseURL: string;
  model: string;
}

interface ProviderSpec {
  env: string;
  name: string;
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
  // Generic override wins: an explicit LLM_API_KEY (+ optional LLM_BASE_URL / LLM_MODEL).
  const override = process.env.LLM_API_KEY;
  if (override) {
    return {
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
        name: p.name,
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
  return new OpenAI({
    apiKey: apiKey ?? provider?.apiKey ?? "",
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
  choices: Array<{ message: { content: string | null; tool_calls?: ToolCall[] } }>;
}

export interface LlmClient {
  chat: { completions: { create(args: ChatCreateArgs): Promise<ChatResponse> } };
}

export function chatClient(): LlmClient {
  return createLlmClient() as unknown as LlmClient;
}
