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

export const DEFAULT_BASE_URL =
  process.env.LLM_BASE_URL || "https://dashscope-intl.aliyuncs.com/compatible-mode/v1";
export const DEFAULT_MODEL = process.env.LLM_MODEL || "qwen-plus";

// True when a real LLM key is configured. Drives auto-selection of real LLM vs. the
// deterministic offline Fake.
export function hasLlmCreds(): boolean {
  return Boolean(process.env.LLM_API_KEY);
}

export function createLlmClient(
  apiKey: string = process.env.LLM_API_KEY ?? "",
  baseURL: string = DEFAULT_BASE_URL
): OpenAI {
  return new OpenAI({ apiKey, baseURL });
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
