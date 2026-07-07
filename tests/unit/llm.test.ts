// Unit tests for the LLM provider auto-detection + the Fake LLM seam.
//
// resolveLlmProvider() reads the environment to pick a real, OpenAI-compatible provider
// (Anthropic / Qwen / Gemini / OpenAI) or return null (offline → Fake). These tests are
// hermetic: they SAVE, clear, exercise, and RESTORE the relevant env vars so they never
// leak state and never depend on the machine's ambient keys.

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLlmProvider, hasLlmCreds } from "../../src/llm/client.js";
import { FakeLlmClient } from "../../src/llm/fake.js";

const KEYS = [
  "LLM_API_KEY",
  "LLM_BASE_URL",
  "LLM_MODEL",
  "DASHSCOPE_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
];

// Run `fn` with a clean slate for all LLM env vars, restoring the prior values after.
function withEnv(overrides: Record<string, string>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    for (const [k, v] of Object.entries(overrides)) process.env[k] = v;
    fn();
  } finally {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
  }
}

test("no keys → offline (null provider, hasLlmCreds false)", () => {
  withEnv({}, () => {
    assert.equal(resolveLlmProvider(), null);
    assert.equal(hasLlmCreds(), false);
  });
});

test("ANTHROPIC_API_KEY → Anthropic OpenAI-compatible endpoint + claude-opus-4-8", () => {
  withEnv({ ANTHROPIC_API_KEY: "sk-ant-xxx" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "anthropic");
    assert.equal(p.apiKey, "sk-ant-xxx");
    assert.equal(p.baseURL, "https://api.anthropic.com/v1/");
    assert.equal(p.model, "claude-opus-4-8");
    assert.equal(hasLlmCreds(), true);
  });
});

test("DASHSCOPE_API_KEY → Qwen via Alibaba Model Studio", () => {
  withEnv({ DASHSCOPE_API_KEY: "sk-qwen" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "qwen");
    assert.match(p.baseURL, /dashscope/);
    assert.equal(p.model, "qwen-plus");
  });
});

test("GEMINI_API_KEY → Gemini OpenAI-compatible gateway", () => {
  withEnv({ GEMINI_API_KEY: "g-key" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "gemini");
    assert.match(p.baseURL, /generativelanguage\.googleapis\.com/);
  });
});

test("OPENAI_API_KEY → OpenAI", () => {
  withEnv({ OPENAI_API_KEY: "sk-oa" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "openai");
    assert.equal(p.baseURL, "https://api.openai.com/v1");
  });
});

test("LLM_API_KEY override wins over named providers + honors LLM_BASE_URL/LLM_MODEL", () => {
  withEnv(
    {
      LLM_API_KEY: "generic",
      ANTHROPIC_API_KEY: "sk-ant",
      LLM_BASE_URL: "https://gateway.example/v1",
      LLM_MODEL: "custom-model",
    },
    () => {
      const p = resolveLlmProvider()!;
      assert.equal(p.name, "custom");
      assert.equal(p.apiKey, "generic");
      assert.equal(p.baseURL, "https://gateway.example/v1");
      assert.equal(p.model, "custom-model");
    }
  );
});

test("named-provider precedence is deterministic (Qwen before OpenAI before Anthropic)", () => {
  withEnv({ DASHSCOPE_API_KEY: "q", OPENAI_API_KEY: "o", ANTHROPIC_API_KEY: "a" }, () => {
    assert.equal(resolveLlmProvider()!.name, "qwen");
  });
});

test("Fake LLM narrates deterministically from the evidence line (no key, offline)", async () => {
  const fake = new FakeLlmClient();
  const res = await fake.chat.completions.create({
    model: "fake",
    messages: [
      { role: "user", content: "EVIDENCE: contradictions=2 lineage_gaps=1 governance_violations=3" },
    ],
  });
  const text = res.choices[0]!.message.content!;
  assert.match(text, /6 finding/); // 2 + 1 + 3
});

test("Fake LLM returns a tool_call when the request carries tools (ReAct path)", async () => {
  const fake = new FakeLlmClient();
  const res = await fake.chat.completions.create({
    model: "fake",
    messages: [{ role: "user", content: "EVIDENCE: harvested=false" }],
    tools: [{ type: "function", function: { name: "harvest_catalog", description: "", parameters: {} } }],
  });
  const call = res.choices[0]!.message.tool_calls![0]!;
  assert.equal(call.function.name, "harvest_catalog");
});
