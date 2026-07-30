// Unit tests for the LLM provider auto-detection + the Fake LLM seam.
//
// resolveLlmProvider() reads the environment to pick a real, OpenAI-compatible provider
// (Bedrock Mantle / Anthropic / Qwen / Gemini / OpenAI) or return null
// (offline → Fake). These tests are
// hermetic: they SAVE, clear, exercise, and RESTORE the relevant env vars so they never
// leak state and never depend on the machine's ambient keys.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  BEDROCK_MANTLE_BASE_URL,
  BEDROCK_MANTLE_MODEL,
  BEDROCK_MANTLE_PROVIDER,
  BEDROCK_MANTLE_REGION,
  BedrockMantleAuthenticationError,
  BedrockMantleRequestError,
  BedrockMantleTokenProviderUnavailableError,
  assertEcsTaskRoleCredentialEnvironment,
  createBedrockMantleLlmClient,
  createLlmClient,
  resolveLlmProvider,
  hasLlmCreds,
  type BedrockMantleLlmProvider,
  type LlmClient,
} from "../../src/llm/client.js";
import { FakeLlmClient } from "../../src/llm/fake.js";
import { NarratorAgent } from "../../src/agents/narrator.js";
import {
  isModelRuntimeProvenance,
  parseModelRuntimeProvenance,
} from "../../src/llm/provenance.js";

interface ModelProvenanceConformanceCase {
  id: string;
  valid: boolean;
  value: unknown;
}

const modelProvenanceCorpus = JSON.parse(
  readFileSync(
    new URL(
      "../../contracts/model-provenance-v1.cases.json",
      import.meta.url
    ),
    "utf8"
  )
) as {
  schemaVersion: string;
  credentialMacros: Record<string, string[]>;
  cases: ModelProvenanceConformanceCase[];
};

function materializeCredentialMacros(value: unknown): unknown {
  let encoded = JSON.stringify(value);
  for (const [name, fragments] of Object.entries(
    modelProvenanceCorpus.credentialMacros
  )) {
    encoded = encoded.replaceAll(
      `{{credential:${name}}}`,
      fragments.join("")
    );
  }
  return JSON.parse(encoded) as unknown;
}

const KEYS = [
  "LLM_PROVIDER",
  "LLM_API_KEY",
  "LLM_BASE_URL",
  "LLM_MODEL",
  "LLM_PROJECT_ID",
  "AWS_BEARER_TOKEN_BEDROCK",
  "AWS_REGION",
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
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "DASHSCOPE_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
];

test("authoritative model-provenance corpus matches the backend validator", () => {
  assert.equal(
    modelProvenanceCorpus.schemaVersion,
    "archon.model-provenance-conformance/v1"
  );
  assert.ok(modelProvenanceCorpus.cases.length >= 20);
  for (const candidate of modelProvenanceCorpus.cases) {
    assert.equal(
      isModelRuntimeProvenance(materializeCredentialMacros(candidate.value)),
      candidate.valid,
      candidate.id
    );
  }
});

// Run `fn` with a clean slate for all LLM env vars, restoring the prior values after.
function withEnv<T>(overrides: Record<string, string>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    for (const [k, v] of Object.entries(overrides)) process.env[k] = v;
    return fn();
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
  withEnv({ ANTHROPIC_API_KEY: "test-anthropic-key" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "anthropic");
    if (p.auth !== "api-key") {
      assert.fail("expected API-key provider");
    }
    assert.equal(p.apiKey, "test-anthropic-key");
    assert.equal(p.baseURL, "https://api.anthropic.com/v1/");
    assert.equal(p.model, "claude-opus-4-8");
    assert.equal(hasLlmCreds(), true);
  });
});

test("DASHSCOPE_API_KEY → Qwen via Alibaba Model Studio", () => {
  withEnv({ DASHSCOPE_API_KEY: "test-qwen-key" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "qwen");
    assert.equal(p.baseURL, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1");
    assert.equal(p.model, "qwen-plus");
  });
});

test("GEMINI_API_KEY → Gemini OpenAI-compatible gateway", () => {
  withEnv({ GEMINI_API_KEY: "g-key" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "gemini");
    assert.equal(p.baseURL, "https://generativelanguage.googleapis.com/v1beta/openai/");
  });
});

test("OPENAI_API_KEY → OpenAI", () => {
  withEnv({ OPENAI_API_KEY: "test-openai-key" }, () => {
    const p = resolveLlmProvider()!;
    assert.equal(p.name, "openai");
    assert.equal(p.baseURL, "https://api.openai.com/v1");
  });
});

test("LLM_API_KEY override wins over named providers + honors LLM_BASE_URL/LLM_MODEL", () => {
  withEnv(
    {
      LLM_API_KEY: "generic",
      ANTHROPIC_API_KEY: "test-anthropic-key",
      LLM_BASE_URL: "https://gateway.example/v1",
      LLM_MODEL: "custom-model",
    },
    () => {
      const p = resolveLlmProvider()!;
      assert.equal(p.name, "custom");
      if (p.auth !== "api-key") {
        assert.fail("expected API-key provider");
      }
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
  assert.equal(call.function.arguments, "{}");
});

test("Bedrock Mantle configuration resolves only the pinned regional provider", () => {
  withEnv(
    {
      LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
      AWS_REGION: BEDROCK_MANTLE_REGION,
      LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
      LLM_MODEL: BEDROCK_MANTLE_MODEL,
      LLM_PROJECT_ID: "proj_archonstaging001",
    },
    () => {
      assert.deepEqual(resolveLlmProvider(), {
        auth: "aws-short-term",
        name: BEDROCK_MANTLE_PROVIDER,
        region: BEDROCK_MANTLE_REGION,
        baseURL: BEDROCK_MANTLE_BASE_URL,
        model: BEDROCK_MANTLE_MODEL,
        project: "proj_archonstaging001",
      });
      assert.equal(hasLlmCreds(), true);
    }
  );
});

test("Bedrock Mantle accepts only the ECS task-role credential endpoint", () => {
  const relativeUri =
    "/v2/credentials/12345678-90ab-cdef-1234-567890abcdef";
  withEnv(
    { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: relativeUri },
    assertEcsTaskRoleCredentialEnvironment
  );

  for (const credentialName of [
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
  ] as const) {
    withEnv(
      {
        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: relativeUri,
        [credentialName]: "forbidden-ambient-credential",
      },
      () => {
        assert.throws(
          assertEcsTaskRoleCredentialEnvironment,
          new RegExp(`${credentialName} is forbidden`, "u")
        );
      }
    );
  }

  for (const relativeUriCandidate of [
    "",
    "/latest/meta-data/iam/security-credentials/role",
    "/v2/credentials/../../escape",
    "http://169.254.170.2/v2/credentials/id",
  ]) {
    withEnv(
      relativeUriCandidate
        ? { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: relativeUriCandidate }
        : {},
      () => {
        assert.throws(
          assertEcsTaskRoleCredentialEnvironment,
          /must identify the ECS task-role credential endpoint/u
        );
      }
    );
  }
});

test("Bedrock Mantle cannot bypass project binding with an injected token", () => {
  withEnv(
    {
      LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
      AWS_REGION: BEDROCK_MANTLE_REGION,
      LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
      LLM_MODEL: BEDROCK_MANTLE_MODEL,
      LLM_PROJECT_ID: "proj_archonstaging001",
    },
    () => {
      assert.throws(
        () =>
          createLlmClient(
            `bedrock-api-key-${"a".repeat(64)}`,
            BEDROCK_MANTLE_BASE_URL
          ),
        /project-bound per-request token factory/u
      );
    }
  );
});

test("Bedrock Mantle rejects ambient tokens, static keys, and configuration drift", () => {
  const baseline = {
    LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
    AWS_REGION: BEDROCK_MANTLE_REGION,
    LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
    LLM_MODEL: BEDROCK_MANTLE_MODEL,
    LLM_PROJECT_ID: "proj_archonstaging001",
  };
  for (const [name, overrides, pattern] of [
    [
      "ambient token",
      { AWS_BEARER_TOKEN_BEDROCK: "bedrock-api-key-static" },
      /AWS_BEARER_TOKEN_BEDROCK is forbidden/u,
    ],
    ["generic key", { LLM_API_KEY: "static-key" }, /LLM_API_KEY is forbidden/u],
    ["region drift", { AWS_REGION: "us-east-1" }, /AWS_REGION must be/u],
    [
      "endpoint drift",
      { LLM_BASE_URL: "https://gateway.example/v1" },
      /LLM_BASE_URL must be/u,
    ],
    ["model drift", { LLM_MODEL: "qwen.other" }, /LLM_MODEL must be/u],
    [
      "project drift",
      { LLM_PROJECT_ID: "default" },
      /LLM_PROJECT_ID must identify/u,
    ],
  ] as const) {
    withEnv({ ...baseline, ...overrides }, () => {
      assert.throws(resolveLlmProvider, pattern, name);
    });
  }
});

test("Bedrock Mantle mints a validated short-term token for every request", async () => {
  const provider = withEnv(
    {
      LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
      AWS_REGION: BEDROCK_MANTLE_REGION,
      LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
      LLM_MODEL: BEDROCK_MANTLE_MODEL,
      LLM_PROJECT_ID: "proj_archonstaging001",
    },
    () => resolveLlmProvider()
  ) as BedrockMantleLlmProvider;
  const tokens = [
    `bedrock-api-key-${"a".repeat(64)}`,
    `bedrock-api-key-${"b".repeat(64)}`,
  ];
  const observed: Array<{
    apiKey: string;
    baseURL: string;
    project: string;
  }> = [];
  const client = createBedrockMantleLlmClient(
    provider,
    async () => tokens.shift()!,
    (options) => {
      observed.push(options);
      return {
        chat: {
          completions: {
            async create() {
              return {
                choices: [{ message: { content: "bounded" } }],
              };
            },
          },
        },
      };
    }
  );
  const request = {
    model: BEDROCK_MANTLE_MODEL,
    messages: [{ role: "user" as const, content: "evidence" }],
  };
  await client.chat.completions.create(request);
  await client.chat.completions.create(request);
  assert.deepEqual(observed, [
    {
      apiKey: `bedrock-api-key-${"a".repeat(64)}`,
      baseURL: BEDROCK_MANTLE_BASE_URL,
      project: "proj_archonstaging001",
    },
    {
      apiKey: `bedrock-api-key-${"b".repeat(64)}`,
      baseURL: BEDROCK_MANTLE_BASE_URL,
      project: "proj_archonstaging001",
    },
  ]);
  assert.deepEqual(client.runtime, {
    source: "live-provider",
    provider: BEDROCK_MANTLE_PROVIDER,
  });
});

test("Bedrock Mantle rejects model drift before token minting or transport", async () => {
  const provider: BedrockMantleLlmProvider = {
    auth: "aws-short-term",
    name: BEDROCK_MANTLE_PROVIDER,
    region: BEDROCK_MANTLE_REGION,
    baseURL: BEDROCK_MANTLE_BASE_URL,
    model: BEDROCK_MANTLE_MODEL,
    project: "proj_archonstaging001",
  };
  let tokenCalls = 0;
  let transportCalls = 0;
  const client = createBedrockMantleLlmClient(
    provider,
    async () => {
      tokenCalls += 1;
      return `bedrock-api-key-${"a".repeat(64)}`;
    },
    () => {
      transportCalls += 1;
      throw new Error("transport must not be created");
    }
  );
  await assert.rejects(
    client.chat.completions.create({
      model: "qwen.unapproved",
      messages: [{ role: "user", content: "evidence" }],
    }),
    (error: unknown) =>
      error instanceof BedrockMantleRequestError && error.status === 400
  );
  assert.equal(tokenCalls, 0);
  assert.equal(transportCalls, 0);
});

test("Bedrock Mantle fails closed before transport on a malformed token", async () => {
  const provider: BedrockMantleLlmProvider = {
    auth: "aws-short-term",
    name: BEDROCK_MANTLE_PROVIDER,
    region: BEDROCK_MANTLE_REGION,
    baseURL: BEDROCK_MANTLE_BASE_URL,
    model: BEDROCK_MANTLE_MODEL,
    project: "proj_archonstaging001",
  };
  let transportCreated = false;
  const client = createBedrockMantleLlmClient(
    provider,
    async () => "malformed-secret-token",
    () => {
      transportCreated = true;
      throw new Error("transport must not be created");
    }
  );
  await assert.rejects(
    client.chat.completions.create({
      model: BEDROCK_MANTLE_MODEL,
      messages: [{ role: "user", content: "evidence" }],
    }),
    (error: unknown) =>
      error instanceof BedrockMantleAuthenticationError &&
      error.status === 401 &&
      error.message ===
        "Unable to mint a valid short-term Bedrock Mantle token from the AWS task role." &&
      error.cause === undefined
  );
  assert.equal(transportCreated, false);
});

test("Bedrock Mantle sanitizes a transient task-role provider outage", async () => {
  const provider: BedrockMantleLlmProvider = {
    auth: "aws-short-term",
    name: BEDROCK_MANTLE_PROVIDER,
    region: BEDROCK_MANTLE_REGION,
    baseURL: BEDROCK_MANTLE_BASE_URL,
    model: BEDROCK_MANTLE_MODEL,
    project: "proj_archonstaging001",
  };
  const client = createBedrockMantleLlmClient(provider, async () => {
    throw new Error(
      "http://169.254.170.2/private-metadata?token=must-not-escape"
    );
  });
  await assert.rejects(
    client.chat.completions.create({
      model: BEDROCK_MANTLE_MODEL,
      messages: [{ role: "user", content: "evidence" }],
    }),
    (error: unknown) =>
      error instanceof BedrockMantleTokenProviderUnavailableError &&
      error.retryable === true &&
      error.status === 503 &&
      error.cause === undefined &&
      !error.message.includes("169.254.170.2")
  );
});

test("a named credential routed through LLM_BASE_URL is provenance-classed as custom", () => {
  withEnv(
    {
      DASHSCOPE_API_KEY: "q",
      LLM_BASE_URL: "https://gateway.example/v1",
    },
    () => {
      const provider = resolveLlmProvider()!;
      assert.equal(provider.name, "custom");
      assert.equal(provider.baseURL, "https://gateway.example/v1");
    }
  );
});

test("live narration emits only strict, bounded provider provenance", async () => {
  const SENTINEL = "provider-secret-must-not-be-exported";
  const client: LlmClient = {
    runtime: { source: "live-provider", provider: "openai" },
    chat: {
      completions: {
        create: async () => ({
          id: "chatcmpl-safe-response-001",
          model: "gpt-4o-mini-2026-07-01",
          usage: {
            prompt_tokens: 40,
            completion_tokens: 12,
            total_tokens: 52,
            raw_provider_payload: SENTINEL,
          },
          choices: [
            {
              message: {
                content: "A bounded provider-authored summary.",
                tool_calls: undefined,
              },
            },
          ],
          raw_provider_payload: SENTINEL,
        }),
      },
    },
  };
  const clock = [100, 137];
  const result = await new NarratorAgent(
    client,
    "gpt-4o-mini",
    () => clock.shift()!
  ).summarize([], {
    totalEntities: 1,
    withLineage: 0,
    sensitiveEntities: 0,
    domains: {},
    platforms: {},
  });

  assert.deepEqual(result.modelProvenance, {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "live-provider",
    modelCall: true,
    provider: "openai",
    requestedModel: "gpt-4o-mini",
    returnedModel: "gpt-4o-mini-2026-07-01",
    providerResponseId: "chatcmpl-safe-response-001",
    tokenUsage: {
      inputTokens: 40,
      outputTokens: 12,
      totalTokens: 52,
    },
    latencyMs: 37,
  });
  assert.doesNotMatch(JSON.stringify(result.modelProvenance), new RegExp(SENTINEL));
});

test("model provenance rejects mode confusion, unexpected fields, and malformed usage", () => {
  const deterministic = {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "deterministic-fixture",
    modelCall: false,
    provider: "fixture",
    requestedModel: "archon-deterministic-fixture-narrator-v1",
    returnedModel: null,
    providerResponseId: null,
    tokenUsage: null,
    latencyMs: null,
  };
  assert.deepEqual(parseModelRuntimeProvenance(deterministic), deterministic);
  assert.equal(
    isModelRuntimeProvenance({ ...deterministic, prompt: "must not be accepted" }),
    false
  );
  assert.equal(
    isModelRuntimeProvenance({
      ...deterministic,
      source: "live-provider",
      modelCall: true,
      provider: "openai",
    }),
    false
  );
  assert.equal(
    isModelRuntimeProvenance({
      ...deterministic,
      source: "live-provider",
      modelCall: true,
      provider: "openai",
      returnedModel: "gpt-4o-mini",
      providerResponseId: "chatcmpl-safe-001",
      tokenUsage: { inputTokens: 5, outputTokens: 2, totalTokens: 99 },
      latencyMs: 12,
    }),
    false
  );
  assert.equal(
    isModelRuntimeProvenance({
      ...deterministic,
      source: "live-provider",
      modelCall: true,
      provider: "custom",
      returnedModel: "custom-model",
      providerResponseId: `sk-${"x".repeat(32)}`,
      tokenUsage: null,
      latencyMs: 12,
    }),
    false
  );
  assert.equal(
    isModelRuntimeProvenance({
      ...deterministic,
      source: "live-provider",
      modelCall: true,
      provider: "custom",
      returnedModel: `model_sk-${"x".repeat(32)}`,
      providerResponseId: "response-safe-001",
      tokenUsage: null,
      latencyMs: 12,
    }),
    false
  );
  assert.equal(
    isModelRuntimeProvenance({
      ...deterministic,
      source: "live-provider",
      modelCall: true,
      provider: "custom",
      returnedModel: "custom-model",
      providerResponseId: `resp_sk-${"x".repeat(32)}`,
      tokenUsage: null,
      latencyMs: 12,
    }),
    false
  );
});

test("live narration fails closed when provider identity metadata is absent", async () => {
  const client: LlmClient = {
    runtime: { source: "live-provider", provider: "custom" },
    chat: {
      completions: {
        create: async () => ({
          choices: [{ message: { content: "No provider identity." } }],
        }),
      },
    },
  };
  await assert.rejects(
    new NarratorAgent(client, "custom-model", () => 1).summarize([], {
      totalEntities: 0,
      withLineage: 0,
      sensitiveEntities: 0,
      domains: {},
      platforms: {},
    }),
    /provenance is absent or invalid/iu
  );
});
