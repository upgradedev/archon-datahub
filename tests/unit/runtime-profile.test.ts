import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RuntimeSelectionError,
  assertPinnedRuntime,
  isRuntimeReady,
  runtimeCapabilityDigest,
  selectRuntime,
  validateRuntimeBinding,
  type RuntimeCapabilities,
  type RuntimeProfileSnapshot,
  type RuntimeBinding,
} from "../../src/datahub/runtime-profile.js";

const NOW = "2026-08-02T08:00:00.000Z";
const EXPIRES = "2026-08-02T08:30:00.000Z";

const allCapabilities: RuntimeCapabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true,
};

function snapshot(
  profileId: "cloud" | "core",
  overrides: Partial<RuntimeProfileSnapshot> = {}
): RuntimeProfileSnapshot {
  return {
    profileId,
    generation: `${profileId}-20260802-1`,
    status: "ready",
    checkedAt: "2026-08-02T07:59:45.000Z",
    capabilities: { ...allCapabilities },
    ...overrides,
  };
}

test("Auto prefers a fully capable healthy DataHub Cloud profile", () => {
  const binding = selectRuntime(
    "auto",
    [snapshot("core"), snapshot("cloud")],
    { now: NOW, leaseExpiresAt: EXPIRES }
  );
  assert.equal(binding.profileId, "cloud");
  assert.equal(binding.resolution, "auto");
  assert.equal(Object.isFrozen(binding), true);
  assert.match(binding.capabilityDigest, /^sha256:[a-f0-9]{64}$/u);
});

test("Auto selects Core before execution when Cloud is not ready", () => {
  const binding = selectRuntime(
    "auto",
    [
      snapshot("cloud", { status: "starting" }),
      snapshot("core"),
    ],
    { now: NOW, leaseExpiresAt: EXPIRES }
  );
  assert.equal(binding.profileId, "core");
});

test("an explicit Cloud request never silently falls back to Core", () => {
  assert.throws(
    () =>
      selectRuntime(
        "cloud",
        [
          snapshot("cloud", { status: "unavailable" }),
          snapshot("core"),
        ],
        { now: NOW, leaseExpiresAt: EXPIRES }
      ),
    (error: unknown) =>
      error instanceof RuntimeSelectionError &&
      error.code === "RUNTIME_NOT_READY"
  );
});

test("all four DataHub components plus governed MCP write are required", () => {
  const incomplete = snapshot("cloud", {
    capabilities: { ...allCapabilities, analyticsAgent: false },
  });
  assert.equal(isRuntimeReady(incomplete, NOW), false);
  assert.throws(
    () =>
      selectRuntime("auto", [incomplete], {
        now: NOW,
        leaseExpiresAt: EXPIRES,
      }),
    (error: unknown) =>
      error instanceof RuntimeSelectionError &&
      error.code === "NO_RUNTIME_AVAILABLE"
  );
});

test("stale or future health cannot resolve a judge session", () => {
  assert.equal(
    isRuntimeReady(
      snapshot("cloud", { checkedAt: "2026-08-02T07:58:00.000Z" }),
      NOW
    ),
    false
  );
  assert.equal(
    isRuntimeReady(
      snapshot("cloud", { checkedAt: "2026-08-02T08:00:01.000Z" }),
      NOW
    ),
    false
  );
});

test("capability digests bind profile, generation, and exact capabilities", () => {
  const original = snapshot("core");
  const nextGeneration = snapshot("core", { generation: "core-20260802-2" });
  const reduced = snapshot("core", {
    capabilities: { ...allCapabilities, dataHubSkills: false },
  });
  assert.notEqual(
    runtimeCapabilityDigest(original),
    runtimeCapabilityDigest(nextGeneration)
  );
  assert.notEqual(
    runtimeCapabilityDigest(original),
    runtimeCapabilityDigest(reduced)
  );
});

test("runtime bindings contain no endpoint, token, secret, or credential", () => {
  const binding = selectRuntime("core", [snapshot("core")], {
    now: NOW,
    leaseExpiresAt: EXPIRES,
  });
  const serialized = JSON.stringify(binding);
  assert.doesNotMatch(
    serialized,
    /(?:https?:\/\/|token|secret|credential|endpoint)/iu
  );
  assert.deepEqual(Object.keys(binding).sort(), [
    "boundAt",
    "capabilityDigest",
    "generation",
    "leaseExpiresAt",
    "profileId",
    "resolution",
    "schemaVersion",
  ]);
});

test("a pinned binding rejects profile, generation, or capability drift", () => {
  const expected = selectRuntime("cloud", [snapshot("cloud")], {
    now: NOW,
    leaseExpiresAt: EXPIRES,
  });
  assert.doesNotThrow(() => assertPinnedRuntime(expected, expected));
  for (const actual of [
    { ...expected, profileId: "core" as const },
    { ...expected, generation: "cloud-20260802-2" },
    {
      ...expected,
      capabilityDigest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const,
    },
    { ...expected, resolution: "auto" as const },
  ]) {
    assert.throws(
      () => assertPinnedRuntime(expected, actual),
      (error: unknown) =>
        error instanceof RuntimeSelectionError &&
        error.code === "RUNTIME_BINDING_MISMATCH"
    );
  }
});

test("duplicate profiles, noncanonical instants, and long leases fail closed", () => {
  assert.throws(
    () =>
      selectRuntime("auto", [snapshot("cloud"), snapshot("cloud")], {
        now: NOW,
        leaseExpiresAt: EXPIRES,
      }),
    /duplicate runtime snapshot/
  );
  assert.throws(
    () =>
      selectRuntime("auto", [snapshot("cloud")], {
        now: "2026-08-02T08:00:00Z",
        leaseExpiresAt: EXPIRES,
      }),
    /exact ISO-8601/
  );
  assert.throws(
    () =>
      selectRuntime("auto", [snapshot("cloud")], {
        now: NOW,
        leaseExpiresAt: "2026-08-02T10:00:00.001Z",
      }),
    /two-hour ceiling/
  );
});

test("runtime binding validation rejects extra fields and malformed leases", () => {
  const binding = selectRuntime("core", [snapshot("core")], {
    now: NOW,
    leaseExpiresAt: EXPIRES,
  });
  const validated = validateRuntimeBinding(binding);
  assert.equal(Object.isFrozen(validated), true);

  const invalid: unknown[] = [
    { ...binding, endpoint: "https://forbidden.example" },
    { ...binding, boundAt: "2026-08-02T08:00:00Z" },
    { ...binding, leaseExpiresAt: binding.boundAt },
    {
      ...binding,
      leaseExpiresAt: "2026-08-02T10:00:00.001Z",
    },
    { ...binding, resolution: "fallback" },
  ];
  for (const candidate of invalid) {
    assert.throws(
      () => validateRuntimeBinding(candidate as RuntimeBinding),
      (error: unknown) =>
        error instanceof RuntimeSelectionError &&
        error.code === "INVALID_RUNTIME_BINDING"
    );
  }
  const symbolBinding = { ...binding } as RuntimeBinding & Record<symbol, boolean>;
  symbolBinding[Symbol("hidden")] = true;
  assert.throws(
    () => validateRuntimeBinding(symbolBinding),
    (error: unknown) =>
      error instanceof RuntimeSelectionError &&
      error.code === "INVALID_RUNTIME_BINDING"
  );
});

test("pinned runtime rejects resolution drift and identical malformed bindings", () => {
  const expected = selectRuntime("cloud", [snapshot("cloud")], {
    now: NOW,
    leaseExpiresAt: EXPIRES,
  });
  assert.throws(
    () =>
      assertPinnedRuntime(expected, {
        ...expected,
        resolution: "auto",
      }),
    (error: unknown) =>
      error instanceof RuntimeSelectionError &&
      error.code === "RUNTIME_BINDING_MISMATCH"
  );

  const malformed = {
    ...expected,
    boundAt: "2026-08-02T08:00:00Z",
  } as RuntimeBinding;
  assert.throws(
    () => assertPinnedRuntime(malformed, malformed),
    (error: unknown) =>
      error instanceof RuntimeSelectionError &&
      error.code === "RUNTIME_BINDING_MISMATCH"
  );
});

test("runtime snapshot and selection object shapes fail closed at runtime", () => {
  assert.throws(
    () =>
      selectRuntime(
        "auto",
        [null as unknown as RuntimeProfileSnapshot],
        { now: NOW, leaseExpiresAt: EXPIRES }
      ),
    /runtime snapshot must be an object/
  );
  assert.throws(
    () =>
      isRuntimeReady(
        {
          ...snapshot("cloud"),
          capabilities: null as unknown as RuntimeCapabilities,
        },
        NOW
      ),
    /runtime capabilities must be an object/
  );
  assert.throws(
    () =>
      selectRuntime("auto", [snapshot("cloud")], {
        now: NOW,
        leaseExpiresAt: EXPIRES,
        endpoint: "forbidden",
      } as never),
    /exact schema/
  );
});