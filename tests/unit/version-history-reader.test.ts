import { test } from "node:test";
import assert from "node:assert/strict";
import {
  readAspectVersionHistory,
  VersionHistoryReadError,
} from "../../src/datahub/version-history-reader.js";
import { auditVersionHistory } from "../../src/datahub/version-history.js";

const URN = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function versionFrom(input: string | URL | Request): number {
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  return Number(new URL(raw).searchParams.get("version"));
}

test("reader combines current v0 with retained history and enables an A→B audit", async () => {
  const requested: number[] = [];
  const fetchFn = (async (input: string | URL | Request) => {
    const version = versionFrom(input);
    requested.push(version);
    if (version === 0) {
      return jsonResponse({
        ownership: {
          value: { owners: [{ owner: "urn:li:corpGroup:ops" }] },
          systemMetadata: {
            version: "2",
            lastObserved: 2,
            runId: "dbt-run-2",
            pipelineName: "dbt-prod",
          },
        },
      });
    }
    if (version === 1) {
      return jsonResponse({
        ownership: {
          value: { owners: [{ owner: "urn:li:corpGroup:finance" }] },
          systemMetadata: {
            version: "1",
            lastObserved: 1,
            runId: "snowflake-run-1",
            pipelineName: "snowflake-prod",
          },
        },
      });
    }
    return jsonResponse({ message: "not found" }, 404);
  }) as typeof fetch;

  const versions = await readAspectVersionHistory(
    "https://datahub.example",
    "secret",
    URN,
    "ownership",
    { fetchFn }
  );

  assert.deepEqual(requested, [0, 1, 2], "v0 must be read before retained versions");
  assert.equal(versions.length, 2);
  assert.equal(
    (versions[1]!.value!["owners"] as Array<{ owner: string }>)[0]!.owner,
    "urn:li:corpGroup:ops",
    "current v0 is retained in the assembled history"
  );
  assert.equal(
    auditVersionHistory([{ urn: URN, aspect: "ownership", versions }]).contradictions.length,
    1
  );
});

test("reader exposes current-only state when DataHub retention has no historical row", async () => {
  const fetchFn = (async (input: string | URL | Request) => {
    if (versionFrom(input) === 0) {
      return jsonResponse({
        ownership: {
          value: { owners: [{ owner: "urn:li:corpGroup:finance" }] },
          systemMetadata: {
            version: "1",
            runId: "run-1",
            pipelineName: "snowflake-prod",
          },
        },
      });
    }
    return jsonResponse({}, 404);
  }) as typeof fetch;

  const versions = await readAspectVersionHistory(
    "https://datahub.example",
    undefined,
    URN,
    "ownership",
    { fetchFn }
  );
  assert.equal(versions.length, 1, "callers can fail readiness when retention depth is <2");
});

test("reader fails closed on auth/server errors instead of returning partial history", async () => {
  for (const status of [401, 403, 500]) {
    const fetchFn = (async () => jsonResponse({ error: "nope" }, status)) as typeof fetch;
    await assert.rejects(
      readAspectVersionHistory(
        "https://datahub.example",
        "bad-token",
        URN,
        "ownership",
        { fetchFn }
      ),
      (error: unknown) =>
        error instanceof VersionHistoryReadError &&
        error.code === "HTTP_ERROR" &&
        error.status === status
    );
  }
});

test("reader refuses a truncated audit when the configured history bound is exceeded", async () => {
  const fetchFn = (async () =>
    jsonResponse({
      ownership: {
        value: { owners: [{ owner: "urn:li:corpGroup:a" }] },
        systemMetadata: { runId: "run", pipelineName: "pipeline" },
      },
    })) as typeof fetch;

  await assert.rejects(
    readAspectVersionHistory(
      "https://datahub.example",
      undefined,
      URN,
      "ownership",
      { fetchFn, maxHistoricalVersions: 2 }
    ),
    (error: unknown) =>
      error instanceof VersionHistoryReadError &&
      error.code === "HISTORY_LIMIT_EXCEEDED"
  );
});

test("reader composes the hosted harvest deadline into every version request", async () => {
  const outer = new AbortController();
  const observedSignals: AbortSignal[] = [];
  const fetchFn = (async (
    input: string | URL | Request,
    init?: RequestInit
  ) => {
    assert.ok(init?.signal instanceof AbortSignal);
    observedSignals.push(init.signal);
    if (versionFrom(input) === 0) {
      return jsonResponse({
        ownership: {
          value: { owners: [] },
          systemMetadata: { pipelineName: "demo" },
        },
      });
    }
    return jsonResponse({}, 404);
  }) as typeof fetch;

  await readAspectVersionHistory(
    "https://datahub.example",
    undefined,
    URN,
    "ownership",
    {
      fetchFn,
      signal: outer.signal,
      requestTimeoutMs: 1_000,
      maxHistoricalVersions: 1,
    }
  );
  assert.equal(observedSignals.length, 2);
  outer.abort();
  assert.ok(observedSignals.every((signal) => signal.aborted));
});
