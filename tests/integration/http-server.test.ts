import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createArchonHttpServer } from "../../src/http/server.js";
import {
  FakeDataHubMcpClient,
  type DataHubClient,
} from "../../src/datahub/mcp-client.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { DataHubHarvestError } from "../../src/datahub/harvest-policy.js";

async function withServer(
  run: (baseUrl: string) => Promise<void>,
  datahub: DataHubClient = new FakeDataHubMcpClient()
): Promise<void> {
  const server = createArchonHttpServer({
    datahub,
    pipeline: new AuditPipeline(),
    releaseSha: "test-sha",
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  }
}

test("HTTP health contract is small, secured, and release-bound", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), { status: "ok", releaseSha: "test-sha" });
  });
});

test("HTTP preview returns a controlled error when a live query exceeds its ceiling", async () => {
  class TooBroadClient extends FakeDataHubMcpClient {
    override async harvestAudit(): Promise<never> {
      throw new DataHubHarvestError(
        "SEARCH_LIMIT_EXCEEDED",
        "provider detail must not be returned"
      );
    }
  }
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/audits`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "too-broad" }),
    });
    assert.equal(response.status, 422);
    assert.deepEqual(await response.json(), {
      error: "audit_scope_too_broad",
      requestId: response.headers.get("x-request-id"),
    });
  }, new TooBroadClient());
});

test("POST /api/audits drives the real pipeline through the HTTP boundary", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/audits`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "sales" }),
    });
    assert.equal(response.status, 200);
    const body = (await response.json()) as {
      releaseSha: string;
      report: { findings: unknown[]; trace: unknown[] };
    };
    assert.equal(body.releaseSha, "test-sha");
    assert.ok(body.report.findings.length > 0);
    assert.equal(body.report.trace.length, 4);
  });
});

test("HTTP boundary rejects wrong methods, media types, and oversized/control input", async () => {
  await withServer(async (baseUrl) => {
    assert.equal((await fetch(`${baseUrl}/api/audits`)).status, 405);
    assert.equal(
      (
        await fetch(`${baseUrl}/api/audits`, {
          method: "POST",
          body: "{}",
        })
      ).status,
      415
    );
    assert.equal(
      (
        await fetch(`${baseUrl}/api/audits`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: "x".repeat(257) }),
        })
      ).status,
      400
    );
    assert.equal(
      (
        await fetch(`${baseUrl}/api/audits`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        })
      ).status,
      400
    );
    assert.equal(
      (
        await fetch(`${baseUrl}/api/audits`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: "*" }),
        })
      ).status,
      400
    );
  });
});
