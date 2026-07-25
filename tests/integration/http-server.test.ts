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
  datahub: DataHubClient = new FakeDataHubMcpClient(),
  demoQuery?: string
): Promise<void> {
  const server = createArchonHttpServer({
    datahub,
    pipeline: new AuditPipeline(),
    releaseSha: "test-sha",
    ...(demoQuery === undefined ? {} : { demoQuery }),
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

for (const code of ["SEARCH_LIMIT_EXCEEDED", "SCHEMA_LIMIT_EXCEEDED"] as const) {
  test(`HTTP preview returns a controlled error when ${code} exceeds its ceiling`, async () => {
    class TooBroadClient extends FakeDataHubMcpClient {
      override async harvestAudit(): Promise<never> {
        throw new DataHubHarvestError(
          code,
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
}

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
    assert.ok(
      (
        body.report.findings as Array<{
          detail: Record<string, unknown>;
        }>
      ).every(
        (finding) =>
          !Object.hasOwn(finding.detail, "values") &&
          !Object.hasOwn(finding.detail, "resolution") &&
          !Object.hasOwn(finding.detail, "sensitiveFields")
      )
    );
  });
});

test("hosted HTTP audit permits only the exact configured public demo query", async () => {
  await withServer(
    async (baseUrl) => {
      const rejected = await fetch(`${baseUrl}/api/audits`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "customer_pii" }),
      });
      assert.equal(rejected.status, 400);
      const rejectedBody = (await rejected.json()) as {
        error: string;
        message: string;
      };
      assert.equal(rejectedBody.error, "invalid_request");
      assert.equal(
        rejectedBody.message,
        "query is outside the configured public demo scope"
      );

      const accepted = await fetch(`${baseUrl}/api/audits`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "sales" }),
      });
      assert.equal(accepted.status, 200);

      const padded = await fetch(`${baseUrl}/api/audits`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: " sales " }),
      });
      assert.equal(padded.status, 400);
    },
    new FakeDataHubMcpClient(),
    "sales"
  );
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
    for (const query of ["*", "?", "**", "{}"]) {
      assert.equal(
        (
          await fetch(`${baseUrl}/api/audits`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ query }),
          })
        ).status,
        400
      );
    }
  });
});
