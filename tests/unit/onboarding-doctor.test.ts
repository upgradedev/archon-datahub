import assert from "node:assert/strict";
import { test } from "node:test";
import { runOnboardingDoctor } from "../../src/onboarding/doctor.js";

const DATAHUB_URL = "https://datahub.example.test";
const QUERY = "urn:li:dataset:(urn:li:dataPlatform:snowflake,orders,PROD)";

test("doctor proves live readiness and executes one exact scoped audit", async () => {
  const requests: Array<{ url: string; init: RequestInit | undefined }> = [];
  const messages: string[] = [];
  const summary = await runOnboardingDoctor({
    apiUrl: "http://api:8080",
    datahubGmsUrl: DATAHUB_URL,
    query: QUERY,
    request: async (input, init) => {
      requests.push({ url: String(input), init });
      if (String(input).endsWith("/readyz")) {
        return Response.json({
          status: "ready",
          datahubMode: "live",
          releaseSha: "release-123",
        });
      }
      return Response.json({
        releaseSha: "release-123",
        report: { findings: [{ type: "contradiction" }], trace: [{ agent: "harvester" }] },
      });
    },
    write: (message) => messages.push(message),
  });

  assert.deepEqual(summary, { releaseSha: "release-123", findings: 1, traceSteps: 1 });
  assert.equal(requests.length, 2);
  assert.equal(requests[0]!.url, "http://api:8080/readyz");
  assert.equal(requests[1]!.url, "http://api:8080/api/audits");
  assert.equal(requests[1]!.init?.method, "POST");
  assert.deepEqual(JSON.parse(String(requests[1]!.init?.body)), { query: QUERY });
  assert.match(messages[0]!, /doctor passed.*ready\/live.*1 finding/u);
});

test("doctor rejects fixture readiness instead of reporting a false live pass", async () => {
  await assert.rejects(
    runOnboardingDoctor({
      apiUrl: "http://api:8080",
      datahubGmsUrl: DATAHUB_URL,
      query: QUERY,
      request: async () =>
        Response.json({ status: "ready", datahubMode: "fixture", releaseSha: "local" }),
      write: () => undefined,
    }),
    /did not prove a live/u
  );
});

test("customer doctor refuses plaintext or credential-bearing DataHub origins", async () => {
  const request = async (): Promise<Response> => {
    throw new Error("network must not be reached");
  };
  for (const datahubGmsUrl of [
    "http://datahub.example.test",
    "https://token@datahub.example.test",
    "https://datahub.example.test/api/graphql",
  ]) {
    await assert.rejects(
      runOnboardingDoctor({
        apiUrl: "http://api:8080",
        datahubGmsUrl,
        query: QUERY,
        request,
        write: () => undefined,
      }),
      /DATAHUB_GMS_URL must be a credential-free origin using https:/u
    );
  }
});

test("doctor rejects broad or normalized-equivalent queries before network access", async () => {
  for (const query of ["*", " orders", "orders?", "{}"] ) {
    await assert.rejects(
      runOnboardingDoctor({
        apiUrl: "http://api:8080",
        datahubGmsUrl: DATAHUB_URL,
        query,
        request: async () => {
          throw new Error("network must not be reached");
        },
        write: () => undefined,
      }),
      /must be one exact/u
    );
  }
});
