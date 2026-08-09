import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const compose = readFileSync("compose.yaml", "utf8");

test("customer quickstart remains local, read-only, and readiness gated", () => {
  assert.match(compose, /127\.0\.0\.1:\$\{ARCHON_PORT:-8080\}:8080/u);
  assert.match(compose, /DATAHUB_GMS_TOKEN: \$\{DATAHUB_GMS_TOKEN:\?/u);
  assert.match(compose, /condition: service_healthy/u);
  assert.match(compose, /dist\/onboarding\/doctor\.js/u);
  assert.match(compose, /read_only: true/u);
  assert.match(compose, /no-new-privileges:true/u);
  assert.doesNotMatch(compose, /DATAHUB_WRITE_|remediation-worker|\/api\/remedi/u);
});
