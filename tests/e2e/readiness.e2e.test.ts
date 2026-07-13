// End-to-end assertion of the READINESS GATE (scripts/readiness.ts).
//
// This imports the SAME pure computeReadiness() the CLI + CI job use, runs the full
// evidence-gathering offline (pipeline, ReAct loop, MCP round-trip, live contradiction
// recovery, static tool-surface + docs/NOTICE checks), and asserts the automatable surface
// clears the 95% CI gate. It also asserts the gate stays HONEST: completeness is strictly
// below 100 (user-gated live proof remains), and the differentiator check (I1) genuinely
// passes on version-history-shaped data.

import { test } from "node:test";
import assert from "node:assert/strict";
import { computeReadiness } from "../../scripts/readiness.js";

test("readiness: automatable surface clears the 95% CI gate offline", async () => {
  const r = await computeReadiness();
  assert.ok(
    r.automatablePercent >= 95,
    `automatablePercent=${r.automatablePercent}% (< 95). Failing checks: ${r.checks
      .filter((c) => c.status === "fail")
      .map((c) => `${c.id}:${c.evidence}`)
      .join(" | ")}`
  );
  assert.equal(r.gate.passed, true);
});

test("readiness: the differentiator (I1) fires on version-history data", async () => {
  const r = await computeReadiness();
  const i1 = r.checks.find((c) => c.id === "I1")!;
  assert.equal(i1.status, "pass", `I1 evidence: ${i1.evidence}`);
});

test("readiness: no automatable check is failing", async () => {
  const r = await computeReadiness();
  const failing = r.checks.filter((c) => c.status === "fail");
  assert.deepEqual(failing.map((c) => c.id), [], `unexpected failures: ${JSON.stringify(failing)}`);
});

test("readiness: stays honest — completeness < 100 while live proof is user-gated", async () => {
  const r = await computeReadiness();
  assert.ok(r.completenessPercent < 100, "completeness must reflect the outstanding user-gated live run");
  assert.ok(r.userGated.length >= 3, "live run, real-catalog finding, and demo video remain user-gated");
});
