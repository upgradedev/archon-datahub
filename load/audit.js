// Load test — the audit/recall hot path under concurrency, fully offline.
//
// WHY NOT k6 (and why this IS the honest "k6 equivalent"). k6 drives an HTTP endpoint.
// Archon has no HTTP server: it is an MCP (stdio) server + an in-process, injectable audit
// pipeline. Standing up an HTTP shell purely to point k6 at it would add an UNtested network
// surface for no signal. So this is an in-process load harness that models k6's contract —
// bounded iterations across virtual users (VUs), per-iteration latency, a p95 threshold, and
// a hard error-rate gate — and drives the SAME code the agent ships (`AuditPipeline.run` and
// the dual-face MCP tool dispatch `callAuditTool`) against the deterministic Fake DataHub
// client (the replay-cassette-shaped offline backend). No live DataHub, no credentials, no
// network — identical to CI.
//
// SLO (asserted; a breach exits non-zero so CI fails):
//   • error_rate            == 0            (hard gate — any thrown/!ok iteration fails)
//   • audit p95 latency     <  P95_BUDGET_MS (default 1500ms; override LOAD_P95_MS)
//   • completed iterations  == planned       (no dropped work)
//
// Run:  node --import tsx load/audit.js
// Tune: LOAD_VUS, LOAD_ITERATIONS, LOAD_P95_MS  (env)

import { AuditPipeline } from "../src/pipeline/pipeline.js";
import { FakeDataHubMcpClient } from "../src/datahub/mcp-client.js";
import { buildMcpServer, callAuditTool } from "../src/mcp/server.js";

// Keep the whole run offline + deterministic regardless of the caller's shell env.
delete process.env.LLM_API_KEY;
delete process.env.DASHSCOPE_API_KEY;
delete process.env.GEMINI_API_KEY;
delete process.env.OPENAI_API_KEY;
delete process.env.ANTHROPIC_API_KEY;
delete process.env.DATAHUB_MCP_URL;
delete process.env.DATAHUB_GMS_URL;

const VUS = intEnv("LOAD_VUS", 10);
const ITERATIONS = intEnv("LOAD_ITERATIONS", 200);
// Generous headroom over locally-observed p95 — shared CI runners are noisy, and the HARD
// gate is error_rate, not a tight latency number (a tight p95 is the classic flaky-red).
const P95_BUDGET_MS = intEnv("LOAD_P95_MS", 1500);

function intEnv(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
}

// One audit iteration = the exact work a caller drives: half through the pipeline directly,
// half through OUR MCP tool surface (audit_catalog), alternating so both faces are loaded.
async function iteration(i, pipeline, mcpDeps) {
  const client = new FakeDataHubMcpClient();
  if (i % 2 === 0) {
    const report = await pipeline.run(client);
    if (!report || report.findings.length === 0 || report.trace.length !== 4) {
      throw new Error(`pipeline produced no/incomplete report (findings=${report?.findings?.length})`);
    }
  } else {
    const res = await callAuditTool(mcpDeps, "audit_catalog", {});
    if (res.isError) throw new Error("audit_catalog returned isError");
    const payload = JSON.parse(res.content?.[0]?.text ?? "{}");
    if (!payload.findings || payload.findings.length === 0) {
      throw new Error("audit_catalog returned no findings");
    }
  }
}

function percentile(sortedMs, p) {
  if (sortedMs.length === 0) return 0;
  const idx = Math.min(sortedMs.length - 1, Math.ceil((p / 100) * sortedMs.length) - 1);
  return sortedMs[idx];
}

async function runVu(vu, planned, pipeline, mcpDeps, latencies, errors) {
  for (let n = 0; n < planned; n++) {
    const globalIdx = vu + n * VUS; // interleave VU work across the iteration space
    const t0 = performance.now();
    try {
      await iteration(globalIdx, pipeline, mcpDeps);
      latencies.push(performance.now() - t0);
    } catch (err) {
      errors.push(`iter ${globalIdx}: ${err.message}`);
    }
  }
}

async function main() {
  const pipeline = new AuditPipeline();
  const { deps: mcpDeps } = await buildMcpServer({ datahub: new FakeDataHubMcpClient() });

  const perVu = Math.ceil(ITERATIONS / VUS);
  const planned = perVu * VUS;
  const latencies = [];
  const errors = [];

  const wallStart = performance.now();
  // All VUs run concurrently — the concurrency the SLO is measured under.
  await Promise.all(
    Array.from({ length: VUS }, (_, vu) => runVu(vu, perVu, pipeline, mcpDeps, latencies, errors))
  );
  const wallMs = performance.now() - wallStart;

  const completed = latencies.length;
  const errorRate = planned === 0 ? 1 : errors.length / planned;
  const sorted = [...latencies].sort((a, b) => a - b);
  const p50 = percentile(sorted, 50);
  const p95 = percentile(sorted, 95);
  const p99 = percentile(sorted, 99);
  const mean = completed ? latencies.reduce((s, x) => s + x, 0) / completed : 0;
  const throughput = wallMs > 0 ? (completed / wallMs) * 1000 : 0;

  const bar = "─".repeat(64);
  console.log(`\nArchon-DataHub — LOAD TEST (offline, in-process, k6-equivalent)\n${bar}`);
  console.log(`VUs                  ${VUS}`);
  console.log(`planned iterations   ${planned}`);
  console.log(`completed            ${completed}`);
  console.log(`errors               ${errors.length}  (rate ${(errorRate * 100).toFixed(2)}%)`);
  console.log(`wall time            ${wallMs.toFixed(0)} ms`);
  console.log(`throughput           ${throughput.toFixed(1)} audits/s`);
  console.log(`latency mean         ${mean.toFixed(1)} ms`);
  console.log(`latency p50/p95/p99  ${p50.toFixed(1)} / ${p95.toFixed(1)} / ${p99.toFixed(1)} ms`);
  console.log(bar);

  const breaches = [];
  if (errors.length > 0) breaches.push(`error_rate ${(errorRate * 100).toFixed(2)}% > 0% (first: ${errors[0]})`);
  if (completed !== planned) breaches.push(`completed ${completed} != planned ${planned}`);
  if (p95 > P95_BUDGET_MS) breaches.push(`p95 ${p95.toFixed(1)}ms > budget ${P95_BUDGET_MS}ms`);

  if (breaches.length > 0) {
    console.log(`SLO: FAIL`);
    for (const b of breaches) console.log(`  ✗ ${b}`);
    console.log(bar);
    process.exit(1);
  }
  console.log(`SLO: PASS  (error_rate=0, p95 ${p95.toFixed(1)}ms < ${P95_BUDGET_MS}ms budget)`);
  console.log(bar);
  process.exit(0);
}

main().catch((err) => {
  console.error(`load test crashed: ${err.message}`);
  process.exit(1);
});
