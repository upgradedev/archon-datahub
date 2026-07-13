// READINESS GATE — a machine-checkable, weighted scorecard of how ready this entry is
// against the "Build with DataHub: The Agent Hackathon" criteria, computed from REAL
// evidence (it runs the pipeline, the ReAct loop, the MCP round-trip, and the live
// contradiction-recovery path; it statically verifies the read-only tool surface and the
// docs/NOTICE consistency). Nothing here asserts `true` — every check exercises the thing
// it claims.
//
// TWO NUMBERS, kept side by side so the gate never reads as an overclaim:
//   • automatablePercent — over the checks a machine CAN prove offline. THE CI GATE
//     (fails below the threshold). A real regression (a mutation tool leaking into the live
//     client, a NOTICE-listed file going missing, the version-history path ceasing to fire)
//     drops this below 95% and reddens CI.
//   • completenessPercent — over ALL checks, INCLUDING the honestly user-gated ones (a
//     recorded live-DataHub run, a real captured cassette, the demo video). This is < 100
//     until the user does the live proof — that is the truth, not a defect to hide.
//
// Weights are set by JUDGE IMPORTANCE (the differentiator/innovation axis is heaviest) and
// documented below; they are NOT tuned to reach any number.
//
//   npm run readiness        # prints the report + writes readiness.json + sets exit code

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { FakeDataHubMcpClient } from "../src/datahub/mcp-client.js";
import { AuditPipeline } from "../src/pipeline/pipeline.js";
import { defaultAuditLoop } from "../src/ap/loop.js";
import { buildMcpServer, callAuditTool, MCP_TOOLS } from "../src/mcp/server.js";
import { LineageAnalyzerAgent } from "../src/agents/lineage-analyzer.js";
import { auditVersionHistory } from "../src/datahub/version-history.js";
import { FIXTURE_VERSION_HISTORY } from "../src/datahub/fixtures.js";
import { validateSnapshot } from "../src/governance/validator.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const p = (rel: string): string => resolve(ROOT, rel);
const read = (rel: string): string => (existsSync(p(rel)) ? readFileSync(p(rel), "utf8") : "");

export type CheckStatus = "pass" | "fail" | "user-gated";
export type CriterionId = "technical" | "innovation" | "datahub-depth" | "usefulness" | "presentation";

export interface Check {
  id: string;
  criterion: CriterionId;
  weight: number;
  status: CheckStatus;
  title: string;
  evidence: string;
}

export interface CriterionSummary {
  id: CriterionId;
  weight: number;
  automatablePercent: number;
  passed: number;
  failed: number;
  userGated: number;
}

export interface ReadinessReport {
  generatedAt: string;
  gate: { threshold: number; metric: "automatablePercent"; passed: boolean };
  automatablePercent: number;
  completenessPercent: number;
  criteria: CriterionSummary[];
  checks: Check[];
  userGated: Array<{ id: string; title: string; evidence: string }>;
}

// The five judged criteria and their judge-importance weights (sum = 100). Innovation is
// heaviest — the self-auditing contradiction engine is the entry's differentiator.
const CRITERION_WEIGHT: Record<CriterionId, number> = {
  technical: 20,
  innovation: 25,
  "datahub-depth": 20,
  usefulness: 20,
  presentation: 15,
};

const GATE_THRESHOLD = 95;

// Run one check safely: a thrown error is a FAIL (never crashes the gate), with the message
// as evidence. user-gated checks short-circuit (their `fn` just declares the manual proof).
function check(
  id: string,
  criterion: CriterionId,
  weight: number,
  title: string,
  fn: () => { ok: boolean; evidence: string } | { gated: true; evidence: string }
): Check {
  try {
    const r = fn();
    if ("gated" in r) return { id, criterion, weight, status: "user-gated", title, evidence: r.evidence };
    return { id, criterion, weight, status: r.ok ? "pass" : "fail", title, evidence: r.evidence };
  } catch (err) {
    return { id, criterion, weight, status: "fail", title, evidence: `threw: ${(err as Error).message}` };
  }
}

// Mutation tool names the live client must NEVER call (read-only guarantee).
const MUTATION_TOOLS = [
  "add_tags",
  "remove_tags",
  "add_terms",
  "remove_terms",
  "add_owners",
  "remove_owners",
  "set_domains",
  "remove_domains",
  "update_description",
  "add_structured_properties",
];

export async function computeReadiness(): Promise<ReadinessReport> {
  const checks: Check[] = [];

  // ── Technical Implementation (20) ─────────────────────────────────────────────
  const pipelineReport = await new AuditPipeline().run(new FakeDataHubMcpClient());
  checks.push(
    check("T1", "technical", 8, "4-agent pipeline runs end-to-end", () => ({
      ok: pipelineReport.trace.length === 4 && pipelineReport.findings.length > 0,
      evidence: `trace=[${pipelineReport.trace.map((t) => t.agent).join(", ")}], findings=${pipelineReport.findings.length}`,
    }))
  );

  const loop = await defaultAuditLoop().run(new FakeDataHubMcpClient());
  checks.push(
    check("T2", "technical", 6, "ReAct loop terminates human-gated (pending)", () => ({
      ok: loop.disposition === "pending" && loop.trace.length > 0,
      evidence: `disposition=${loop.disposition}, stopReason=${loop.stopReason}, steps=${loop.trace.length}`,
    }))
  );

  const { deps } = await buildMcpServer({ datahub: new FakeDataHubMcpClient() });
  const toolResult = await callAuditTool(deps, "audit_catalog", {});
  checks.push(
    check("T3", "technical", 6, "Dual-face MCP round-trip (our server serves audit_catalog)", () => ({
      ok: toolResult.isError !== true && JSON.parse(textOf(toolResult)).findings.length > 0,
      evidence: `audit_catalog → ${toolResult.isError ? "ERROR" : "ok"}, findings=${
        toolResult.isError ? 0 : JSON.parse(textOf(toolResult)).findings.length
      }`,
    }))
  );

  // ── Innovation / Originality (25) — the differentiator, LIVE ──────────────────
  const vhFindings = new LineageAnalyzerAgent().analyzeVersionHistory(FIXTURE_VERSION_HISTORY);
  const vhContradictions = vhFindings.filter((f) => f.type === "contradiction");
  checks.push(
    check("I1", "innovation", 13, "Self-audit FIRES on aspect version-history-shaped data", () => ({
      ok: vhContradictions.length >= 1,
      evidence: `${vhContradictions.length} cross-source contradiction(s) recovered from version history (attrs: ${vhContradictions
        .map((f) => (f.detail as { attribute?: string }).attribute)
        .join(", ")})`,
    }))
  );

  // Honest negative: a single-run monotonic edit is DRIFT, not a contradiction. This proves
  // the live-firing is not "any value change" — the credibility guard for the whole claim.
  const singleRun = auditVersionHistory([
    {
      urn: "urn:li:dataset:(urn:li:dataPlatform:snowflake,x,PROD)",
      aspect: "ownership",
      versions: [
        { value: { owners: [{ owner: "urn:li:corpGroup:a" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "r1" } },
        { value: { owners: [{ owner: "urn:li:corpGroup:b" }] }, systemMetadata: { version: "2", lastObserved: 2, runId: "r1" } },
      ],
    },
  ]);
  checks.push(
    check("I2", "innovation", 6, "Single-run drift does NOT fire (honest distinct-source gate)", () => ({
      ok: singleRun.contradictions.length === 0,
      evidence: `monotonic single-run edit → ${singleRun.contradictions.length} contradictions (must be 0)`,
    }))
  );

  checks.push(
    check("I3", "innovation", 6, "Version-history recovery has a dedicated test suite", () => ({
      ok: existsSync(p("tests/unit/version-history.test.ts")) && existsSync(p("tests/integration/version-history-cassette.test.ts")),
      evidence: "tests/unit/version-history.test.ts + tests/integration/version-history-cassette.test.ts present",
    }))
  );

  // ── Use of DataHub (depth) (20) ───────────────────────────────────────────────
  const liveSrc = read("src/datahub/mcp-client-live.ts");
  const consumesReadTools = ['"search"', '"get_entities"', '"get_lineage"'].every((t) => liveSrc.includes(t));
  const leakedMutation = MUTATION_TOOLS.filter((t) => liveSrc.includes(`"${t}"`));
  checks.push(
    check("D1", "datahub-depth", 8, "Live client consumes ONLY the official MCP read tools", () => ({
      ok: consumesReadTools && leakedMutation.length === 0,
      evidence: `read tools present=${consumesReadTools}; mutation tools leaked=[${leakedMutation.join(", ") || "none"}]`,
    }))
  );

  const toolNames = MCP_TOOLS.map((t) => t.name);
  checks.push(
    check("D2", "datahub-depth", 5, "Own audit RE-EXPOSED as MCP tools (dual-face)", () => ({
      ok: toolNames.includes("audit_catalog") && toolNames.includes("run_audit_loop"),
      evidence: `our MCP tools: [${toolNames.join(", ")}]`,
    }))
  );

  checks.push(
    check("D3", "datahub-depth", 7, "Recorded live-DataHub run (screenshots + captured finding)", () => ({
      gated: true,
      evidence:
        "USER-GATED: stand up `datahub docker quickstart` on a cloud VM, point the agent at it (DATAHUB_GMS_URL + PAT), run `npm run audit:demo`, capture screenshots + one recorded finding. Also swap the replay cassette for a real captured batch.",
    }))
  );

  // ── Real-World Usefulness (20) ────────────────────────────────────────────────
  const gov = validateSnapshot(await new FakeDataHubMcpClient().harvestSnapshot());
  const ruleIds = new Set(gov.map((g) => g.ruleId));
  checks.push(
    check("U1", "usefulness", 8, "Governance gate evaluates all of G1–G6", () => ({
      ok: ["G1", "G2", "G3", "G4", "G5", "G6"].every((r) => ruleIds.has(r as never)),
      evidence: `rules evaluated: [${[...ruleIds].sort().join(", ")}]`,
    }))
  );

  const byType = (t: string) => pipelineReport.findings.filter((f) => f.type === t).length;
  checks.push(
    check("U2", "usefulness", 7, "Produces a quantified, multi-class finding set", () => ({
      ok: byType("contradiction") > 0 && byType("governance_violation") > 0 && byType("lineage_gap") > 0,
      evidence: `contradictions=${byType("contradiction")}, governance=${byType("governance_violation")}, lineage_gaps=${byType("lineage_gap")}`,
    }))
  );

  checks.push(
    check("U3", "usefulness", 5, "Quantified finding on a REAL catalog", () => ({
      gated: true,
      evidence: "USER-GATED: the numbers above are on fixtures; a real-catalog run (D3) converts 'asserted' usefulness into 'shown'.",
    }))
  );

  // ── Presentation / Submission Quality (15) ────────────────────────────────────
  // Normalize whitespace so a hedge phrase that wraps across lines still matches.
  const flat = (s: string): string => s.replace(/\s+/g, " ");
  const readme = read("README.md");
  const design = read("docs/DESIGN.md");
  const hedged =
    flat(readme).includes("cannot fire from the MCP read tools alone") &&
    /version[- ]history/i.test(readme) &&
    /version[- ]history/i.test(design);
  checks.push(
    check("P1", "presentation", 5, "Docs stay hedged AND document the version-history recovery", () => ({
      ok: hedged,
      evidence: `README keeps the read-surface hedge + names version-history recovery; DESIGN references it = ${hedged}`,
    }))
  );

  // Accuracy of the disclosure of THIS repo's files: scan only the "New files" section
  // onward, so the ported table's foreign "Ported from" paths (src/memory/…, src/qwen/…,
  // which live in the SOURCE projects, not here) are not mistaken for missing repo files.
  const notice = read("NOTICE.md");
  const newFilesSection = notice.slice(Math.max(0, notice.indexOf("## New files")));
  const noticePaths = [...newFilesSection.matchAll(/`(src\/[A-Za-z0-9/_-]+\.ts)`/g)].map((m) => m[1]!);
  const missing = noticePaths.filter((rel) => !existsSync(p(rel)));
  const disclosesNew = notice.includes("version-history.ts") && notice.includes("readiness.ts");
  checks.push(
    check("P2", "presentation", 5, "NOTICE ported-vs-new disclosure is accurate", () => ({
      ok: noticePaths.length > 0 && missing.length === 0 && disclosesNew,
      evidence: `${noticePaths.length} this-repo src files disclosed, missing=[${missing.join(", ") || "none"}], discloses version-history.ts + readiness.ts=${disclosesNew}`,
    }))
  );

  checks.push(
    check("P3", "presentation", 5, "Demo video + write-up in the submission package", () => ({
      gated: true,
      evidence: "USER-GATED: record the 3-min demo + publish the write-up; ensure both hedge the differentiator exactly as the README does (no 'detects contradictions in your live catalog' overclaim).",
    }))
  );

  return summarize(checks);
}

function textOf(r: { content?: Array<{ type: string; text?: string }> }): string {
  return r.content?.find((c) => c.type === "text")?.text ?? "{}";
}

function summarize(checks: Check[]): ReadinessReport {
  const automatable = checks.filter((c) => c.status !== "user-gated");
  const autoTotal = automatable.reduce((s, c) => s + c.weight, 0);
  const autoPassed = automatable.filter((c) => c.status === "pass").reduce((s, c) => s + c.weight, 0);
  const allTotal = checks.reduce((s, c) => s + c.weight, 0);
  const allPassed = checks.filter((c) => c.status === "pass").reduce((s, c) => s + c.weight, 0);

  const automatablePercent = round1((autoPassed / autoTotal) * 100);
  const completenessPercent = round1((allPassed / allTotal) * 100);

  const criteria: CriterionSummary[] = (Object.keys(CRITERION_WEIGHT) as CriterionId[]).map((id) => {
    const cs = checks.filter((c) => c.criterion === id);
    const auto = cs.filter((c) => c.status !== "user-gated");
    const at = auto.reduce((s, c) => s + c.weight, 0);
    const ap = auto.filter((c) => c.status === "pass").reduce((s, c) => s + c.weight, 0);
    return {
      id,
      weight: CRITERION_WEIGHT[id],
      automatablePercent: at > 0 ? round1((ap / at) * 100) : 100,
      passed: cs.filter((c) => c.status === "pass").length,
      failed: cs.filter((c) => c.status === "fail").length,
      userGated: cs.filter((c) => c.status === "user-gated").length,
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    gate: { threshold: GATE_THRESHOLD, metric: "automatablePercent", passed: automatablePercent >= GATE_THRESHOLD },
    automatablePercent,
    completenessPercent,
    criteria,
    checks,
    userGated: checks
      .filter((c) => c.status === "user-gated")
      .map((c) => ({ id: c.id, title: c.title, evidence: c.evidence })),
  };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

// ── CLI ─────────────────────────────────────────────────────────────────────────
const isMain = Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === resolve(process.argv[1]!);

if (isMain) {
  computeReadiness()
    .then((report) => {
      const bar = "─".repeat(72);
      console.log(`\nArchon-DataHub — READINESS GATE\n${bar}`);
      for (const cr of report.criteria) {
        console.log(
          `${cr.id.padEnd(14)} weight ${String(cr.weight).padStart(3)}  automatable ${String(cr.automatablePercent).padStart(5)}%  ` +
            `(pass ${cr.passed} / fail ${cr.failed} / user-gated ${cr.userGated})`
        );
      }
      console.log(bar);
      for (const c of report.checks) {
        const mark = c.status === "pass" ? "PASS " : c.status === "fail" ? "FAIL " : "GATE↦";
        console.log(`  [${mark}] ${c.id} (${c.criterion}, w${c.weight}) — ${c.title}\n           ${c.evidence}`);
      }
      console.log(bar);
      console.log(`AUTOMATABLE: ${report.automatablePercent}%  (CI gate ≥ ${report.gate.threshold}% → ${report.gate.passed ? "PASS" : "FAIL"})`);
      console.log(`COMPLETENESS (incl. user-gated): ${report.completenessPercent}%  — remaining is user-gated:`);
      for (const u of report.userGated) console.log(`   • ${u.id}: ${u.title}`);
      console.log(bar);

      writeFileSync(p("readiness.json"), JSON.stringify(report, null, 2) + "\n");
      console.log("wrote readiness.json\n");
      process.exit(report.gate.passed ? 0 : 1);
    })
    .catch((err) => {
      console.error(`readiness gate crashed: ${(err as Error).message}`);
      process.exit(1);
    });
}
