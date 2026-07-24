// AuditLoop — a bounded, multi-step ReAct loop over LLM function-calling that drives
// the audit as an AGENT, not a fixed script.
//
// Each step the LLM is given the catalog context + the evidence gathered so far + the
// tool catalog, and chooses the NEXT tool. The autonomous READ tools — harvest_catalog,
// run_consistency_audit, run_governance_audit — have NO side effect: the loop executes
// them, appends the observation to a running trace, and iterates. When the model picks
// the TERMINAL action emit_findings, the loop STOPS and hands back the assembled
// findings as a PENDING report for a human steward to disposition. The human gate is
// ironclad: NOTHING mutates DataHub anywhere in this loop — the terminal action only
// RECOMMENDS. Loop guards (max-steps cap, no-progress detection, deterministic
// flag_for_review fallback) keep it safe and terminating.
//
// There is a SINGLE loop. Offline vs. online differs only by the client behind the
// LlmClient seam (real LLM vs. the deterministic FakeLlmClient), so the tool-call parse
// path is exercised in CI.

import { chatClient, hasLlmCreds, DEFAULT_MODEL, type ChatMessage, type LlmClient, type ToolDef } from "../llm/client.js";
import { FakeLlmClient } from "../llm/fake.js";
import type { DataHubClient } from "../datahub/mcp-client.js";
import { ClassifierAgent } from "../agents/classifier.js";
import { LineageAnalyzerAgent } from "../agents/lineage-analyzer.js";
import { GovernanceAuditorAgent } from "../agents/governance-auditor.js";
import type { Finding } from "../types.js";

export type LoopStopReason = "emitted_findings" | "no_progress_fallback" | "max_steps_fallback";

export interface AuditTraceStep {
  step: number;
  tool: string;
  observation: string;
  reasoning: string;
}

export interface AuditRunResult {
  // Always "pending": the findings await a human steward. Nothing executed against DataHub.
  disposition: "pending";
  findings: Finding[];
  trace: AuditTraceStep[];
  stopReason: LoopStopReason;
}

const AUTONOMOUS = ["harvest_catalog", "run_consistency_audit", "run_governance_audit"] as const;
const TERMINAL = ["emit_findings", "flag_for_review"] as const;

const TOOL_DEFS: ToolDef[] = [
  fn("harvest_catalog", "Harvest catalog metadata + lineage from DataHub (read-only). Always first."),
  fn("run_consistency_audit", "Run the self-audit for cross-source contradictions and lineage gaps (read-only)."),
  fn("run_governance_audit", "Check the G1–G6 governance policy rules over the catalog (read-only)."),
  fn("emit_findings", "Emit the assembled read-only findings for a steward to disposition. Terminal."),
  fn("flag_for_review", "Escalate to a human without a complete audit. Terminal fallback."),
];

const SYSTEM_PROMPT =
  "You are Archon, a read-only metadata-governance agent for a DataHub catalog. You work " +
  "in STEPS: each step call exactly ONE tool. First harvest_catalog, then run_consistency_audit, " +
  "then run_governance_audit — all read-only. Once the evidence is gathered, call emit_findings. " +
  "You NEVER mutate the catalog; you only recommend, and a human disposes. Put a short `reasoning` " +
  "on every call.";

interface LoopState {
  harvested: boolean;
  consistencyDone: boolean;
  governanceDone: boolean;
  findings: Finding[];
}

export interface AuditLoopOptions {
  maxSteps?: number;
  onStop?: (reason: LoopStopReason, detail: string) => void;
}

export class AuditLoop {
  private maxSteps: number;
  private onStop?: AuditLoopOptions["onStop"];
  private classifier = new ClassifierAgent();
  private lineage = new LineageAnalyzerAgent();
  private governance = new GovernanceAuditorAgent();

  constructor(
    private client: LlmClient = hasLlmCreds() ? chatClient() : new FakeLlmClient(),
    private modelId: string = DEFAULT_MODEL,
    opts: AuditLoopOptions = {}
  ) {
    this.maxSteps = Math.max(3, opts.maxSteps ?? 6);
    this.onStop = opts.onStop;
  }

  async run(datahub: DataHubClient, query?: string): Promise<AuditRunResult> {
    const state: LoopState = { harvested: false, consistencyDone: false, governanceDone: false, findings: [] };
    const trace: AuditTraceStep[] = [];
    let noProgress = 0;

    for (let step = 1; step <= this.maxSteps; step++) {
      const res = await this.client.chat.completions.create({
        model: this.modelId,
        messages: this.messages(trace, state),
        temperature: 0.1,
        max_tokens: 256,
        tools: TOOL_DEFS,
        tool_choice: "auto",
      });

      const call = res.choices?.[0]?.message?.tool_calls?.[0];
      const name = call?.function?.name ?? "";
      const args = call ? safeParse(call.function.arguments) : {};
      const reasoning = typeof args["reasoning"] === "string" ? (args["reasoning"] as string) : "";

      if (name === "emit_findings") {
        return { disposition: "pending", findings: state.findings, trace, stopReason: "emitted_findings" };
      }
      if (name === "flag_for_review") {
        return this.fallback(state, trace, "no_progress_fallback", reasoning || "model escalated to a human");
      }

      if ((AUTONOMOUS as readonly string[]).includes(name)) {
        const before = signature(state);
        const observation = await this.execute(name, state, datahub, query);
        trace.push({ step, tool: name, observation, reasoning });
        if (signature(state) === before) {
          // re-ran an already-done read tool → no new evidence
          if (++noProgress >= 2) {
            return this.fallback(state, trace, "no_progress_fallback", "the model repeated a completed read tool without progressing");
          }
        }
        continue;
      }

      if (++noProgress >= 2) {
        return this.fallback(state, trace, "no_progress_fallback", "the model returned no usable tool call");
      }
    }
    return this.fallback(state, trace, "max_steps_fallback", `reached the ${this.maxSteps}-step cap`);
  }

  private async execute(name: string, state: LoopState, datahub: DataHubClient, query?: string): Promise<string> {
    switch (name) {
      case "harvest_catalog": {
        const harvest = await datahub.harvestAudit(query, {
          profile: "synchronous-preview",
        });
        const snapshot = harvest.snapshot;
        (state as LoopState & { snapshot?: unknown }).snapshot = snapshot;
        (state as LoopState & { facts?: unknown }).facts = harvest.facts;
        state.harvested = true;
        return `harvested ${snapshot.entities.length} entities (${this.classifier.classify(snapshot).withLineage} with lineage)`;
      }
      case "run_consistency_audit": {
        if (!state.harvested) return "cannot audit before harvest_catalog";
        const facts = (state as LoopState & { facts?: Parameters<LineageAnalyzerAgent["analyze"]>[0] }).facts ?? [];
        const found = this.lineage.analyze(facts);
        state.findings.push(...found);
        state.consistencyDone = true;
        return `self-audit found ${found.length} contradiction/lineage finding(s)`;
      }
      case "run_governance_audit": {
        if (!state.harvested) return "cannot audit before harvest_catalog";
        const snapshot = (state as LoopState & { snapshot?: Parameters<GovernanceAuditorAgent["audit"]>[0] }).snapshot;
        const found = snapshot ? this.governance.audit(snapshot) : [];
        state.findings.push(...found);
        state.governanceDone = true;
        return `governance audit found ${found.length} violation(s)`;
      }
      default:
        return `unknown tool ${name}`;
    }
  }

  private fallback(state: LoopState, trace: AuditTraceStep[], reason: LoopStopReason, detail: string): AuditRunResult {
    (this.onStop ?? ((r, d) => console.warn(`[AuditLoop] ${r}: ${d}`)))(reason, detail);
    return { disposition: "pending", findings: state.findings, trace, stopReason: reason };
  }

  private messages(trace: AuditTraceStep[], state: LoopState): ChatMessage[] {
    const steps = trace.length
      ? trace.map((t) => `  ${t.step}. ${t.tool}${t.reasoning ? ` — ${t.reasoning}` : ""}\n     → ${t.observation}`).join("\n")
      : "  (none yet — start with harvest_catalog)";
    const evidence =
      `EVIDENCE: harvested=${state.harvested} consistency_done=${state.consistencyDone} ` +
      `governance_done=${state.governanceDone} findings=${state.findings.length}`;
    const user = [`STEPS SO FAR:`, steps, ``, evidence, ``, `Choose the next tool now.`].join("\n");
    return [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: user },
    ];
  }
}

export function defaultAuditLoop(client?: LlmClient, opts: AuditLoopOptions = {}): AuditLoop {
  if (client) return new AuditLoop(client, DEFAULT_MODEL, opts);
  return new AuditLoop(hasLlmCreds() ? chatClient() : new FakeLlmClient(), DEFAULT_MODEL, opts);
}

export const ALL_LOOP_TOOLS = [...AUTONOMOUS, ...TERMINAL];

function signature(state: LoopState): string {
  return `${state.harvested}|${state.consistencyDone}|${state.governanceDone}|${state.findings.length}`;
}

function fn(name: string, description: string): ToolDef {
  return {
    type: "function",
    function: {
      name,
      description,
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: { reasoning: { type: "string" }, confidence: { type: "number" } },
      },
    },
  };
}

function safeParse(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
