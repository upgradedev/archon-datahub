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

import { performance } from "node:perf_hooks";
import {
  chatClient,
  hasLlmCreds,
  resolveLlmProvider,
  DEFAULT_MODEL,
  type ChatMessage,
  type LlmClient,
  type ToolDef,
} from "../llm/client.js";
import {
  DETERMINISTIC_FIXTURE_MODEL,
  FakeLlmClient,
} from "../llm/fake.js";
import {
  createModelRuntimeProvenance,
  type ModelRuntimeProvenance,
} from "../llm/provenance.js";
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
}

export interface AuditRunResult {
  // Always "pending": the findings await a human steward. Nothing executed against DataHub.
  disposition: "pending";
  findings: Finding[];
  trace: AuditTraceStep[];
  // One strict, privacy-safe receipt per model call. Prompts, provider payloads,
  // model-authored reasoning, endpoints, errors, and credentials are never retained.
  modelProvenance: ModelRuntimeProvenance[];
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
  "You NEVER mutate the catalog; you only recommend, and a human disposes.";

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
    private modelId: string =
      client.runtime.source === "deterministic-fixture"
        ? DETERMINISTIC_FIXTURE_MODEL
        : resolveLlmProvider()?.model ?? DEFAULT_MODEL,
    opts: AuditLoopOptions = {},
    private now: () => number = () => performance.now()
  ) {
    this.maxSteps = Math.min(12, Math.max(3, opts.maxSteps ?? 6));
    this.onStop = opts.onStop;
  }

  async run(datahub: DataHubClient, query?: string): Promise<AuditRunResult> {
    const state: LoopState = { harvested: false, consistencyDone: false, governanceDone: false, findings: [] };
    const trace: AuditTraceStep[] = [];
    const modelProvenance: ModelRuntimeProvenance[] = [];
    let noProgress = 0;

    for (let step = 1; step <= this.maxSteps; step++) {
      const startedAt =
        this.client.runtime.source === "live-provider" ? this.now() : null;
      const res = await this.client.chat.completions.create({
        model: this.modelId,
        messages: this.messages(trace, state),
        temperature: 0.1,
        max_tokens: 256,
        tools: TOOL_DEFS,
        tool_choice: "auto",
      });
      modelProvenance.push(
        createModelRuntimeProvenance(
          this.client.runtime,
          this.modelId,
          { id: res.id, model: res.model, usage: res.usage },
          startedAt === null ? null : Math.round(this.now() - startedAt)
        )
      );

      const call = res.choices?.[0]?.message?.tool_calls?.[0];
      const name = call?.function?.name ?? "";

      if (name === "emit_findings") {
        return {
          disposition: "pending",
          findings: state.findings,
          trace,
          modelProvenance,
          stopReason: "emitted_findings",
        };
      }
      if (name === "flag_for_review") {
        return this.fallback(
          state,
          trace,
          modelProvenance,
          "no_progress_fallback",
          "the model escalated to a human"
        );
      }

      if ((AUTONOMOUS as readonly string[]).includes(name)) {
        const before = signature(state);
        const observation = await this.execute(name, state, datahub, query);
        trace.push({ step, tool: name, observation });
        if (signature(state) === before) {
          // re-ran an already-done read tool → no new evidence
          if (++noProgress >= 2) {
            return this.fallback(
              state,
              trace,
              modelProvenance,
              "no_progress_fallback",
              "the model repeated a completed read tool without progressing"
            );
          }
        }
        continue;
      }

      if (++noProgress >= 2) {
        return this.fallback(
          state,
          trace,
          modelProvenance,
          "no_progress_fallback",
          "the model returned no usable tool call"
        );
      }
    }
    return this.fallback(
      state,
      trace,
      modelProvenance,
      "max_steps_fallback",
      `reached the ${this.maxSteps}-step cap`
    );
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

  private fallback(
    state: LoopState,
    trace: AuditTraceStep[],
    modelProvenance: ModelRuntimeProvenance[],
    reason: LoopStopReason,
    detail: string
  ): AuditRunResult {
    (this.onStop ?? ((r, d) => console.warn(`[AuditLoop] ${r}: ${d}`)))(reason, detail);
    return {
      disposition: "pending",
      findings: state.findings,
      trace,
      modelProvenance,
      stopReason: reason,
    };
  }

  private messages(trace: AuditTraceStep[], state: LoopState): ChatMessage[] {
    const steps = trace.length
      ? trace
          .map((t) => `  ${t.step}. ${t.tool}\n     → ${t.observation}`)
          .join("\n")
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
  const resolvedClient =
    client ?? (hasLlmCreds() ? chatClient() : new FakeLlmClient());
  return new AuditLoop(resolvedClient, undefined, opts);
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
        additionalProperties: false,
        properties: {},
      },
    },
  };
}
