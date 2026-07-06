// FakeLlmClient — the offline stand-in for the LLM, at the SAME seam as the real
// OpenAI-compatible client (LlmClient). It plays two roles, chosen by the request:
//
//   • ReAct loop (request carries `tools` + an EVIDENCE line): returns ONE canned
//     `tool_calls` entry — the exact shape a function-calling model returns — choosing
//     the next audit tool by reading the deterministic evidence the loop embeds. This
//     exercises the loop's REAL tool-call parse path in CI with no key.
//   • Narrator (request carries no tools): returns a deterministic executive summary
//     assembled from the finding counts the caller put in the prompt.
//
// The SAME loop + narrator code runs offline and online; only the client behind this
// interface changes.

import type { ChatCreateArgs, ChatResponse, LlmClient, ToolCall } from "./client.js";

export class FakeLlmClient implements LlmClient {
  chat = {
    completions: {
      create: async (args: ChatCreateArgs): Promise<ChatResponse> => {
        const prompt = args.messages.map((m) => m.content).join("\n");
        if (args.tools && args.tools.length > 0) {
          return { choices: [{ message: { content: null, tool_calls: [chooseNextTool(prompt)] } }] };
        }
        return { choices: [{ message: { content: narrate(prompt), tool_calls: undefined } }] };
      },
    },
  };
}

// The deterministic audit ReAct policy: gather all read-only evidence (harvest →
// consistency → governance), THEN emit the read-only findings. Every audit step is
// side-effect-free; the terminal action only RECOMMENDS — nothing mutates DataHub.
function chooseNextTool(prompt: string): ToolCall {
  const line = lastEvidence(prompt);
  const flag = (k: string): boolean => new RegExp(`\\b${k}=true\\b`).test(line);
  if (!flag("harvested")) {
    return call("harvest_catalog", { reasoning: "Harvest the catalog metadata + lineage before auditing." });
  }
  if (!flag("consistency_done")) {
    return call("run_consistency_audit", {
      reasoning: "Run the self-audit for cross-source contradictions and lineage gaps.",
    });
  }
  if (!flag("governance_done")) {
    return call("run_governance_audit", { reasoning: "Check the G1–G6 governance policy rules." });
  }
  return call("emit_findings", {
    reasoning: "All read-only evidence gathered — emit the findings for a steward to disposition.",
    confidence: 0.9,
  });
}

function narrate(prompt: string): string {
  const num = (k: string): number => {
    const m = new RegExp(`${k}=(\\d+)`).exec(prompt);
    return m ? Number(m[1]) : 0;
  };
  const contradictions = num("contradictions");
  const gaps = num("lineage_gaps");
  const violations = num("governance_violations");
  const total = contradictions + gaps + violations;
  if (total === 0) {
    return "Metadata governance summary: the audited catalog is internally consistent — no cross-source contradictions, no dangling lineage edges, and no governance-policy violations were found. Read-only audit; no action required.";
  }
  return (
    `Metadata governance summary: the self-audit surfaced ${total} finding(s) for steward review — ` +
    `${contradictions} cross-source contradiction(s), ${gaps} lineage gap(s), and ${violations} ` +
    `governance-policy violation(s). Contradictions indicate two metadata sources disagree on the ` +
    `same entity and should be reconciled at the system of record; lineage gaps are declared upstreams ` +
    `that are not catalogued and risk silent schema breaks downstream; governance violations are ` +
    `ungoverned or unclassified assets. All findings are read-only recommendations — a steward decides.`
  );
}

function lastEvidence(prompt: string): string {
  const lines = prompt.split("\n").filter((l) => l.trim().startsWith("EVIDENCE:"));
  return lines.length ? lines[lines.length - 1]! : "";
}

function call(name: string, args: Record<string, unknown>): ToolCall {
  return { id: `fake-${name}`, type: "function", function: { name, arguments: JSON.stringify(args) } };
}
