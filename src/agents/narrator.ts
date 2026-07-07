// NarratorAgent — the ONLY LLM-backed agent. Writes a short, steward-facing executive
// summary over the findings the deterministic agents produced. The LLM never invents
// findings or numbers: it is handed the exact counts + top findings and asked to
// narrate them. Injectable client (defaults to real LLM when LLM_API_KEY is set, else
// the deterministic FakeLlmClient), so CI runs the narrator offline with zero spend.

import { chatClient, hasLlmCreds, resolveLlmProvider, DEFAULT_MODEL, type LlmClient } from "../llm/client.js";
import { FakeLlmClient } from "../llm/fake.js";
import type { Finding } from "../types.js";
import type { Classification } from "./classifier.js";

const SYSTEM_PROMPT =
  "You are Archon, a read-only metadata-governance analyst for a data catalog. You are " +
  "given the exact results of a deterministic self-audit (contradiction, lineage-gap, and " +
  "governance findings) plus a classification of the catalog. Write a concise, factual " +
  "executive summary for a data steward: what was audited, what was found, and why it " +
  "matters. Never invent findings or numbers beyond those given. Make clear the agent is " +
  "READ-ONLY — it recommends; a human disposes. 4–7 sentences.";

export class NarratorAgent {
  constructor(private client: LlmClient = hasLlmCreds() ? chatClient() : new FakeLlmClient(),
    // Default to the detected provider's model (resolved fresh), else the module default.
    private modelId: string = resolveLlmProvider()?.model ?? DEFAULT_MODEL) {}

  async summarize(findings: Finding[], classification: Classification): Promise<string> {
    const counts = tally(findings);
    // The machine-readable evidence line the deterministic Fake narrator reads; the
    // real LLM reads the whole human block below it.
    const evidence =
      `EVIDENCE: contradictions=${counts.contradiction} lineage_gaps=${counts.lineage_gap} ` +
      `governance_violations=${counts.governance_violation}`;
    const top = findings
      .slice()
      .sort((a, b) => sev(b.severity) - sev(a.severity))
      .slice(0, 8)
      .map((f) => `  - [${f.type}/${f.severity}] ${f.summary}`)
      .join("\n");

    const user = [
      `CATALOG CLASSIFICATION: ${classification.totalEntities} entities, ` +
        `${classification.withLineage} with lineage, ${classification.sensitiveEntities} with sensitive fields.`,
      evidence,
      `TOP FINDINGS:`,
      top || "  (none)",
      ``,
      `Write the executive summary now.`,
    ].join("\n");

    const res = await this.client.chat.completions.create({
      model: this.modelId,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: user },
      ],
      temperature: 0.2,
      max_tokens: 400,
    });
    return res.choices?.[0]?.message?.content?.trim() || "(no summary produced)";
  }
}

function tally(findings: Finding[]): Record<Finding["type"], number> {
  const c = { contradiction: 0, lineage_gap: 0, governance_violation: 0 };
  for (const f of findings) c[f.type]++;
  return c;
}

function sev(s: Finding["severity"]): number {
  return s === "high" ? 3 : s === "medium" ? 2 : 1;
}
