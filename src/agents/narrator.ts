// NarratorAgent — the ONLY LLM-backed agent. Writes a short, steward-facing executive
// summary over the findings the deterministic agents produced. The LLM never invents
// findings or numbers: it is handed the exact counts + top findings and asked to
// narrate them. Injectable client (defaults to a real configured provider, else
// the deterministic FakeLlmClient), so CI runs the narrator offline with zero spend.

import { performance } from "node:perf_hooks";
import { chatClient, hasLlmCreds, resolveLlmProvider, DEFAULT_MODEL, type LlmClient } from "../llm/client.js";
import {
  DETERMINISTIC_FIXTURE_MODEL,
  FakeLlmClient,
} from "../llm/fake.js";
import {
  createModelRuntimeProvenance,
  type ModelRuntimeProvenance,
} from "../llm/provenance.js";
import type { Finding } from "../types.js";
import type { Classification } from "./classifier.js";

const SYSTEM_PROMPT =
  "You are Archon, the narration stage of a metadata-governance control plane. The audit " +
  "and recommendation phase you are summarizing is read-only. You are " +
  "given the exact results of a deterministic self-audit (contradiction, lineage-gap, and " +
  "governance findings) plus a classification of the catalog. Write a concise, factual " +
  "executive summary for a data steward: what was audited, what was found, and why it " +
  "matters. Never invent findings or numbers beyond those given. Make clear that no write " +
  "occurs during audit or recommendation; a separate digest-bound action may execute only " +
  "after an authenticated human approval. 4–7 sentences.";

export interface NarrationResult {
  narrative: string;
  modelProvenance: ModelRuntimeProvenance;
}

export class NarratorAgent {
  constructor(
    private client: LlmClient = hasLlmCreds()
      ? chatClient()
      : new FakeLlmClient(),
    // A fixture run requests an explicit fixture identity rather than implying that the
    // live-provider default was called. Injected live clients retain the configured model.
    private modelId: string =
      client.runtime.source === "deterministic-fixture"
        ? DETERMINISTIC_FIXTURE_MODEL
        : resolveLlmProvider()?.model ?? DEFAULT_MODEL,
    private now: () => number = () => performance.now()
  ) {}

  async summarize(
    findings: Finding[],
    classification: Classification
  ): Promise<NarrationResult> {
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

    const startedAt =
      this.client.runtime.source === "live-provider" ? this.now() : null;
    const res = await this.client.chat.completions.create({
      model: this.modelId,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: user },
      ],
      temperature: 0.2,
      max_tokens: 400,
    });
    const latencyMs =
      startedAt === null ? null : Math.round(this.now() - startedAt);
    const narrative =
      res.choices?.[0]?.message?.content?.trim() || "(no summary produced)";
    if (
      narrative.length > 8_000 ||
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(narrative)
    ) {
      throw new Error("The model narration did not satisfy the bounded text contract.");
    }
    return {
      narrative,
      modelProvenance: createModelRuntimeProvenance(
        this.client.runtime,
        this.modelId,
        {
          id: res.id,
          model: res.model,
          usage: res.usage,
        },
        latencyMs
      ),
    };
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
