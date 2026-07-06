// Self-auditing metadata-consistency layer — the agent that audits DataHub's OWN
// metadata for internal disagreement.
//
// PORTED from Archon MemoryAgent (repos/qwen-memoryagent/src/memory/consistency.ts)
// and RE-AIMED from "cross-session memory contradictions" onto "cross-SOURCE
// metadata contradictions & lineage gaps". The algorithm is unchanged — only the
// domain the facts describe changed. See NOTICE.md for the disclosure.
//
// A metadata catalog accumulates facts about the same entity from MANY independent
// sources: the source system's own schema, a dbt model's declaration, a manual
// catalog edit, an ingestion connector. Nothing stops two of those from
// DISAGREEING: Snowflake reports `sales.amount` as `number`, while the dbt manifest
// declares it `string`; connector A names the owner `team-finance`, a manual edit
// says `team-ops`. A plain lookup just returns whichever ranked higher and stays
// silent about the conflict. That is exactly the failure mode this module catches.
//
// `auditConsistency` groups harvested facts by the ENTITY they describe and flags
// two metadata-native problems:
//
//   CONTRADICTION — two facts describing the SAME entity assign DIFFERENT values to
//                   the SAME attribute (two owners for one dataset, two types for
//                   one field). Because each fact is a distinct harvest from a
//                   distinct source, a contradiction means two sources of truth
//                   disagree — the catalog is internally inconsistent.
//   LINEAGE GAP   — a fact explicitly references another entity (metadata.refs, e.g.
//                   a declared upstream lineage URN) that has NO catalogued fact in
//                   the audited set — a dangling lineage edge: an upstream the
//                   pipeline claims to read from that the catalog never ingested.
//                   (Surfaced by the caller as a `lineage_gap` finding.)
//
// This is a PURE function over generic facts (no DB, no DataHub calls, no policy
// rulebook — that is the governance validator's job). It runs identically over
// hand-built facts in tests and over facts harvested from a live DataHub instance,
// so the "self-auditing" claim is measured on the same engine that ships.

import type { AuditFact, FactKind } from "../types.js";

// A RECOMMENDATION for which side of a contradiction to trust. This is a
// recommender, NOT ground truth: the audit cannot know which source was correct,
// only which one a defensible, domain-neutral policy would prefer. It NEVER mutates
// metadata — the caller (a human steward) decides what to do with the recommendation.
//
// The policy is a fixed priority ladder over signals ALREADY present on the facts:
//   1. importance       — an explicit salience (a steward-pinned fact) is the
//                         strongest signal; it outranks a later harvest with none.
//   2. source-authority — a STRUCTURED, source-system fact (`schema`/`ownership`/
//                         `lineage`/…) is a more authoritative source of a RAW value
//                         than a DERIVED narrative (`insight`). Overridable.
//   3. recency          — the DEFAULT: the later harvest wins (the newest scan
//                         presumably reflects the current state of the source).
export interface Resolution {
  recommendedFactId: string; // a real fact id carrying the winning value
  recommendedValue: unknown; // the value the policy recommends trusting
  rule: "recency" | "importance" | "source-authority";
  // Heuristic ordinal confidence in [0,1] — NOT a calibrated probability.
  confidence: number;
  rationale: string; // one-line human-readable justification
}

// One conflicting attribute across two-or-more facts about the same entity.
export interface Contradiction {
  type: "contradiction";
  subject: string; // the entity all these facts describe
  attribute: string; // the metadata attribute they disagree on
  values: Array<{
    factId: string;
    source: string | null;
    value: unknown;
    createdAt: string;
  }>;
  resolution: Resolution;
}

// A referenced entity (e.g. a declared lineage upstream) that no fact in the
// audited set actually catalogues — a lineage gap.
export interface Absence {
  type: "absence";
  subject: string; // the referenced-but-missing entity
  referencedBy: Array<{ factId: string; source: string | null }>;
}

export interface ConsistencyReport {
  audited: number; // facts examined
  subjects: number; // distinct entities seen
  contradictions: Contradiction[];
  absences: Absence[];
  ok: boolean; // true ⇔ no findings
}

export interface AuditOptions {
  // Absolute tolerance for treating two numbers as "the same value" (rounding /
  // float noise). Two numbers within this band are NOT a contradiction.
  numericTolerance?: number;
  // Optional override for the source-authority ranking over fact `kind`. Higher =
  // more authoritative for a RAW attribute value. Anything not in the map falls
  // back to the neutral/structured rank; see DEFAULT_KIND_AUTHORITY.
  kindAuthority?: Record<string, number>;
}

// Metadata keys that name the entity itself or its cross-references — they are
// identity, not attributes to compare, so they never count as contradictions.
const RESERVED_KEYS = new Set(["record", "refs"]);

// The entity a fact is about. Deterministic and SPECIFIC on purpose:
//   1. an explicit `metadata.record` (a caller-declared entity URN/id), else
//   2. the fact's `sourceRef` (the originating entity URN).
// We deliberately do NOT fall back to source::scan — that would collapse unrelated
// entities into one subject and manufacture false contradictions. A fact with no
// entity key is un-auditable for contradictions and is skipped (counted, never
// flagged).
export function subjectKey(m: AuditFact): string | null {
  const rec = m.metadata?.["record"];
  if (typeof rec === "string" && rec.length > 0) return rec;
  if (typeof rec === "number") return String(rec);
  if (m.sourceRef && m.sourceRef.length > 0) return m.sourceRef;
  return null;
}

// Compare two attribute values for equality. Numbers use an absolute tolerance;
// everything else uses strict string-normalized equality.
function valuesAgree(a: unknown, b: unknown, tol: number): boolean {
  if (typeof a === "number" && typeof b === "number") {
    return Math.abs(a - b) <= tol;
  }
  if (typeof a === "number" || typeof b === "number") {
    return String(a) === String(b);
  }
  return JSON.stringify(a) === JSON.stringify(b);
}

// Comparable attributes of a fact: its flat metadata entries minus the reserved
// identity keys, keeping only JSON-scalar values (number/string/bool).
function attributesOf(m: AuditFact): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const md = m.metadata;
  if (!md) return out;
  for (const [k, v] of Object.entries(md)) {
    if (RESERVED_KEYS.has(k)) continue;
    if (v === null || v === undefined) continue;
    const t = typeof v;
    if (t === "number" || t === "string" || t === "boolean") out.set(k, v);
  }
  return out;
}

// ── Resolution (recommender) ────────────────────────────────────────────────
// Conservative, OVERRIDABLE authority ranking over the fact `kind`. A fact drawn
// from a source system's own metadata (schema/ownership/lineage/glossary/domain/
// deprecation) is STRUCTURED and system-of-record; an `insight` is a DERIVED
// narrative the agent wrote ABOUT other facts. For a RAW attribute value the
// structured record is the more authoritative source than a narrated derivation.
// We ONLY ever demote a fact we KNOW is derived (`insight`); every other/unknown
// kind keeps the neutral structured rank, so the audit never invents authority it
// can't justify. Callers can supply their own map via `AuditOptions.kindAuthority`.
const STRUCTURED_AUTHORITY = 2;
const DEFAULT_KIND_AUTHORITY: Record<string, number> = { insight: 1 };

function authorityOf(kind: string, map: Record<string, number>): number {
  const v = map[kind];
  return typeof v === "number" ? v : STRUCTURED_AUTHORITY;
}

// The explicit salience a fact carries. Prefers the top-level `importance` field,
// falling back to a caller-placed `metadata.importance`. Returns null when
// absent/non-numeric (→ "no signal").
function importanceOf(m: AuditFact): number | null {
  if (typeof m.importance === "number" && Number.isFinite(m.importance)) return m.importance;
  const v = m.metadata?.["importance"];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

const MS_PER_DAY = 86_400_000;

// A distinct-value cluster: the value plus every fact (harvest) asserting it.
interface ValueCluster {
  value: unknown;
  facts: AuditFact[];
}

function latestOf(facts: AuditFact[]): AuditFact {
  return [...facts].sort((a, b) =>
    a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : a.id < b.id ? -1 : 1
  )[0]!;
}

// Recommend which distinct value to trust, using the fixed priority ladder
// (importance → source-authority → recency). Pure; a recommender, not truth.
export function resolveContradiction(
  clusters: ValueCluster[],
  kindAuthority: Record<string, number> = DEFAULT_KIND_AUTHORITY
): Resolution {
  const agg = clusters.map((c) => {
    const impCarrier = c.facts
      .filter((m) => importanceOf(m) !== null)
      .sort((a, b) => importanceOf(b)! - importanceOf(a)!)[0];
    const authCarrier = [...c.facts].sort(
      (a, b) => authorityOf(b.kind, kindAuthority) - authorityOf(a.kind, kindAuthority)
    )[0]!;
    const latest = latestOf(c.facts);
    return {
      value: c.value,
      importance: impCarrier ? importanceOf(impCarrier) : null,
      importanceCarrier: impCarrier ?? null,
      authority: authorityOf(authCarrier.kind, kindAuthority),
      authorityCarrier: authCarrier,
      latest,
    };
  });

  // ── Rule 1: importance — a fact flagged with higher salience wins. ───────────
  const withImp = agg.filter((a) => a.importance !== null);
  if (withImp.length > 0) {
    const sorted = [...agg].sort((a, b) => (b.importance ?? -1) - (a.importance ?? -1));
    const top = sorted[0]!;
    const second = sorted[1]!;
    const margin = (top.importance ?? -1) - (second.importance ?? -1);
    if (top.importance !== null && margin >= 0.05) {
      const win = top.importanceCarrier!;
      const conf = clamp(0.6 + Math.min(0.3, margin * 0.5), 0, 0.95);
      return {
        recommendedFactId: win.id,
        recommendedValue: top.value,
        rule: "importance",
        confidence: round2(conf),
        rationale:
          `Fact ${win.id} carries higher importance (${fmt(top.importance)} vs ` +
          `${second.importance === null ? "none" : fmt(second.importance)}); ` +
          `explicit salience outranks a later harvest.`,
      };
    }
  }

  // ── Rule 2: source-authority — a structured source outranks a derived note. ──
  const sortedAuth = [...agg].sort((a, b) => b.authority - a.authority);
  const topAuth = sortedAuth[0]!;
  const secondAuth = sortedAuth[1]!;
  if (topAuth.authority > secondAuth.authority) {
    const win = topAuth.authorityCarrier;
    return {
      recommendedFactId: win.id,
      recommendedValue: topAuth.value,
      rule: "source-authority",
      confidence: 0.75,
      rationale:
        `Structured '${win.kind}' fact outranks derived '${secondAuth.authorityCarrier.kind}' ` +
        `for a raw value; source authority overrides recency.`,
    };
  }

  // ── Rule 3: recency (default) — the later harvest wins. ──────────────────────
  const sortedRec = [...agg].sort((a, b) =>
    a.latest.createdAt < b.latest.createdAt
      ? 1
      : a.latest.createdAt > b.latest.createdAt
        ? -1
        : a.latest.id < b.latest.id
          ? -1
          : 1
  );
  const win = sortedRec[0]!;
  const runnerUp = sortedRec[1]!;
  const tie = win.latest.createdAt === runnerUp.latest.createdAt;
  const gapDays = tie
    ? 0
    : (Date.parse(win.latest.createdAt) - Date.parse(runnerUp.latest.createdAt)) / MS_PER_DAY;
  const conf = tie ? 0.4 : clamp(0.5 + Math.min(0.35, (gapDays / 30) * 0.35), 0, 0.85);
  return {
    recommendedFactId: win.latest.id,
    recommendedValue: win.value,
    rule: "recency",
    confidence: round2(conf),
    rationale: tie
      ? `Harvests share a timestamp; no stronger signal available — defaulting to ` +
        `fact ${win.latest.id} (deterministic tie-break). Low confidence.`
      : `Later harvest (${win.latest.createdAt.slice(0, 10)}) supersedes the earlier ` +
        `value ${fmt(runnerUp.value)} (${runnerUp.latest.createdAt.slice(0, 10)}); ` +
        `recency is the default tie-breaker.`,
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}
function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
function fmt(v: unknown): string {
  return typeof v === "number" ? String(v) : JSON.stringify(v);
}

// Audit a set of harvested facts for cross-source contradictions and dangling
// lineage references. Pure — no I/O. The caller supplies the facts in scope.
export function auditConsistency(facts: AuditFact[], opts: AuditOptions = {}): ConsistencyReport {
  const tol = opts.numericTolerance ?? 0.5;

  // Group facts by the entity they describe.
  const bySubject = new Map<string, AuditFact[]>();
  const presentSubjects = new Set<string>();
  for (const m of facts) {
    const s = subjectKey(m);
    if (!s) continue;
    presentSubjects.add(s);
    (bySubject.get(s) ?? bySubject.set(s, []).get(s)!).push(m);
  }

  // ── Contradictions: same subject, same attribute, disagreeing values ────────
  const contradictions: Contradiction[] = [];
  for (const [subject, group] of bySubject) {
    if (group.length < 2) continue;

    const byAttr = new Map<string, Array<{ m: AuditFact; value: unknown }>>();
    for (const m of group) {
      for (const [attr, value] of attributesOf(m)) {
        (byAttr.get(attr) ?? byAttr.set(attr, []).get(attr)!).push({ m, value });
      }
    }

    for (const [attr, carriers] of byAttr) {
      if (carriers.length < 2) continue;
      const distinct: Array<{ value: unknown; carriers: typeof carriers }> = [];
      for (const c of carriers) {
        const bucket = distinct.find((d) => valuesAgree(d.value, c.value, tol));
        if (bucket) bucket.carriers.push(c);
        else distinct.push({ value: c.value, carriers: [c] });
      }
      if (distinct.length < 2) continue; // all agree → consistent

      const resolution = resolveContradiction(
        distinct.map((d) => ({ value: d.value, facts: d.carriers.map((c) => c.m) })),
        opts.kindAuthority ?? DEFAULT_KIND_AUTHORITY
      );

      contradictions.push({
        type: "contradiction",
        subject,
        attribute: attr,
        values: distinct
          .map((d) => {
            const rep = [...d.carriers].sort((a, b) =>
              a.m.createdAt < b.m.createdAt ? -1 : a.m.createdAt > b.m.createdAt ? 1 : 0
            )[0]!;
            return {
              factId: rep.m.id,
              source: rep.m.source,
              value: d.value,
              createdAt: rep.m.createdAt,
            };
          })
          .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0)),
        resolution,
      });
    }
  }

  // ── Absences (lineage gaps): a referenced entity with no fact of its own ─────
  const referencedBy = new Map<string, Array<{ factId: string; source: string | null }>>();
  for (const m of facts) {
    const refs = m.metadata?.["refs"];
    if (!Array.isArray(refs)) continue;
    for (const r of refs) {
      const key = typeof r === "number" ? String(r) : typeof r === "string" ? r : null;
      if (!key) continue;
      if (presentSubjects.has(key)) continue; // the referenced entity exists
      (referencedBy.get(key) ?? referencedBy.set(key, []).get(key)!).push({
        factId: m.id,
        source: m.source,
      });
    }
  }
  const absences: Absence[] = [...referencedBy.entries()].map(([subject, refs]) => ({
    type: "absence",
    subject,
    referencedBy: refs,
  }));

  // Deterministic ordering for stable output / tests.
  contradictions.sort((a, b) =>
    a.subject !== b.subject
      ? a.subject < b.subject
        ? -1
        : 1
      : a.attribute < b.attribute
        ? -1
        : a.attribute > b.attribute
          ? 1
          : 0
  );
  absences.sort((a, b) => (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0));

  return {
    audited: facts.length,
    subjects: bySubject.size,
    contradictions,
    absences,
    ok: contradictions.length === 0 && absences.length === 0,
  };
}

// Re-export the fact-kind type for downstream callers that build facts.
export type { FactKind };
