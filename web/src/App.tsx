import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type FormEvent,
} from "react";
import { submitApprovalDecision } from "./api";
import { EvidencePack } from "./EvidencePack";
import { GuidedTour } from "./GuidedTour";
import { RuntimeControl } from "./RuntimeControl";
import {
  AGENT_STACK_DATASET_URN,
  AGENT_STACK_QUESTION,
  loadRuntimeAgentStack,
  requestRuntimeImproveContext,
  resumeRuntimeAgentStack,
  submitRuntimeApproval,
  type JsonObject,
  type JsonValue,
  type RuntimeControlLoopStatus,
  type RuntimeSessionStatus,
} from "./runtime-api";
import {
  beginSignIn,
  getAccessToken,
  getAuthSnapshot,
  initializeAuthentication,
  signOut,
  subscribeToAuth,
  type AuthSnapshot,
} from "./auth";
import { previewAudit } from "./fixtures";
import type {
  ApprovalDecision,
  ApprovalReview,
  BlastRadius,
  ControlLoopStatus,
  Finding,
  FindingType,
  LoadedAudit,
  ModelRuntimeProvenance,
  ProvenanceEvent,
  Severity,
} from "./types";

type IconName =
  | "arrow"
  | "check"
  | "chevron"
  | "copy"
  | "database"
  | "file"
  | "fingerprint"
  | "graph"
  | "layers"
  | "play"
  | "refresh"
  | "search"
  | "shield"
  | "spark"
  | "warning";

const RUN_DISABLED_HINT =
  "It starts a live, credentialed run against a real DataHub tenant with a real write credential, so it requires an authenticated steward session.";

const iconPaths: Record<IconName, string[]> = {
  arrow: ["M5 12h14", "m13 6 6 6-6 6"],
  check: ["m5 12 4 4L19 6"],
  chevron: ["m9 18 6-6-6-6"],
  copy: ["M8 8h11v11H8z", "M5 16H4V5h11v1"],
  database: [
    "M4 6c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3Z",
    "M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6",
    "M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  ],
  file: ["M6 3h8l4 4v14H6z", "M14 3v5h5", "M9 13h6", "M9 17h4"],
  fingerprint: [
    "M7.6 8.4a6 6 0 0 1 8.8 0",
    "M5.2 6a9.4 9.4 0 0 1 13.6 0",
    "M9 11a3 3 0 0 1 6 0c0 4.6-1 7.2-2.2 9",
    "M6 11c0 4.2-.4 6.2-1.5 8",
    "M12 11c0 4-.5 7.2-2 10",
    "M18 11c0 2.8-.2 5.2-1.2 7.5",
  ],
  graph: ["M5 18V9", "M12 18V5", "M19 18v-7", "M3 21h18"],
  layers: [
    "m12 3 9 5-9 5-9-5 9-5Z",
    "m3 12 9 5 9-5",
    "m3 16 9 5 9-5",
  ],
  play: ["M8 5v14l11-7Z"],
  refresh: ["M20 7v5h-5", "M4 17v-5h5", "M6.1 8A7 7 0 0 1 18.6 7", "M17.9 16A7 7 0 0 1 5.4 17"],
  search: ["m21 21-4.4-4.4", "M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z"],
  shield: ["M12 3 20 6v5c0 5.3-3.4 8.8-8 10-4.6-1.2-8-4.7-8-10V6l8-3Z", "m8.5 12 2.2 2.2 4.8-5"],
  spark: ["m12 3 1.2 4.3L17 9l-3.8 1.7L12 15l-1.2-4.3L7 9l3.8-1.7L12 3Z", "m19 15 .6 2.1 1.9.9-1.9.9L19 21l-.6-2.1-1.9-.9 1.9-.9L19 15Z"],
  warning: ["M12 4 3 20h18L12 4Z", "M12 9v5", "M12 17.5v.1"],
};

function Icon({
  name,
  className = "size-4",
}: {
  name: IconName;
  className?: string;
}) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {iconPaths[name].map((path) => (
        <path d={path} key={path} />
      ))}
    </svg>
  );
}

const severityRank: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

const typeLabels: Record<FindingType, string> = {
  contradiction: "Contradiction",
  lineage_gap: "Lineage gap",
  governance_violation: "Governance",
};

function shortUrn(urn: string): string {
  const field = urn.includes("#") ? ` · ${urn.split("#").at(-1)}` : "";
  const base = urn.split("#")[0] ?? urn;
  const tuple = base.match(/,\s*([^,()]+),[^,()]+\)$/);
  if (tuple?.[1]) return `${tuple[1]}${field}`;
  const simple = base.match(/\([^,]+,\s*([^)]+)\)$/);
  if (simple?.[1]) return `${simple[1]}${field}`;
  return `${base.split(":").at(-1) ?? base}${field}`;
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function controlLoopMessage(status: ControlLoopStatus): string {
  if (status.status === "RUNNING") {
    if (status.approval?.status === "DECIDED") {
      return "The steward decision was recorded; the isolated worker is validating the bound plan and exact post-state.";
    }
    return status.report
      ? "The immutable report is sealed; the durable workflow is preparing the steward handoff."
      : "The durable control loop is harvesting DataHub evidence in the isolated worker.";
  }
  if (status.status === "AWAITING_APPROVAL") {
    return "Immutable evidence is ready. The workflow is paused on a server-held token until an authenticated steward decides.";
  }
  if (status.status === "SUCCEEDED") {
    if (status.result?.outcome === "VERIFIED") {
      return "Verified: the exact approved postcondition, receipt chain, and execution evidence were independently checked.";
    }
    if (status.result?.outcome === "REJECTED") {
      return "Rejected: the workflow closed without invoking a DataHub mutation.";
    }
    return "The durable read-only audit completed successfully.";
  }
  return `The durable control loop ended with status ${status.status.toLowerCase()}.`;
}

function digestTail(value: string): string {
  const raw = value.replace(/^sha256:/, "");
  return `${raw.slice(0, 8)}…${raw.slice(-8)}`;
}

function EvidenceDigest({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    if (!navigator.clipboard) return;
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/10 p-2.5">
      <dt className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-400">
        {label}
      </dt>
      <dd className="mt-1 flex items-center gap-1.5 font-mono text-[10px] text-slate-300">
        <code title={value}>{digestTail(value)}</code>
        <button
          aria-label={`Copy ${label.toLowerCase()}`}
          className="copy-button"
          onClick={() => void copy()}
          type="button"
        >
          <Icon className="size-3.5" name={copied ? "check" : "copy"} />
        </button>
      </dd>
    </div>
  );
}

function TerminalEvidence({ status }: { status: ControlLoopStatus }) {
  const result = status.result;
  if (
    status.status !== "SUCCEEDED" ||
    !result ||
    result.outcome === "READ_ONLY_COMPLETE"
  ) {
    return null;
  }
  const passed = result.verification.checks.filter((check) => check.passed).length;
  return (
    <section
      aria-label="Terminal execution evidence"
      className="mb-2 rounded-xl border border-emerald-300/15 bg-emerald-300/[0.025] p-3"
      data-testid="terminal-evidence"
      id="judge-tour-terminal-proof"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="eyebrow text-emerald-200/65">Immutable terminal proof</p>
          <p className="mt-1 text-xs font-semibold text-emerald-50">
            {result.outcome === "VERIFIED"
              ? "Approved mutation verified"
              : "Rejection sealed without mutation"}
          </p>
        </div>
        <span className="rounded-full border border-emerald-300/15 px-2 py-1 text-[9px] font-semibold tracking-[0.1em] text-emerald-200">
          {result.outcome}
        </span>
      </div>
      <dl className="mt-3 grid gap-2 sm:grid-cols-2">
        <EvidenceDigest label="Receipt digest" value={result.receiptDigest} />
        <EvidenceDigest
          label="Execution evidence digest"
          value={result.executionEvidenceDigest}
        />
      </dl>
      <dl className="mt-3 grid grid-cols-2 gap-2 text-[10px] text-slate-400 sm:grid-cols-4">
        <div>
          <dt className="text-slate-400">Checks</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.outcome === "REJECTED"
              ? "Not invoked"
              : `${passed}/${result.verification.checks.length} passed`}
          </dd>
        </div>
        <div>
          <dt className="text-slate-400">Receipt events</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.verification.eventCount}
          </dd>
        </div>
        <div>
          <dt className="text-slate-400">Rollback</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.verification.rollbackAvailability}
          </dd>
        </div>
        <div>
          <dt className="text-slate-400">Completed</dt>
          <dd className="mt-0.5 text-slate-300">{formatDate(result.completedAt)}</dd>
        </div>
      </dl>
      {result.verification.checks.length > 0 && (
        <ul
          aria-label="Verified postcondition checks"
          className="mt-3 grid gap-1 text-[9px] text-emerald-100/70 sm:grid-cols-2"
        >
          {result.verification.checks.map((check) => (
            <li className="flex items-center gap-1.5" key={check.checkId}>
              <Icon className="size-3 text-emerald-300" name="check" />
              <code>{check.checkId}</code>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function findingIdentity(finding: Finding): string {
  return `${finding.type}:${finding.subject}:${String(finding.detail.attribute ?? finding.detail.ruleId ?? "")}`;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-badge severity-${severity}`}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

function SourceBadge({ source }: { source: LoadedAudit["source"] }) {
  const label = source === "live" ? "Live DataHub" : "Fixture preview";
  return (
    <span
      aria-label={label}
      className={`source-badge ${
        source === "live" ? "source-live" : "source-fixture"
      }`}
      role="status"
    >
      <span className="relative flex size-2" aria-hidden="true">
        <span
          className={`absolute inline-flex size-full rounded-full opacity-50 ${
            source === "live" ? "animate-ping bg-emerald-300" : "bg-amber-300"
          }`}
        />
        <span
          className={`relative inline-flex size-2 rounded-full ${
            source === "live" ? "bg-emerald-300" : "bg-amber-300"
          }`}
        />
      </span>
      <span className="sm:hidden">
        {source === "live" ? "Live" : "Fixture"}
      </span>
      <span className="hidden sm:inline">{label}</span>
    </span>
  );
}

function ModelProvenancePanel({
  provenance,
}: {
  provenance: ModelRuntimeProvenance;
}) {
  const titleId = "model-runtime-provenance-title";
  if (provenance.source === "deterministic-fixture") {
    return (
      <section
        aria-labelledby={titleId}
        className="panel mt-6 overflow-hidden"
        data-testid="model-provenance"
      >
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Truthful runtime disclosure</p>
            <h2 className="section-title" id={titleId}>
              Model runtime provenance
            </h2>
          </div>
          <span className="rounded-full border border-amber-300/20 bg-amber-300/[0.05] px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-amber-100">
            No model call
          </span>
        </div>
        <div className="border-t border-white/[0.06] p-5">
          <p className="text-xs leading-5 text-slate-300">
            This narrative is deterministic fixture output. No provider model API
            call occurred, so there is no provider response ID, token usage, or
            client latency to report.
          </p>
          <p className="mt-2 text-[10px] leading-4 text-slate-400">
            Prompts, credentials, endpoints, raw responses, and provider errors are
            outside the browser contract.
          </p>
        </div>
      </section>
    );
  }

  const usage = provenance.tokenUsage;
  return (
    <section
      aria-labelledby={titleId}
      className="panel mt-6 overflow-hidden"
      data-testid="model-provenance"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Truthful runtime disclosure</p>
          <h2 className="section-title" id={titleId}>
            Model runtime provenance
          </h2>
        </div>
        <span className="rounded-full border border-cyan-300/20 bg-cyan-300/[0.05] px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-cyan-100">
          Live model call
        </span>
      </div>
      <dl className="grid gap-px border-t border-white/[0.06] bg-white/[0.06] sm:grid-cols-2 xl:grid-cols-3">
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Provider</dt>
          <dd className="mt-2 text-xs font-semibold uppercase text-slate-100">
            {provenance.provider}
          </dd>
        </div>
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Requested model</dt>
          <dd className="mt-2 break-all font-mono text-[11px] text-slate-300">
            {provenance.requestedModel}
          </dd>
        </div>
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Returned model</dt>
          <dd className="mt-2 break-all font-mono text-[11px] text-slate-300">
            {provenance.returnedModel}
          </dd>
        </div>
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Provider response ID</dt>
          <dd className="mt-2 break-all font-mono text-[11px] text-slate-300">
            {provenance.providerResponseId}
          </dd>
        </div>
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Token usage</dt>
          <dd className="mt-2 text-[11px] leading-5 text-slate-300">
            {usage
              ? `${usage.inputTokens.toLocaleString("en-US")} in · ${usage.outputTokens.toLocaleString("en-US")} out · ${usage.totalTokens.toLocaleString("en-US")} total`
              : "Not reported by provider"}
          </dd>
        </div>
        <div className="bg-[#0a1513] p-4">
          <dt className="detail-label">Client latency</dt>
          <dd className="mt-2 text-[11px] text-slate-300">
            {provenance.latencyMs.toLocaleString("en-US")} ms
          </dd>
        </div>
      </dl>
      <p className="border-t border-white/[0.06] px-5 py-3 text-[10px] leading-4 text-slate-400">
        Privacy-bounded metadata only. Prompts, credentials, endpoints, raw
        responses, and provider errors are not accepted by this schema.
      </p>
    </section>
  );
}

function AuthControl({ auth }: { auth: AuthSnapshot }) {
  if (auth.status === "authenticated") {
    return (
      <div className="flex items-center gap-2">
        <span className="hidden items-center gap-1.5 rounded-full border border-cyan-300/15 bg-cyan-300/[0.04] px-2.5 py-1.5 text-[10px] font-medium text-cyan-100 lg:inline-flex">
          <Icon className="size-3" name="shield" />
          Steward signed in
        </span>
        <button
          className="rounded-lg border border-white/10 px-2.5 py-1.5 text-[10px] font-medium text-slate-400 transition hover:border-white/20 hover:text-slate-200"
          onClick={signOut}
          type="button"
        >
          Sign out
        </button>
      </div>
    );
  }

  if (auth.status === "loading" || auth.status === "redirecting") {
    return (
      <span
        aria-live="polite"
        className="hidden items-center gap-1.5 rounded-full border border-white/[0.07] px-2.5 py-1.5 text-[10px] text-slate-400 md:inline-flex"
      >
        <Icon className="size-3 animate-spin" name="refresh" />
        {auth.status === "loading" ? "Loading auth" : "Opening sign-in"}
      </span>
    );
  }

  const unavailable = auth.status === "error" && !auth.recoverable;
  const label = unavailable
    ? "Approval authentication unavailable"
    : "Steward sign in";
  return (
    <button
      aria-label={label}
      className="rounded-lg border border-cyan-300/15 bg-cyan-300/[0.04] px-2.5 py-1.5 text-[10px] font-semibold text-cyan-100 transition enabled:hover:border-cyan-300/30 enabled:hover:bg-cyan-300/[0.07] disabled:cursor-not-allowed disabled:border-white/[0.05] disabled:bg-transparent disabled:text-slate-400"
      disabled={unavailable}
      onClick={() => void beginSignIn().catch(() => undefined)}
      title={auth.status === "error" ? auth.message : "Authenticate through Cognito"}
      type="button"
    >
      <Icon className="size-3.5 sm:hidden" name="shield" />
      <span className="hidden sm:inline">
        {unavailable ? "Approval auth unavailable" : "Steward sign in"}
      </span>
    </button>
  );
}

function Metric({
  label,
  value,
  detail,
  icon,
  accent = false,
}: {
  label: string;
  value: string;
  detail: string;
  icon: IconName;
  accent?: boolean;
}) {
  return (
    <article className={`metric-card ${accent ? "metric-accent" : ""}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="metric-label">{label}</p>
          <p className="mt-2 text-[1.75rem] font-semibold leading-none tracking-[-0.04em] text-white">
            {value}
          </p>
        </div>
        <span className="metric-icon">
          <Icon className="size-[18px]" name={icon} />
        </span>
      </div>
      <p className="mt-4 text-xs leading-5 text-slate-400">{detail}</p>
    </article>
  );
}

function PipelineTrace({ trace }: { trace: LoadedAudit["envelope"]["report"]["trace"] }) {
  return (
    <section aria-labelledby="pipeline-title" className="panel overflow-hidden">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Deterministic agent trace</p>
          <h2 className="section-title" id="pipeline-title">
            One bounded integrity pass
          </h2>
        </div>
        <span className="rounded-full border border-emerald-300/20 bg-emerald-300/5 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-200">
          Read → reason → propose
        </span>
      </div>
      <ol className="grid gap-px border-t border-white/[0.06] bg-white/[0.06] sm:grid-cols-2 xl:grid-cols-4">
        {trace.map((step, index) => (
          <li className="relative bg-[#0a1513] px-5 py-4" key={`${step.agent}:${index}`}>
            <div className="flex items-center gap-3">
              <span className="grid size-7 shrink-0 place-items-center rounded-full border border-emerald-300/25 bg-emerald-300/[0.07] font-mono text-[10px] text-emerald-200">
                {String(index + 1).padStart(2, "0")}
              </span>
              <div className="min-w-0">
                <p className="truncate text-xs font-semibold capitalize text-slate-200">
                  {step.agent.replaceAll("-", " ")}
                </p>
                <p className="mt-1 line-clamp-2 text-[11px] leading-4 text-slate-400">
                  {step.produced}
                </p>
              </div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

interface FindingListProps {
  findings: Finding[];
  selectedId?: string;
  onSelect: (finding: Finding) => void;
}

function FindingList({ findings, selectedId, onSelect }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <div className="grid min-h-64 place-items-center px-6 text-center">
        <div>
          <span className="mx-auto grid size-10 place-items-center rounded-xl border border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200">
            <Icon name="check" />
          </span>
          <p className="mt-4 text-sm font-semibold text-slate-200">No matching findings</p>
          <p className="mt-1 text-xs text-slate-400">Adjust the severity or control filter.</p>
        </div>
      </div>
    );
  }

  return (
    <ol aria-label="Audit findings" className="divide-y divide-white/[0.06]">
      {findings.map((finding) => {
        const id = findingIdentity(finding);
        const selected = id === selectedId;
        const blast = finding.detail.blastRadius;
        return (
          <li key={id}>
            <button
              aria-current={selected ? "true" : undefined}
              className={`finding-row ${selected ? "finding-selected" : ""}`}
              onClick={() => onSelect(finding)}
              type="button"
            >
              <span
                aria-hidden="true"
                className={`mt-1.5 size-2 shrink-0 rounded-full severity-dot-${finding.severity}`}
              />
              <span className="min-w-0 flex-1 text-left">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-400">
                    {finding.detail.ruleId ?? typeLabels[finding.type]}
                  </span>
                  <SeverityBadge severity={finding.severity} />
                </span>
                <span className="mt-2 block text-sm font-medium leading-5 text-slate-100">
                  {finding.summary}
                </span>
                <span className="mt-2 flex items-center gap-2 text-[11px] text-slate-400">
                  <span className="truncate font-mono">{shortUrn(finding.subject)}</span>
                  {blast && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span className="shrink-0">{blast.downstream.length} downstream</span>
                    </>
                  )}
                </span>
              </span>
              <Icon
                className={`mt-1 size-4 shrink-0 transition-transform ${
                  selected ? "-rotate-90 text-emerald-200" : "text-slate-400"
                }`}
                name="chevron"
              />
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function BlastRadiusView({ blast }: { blast?: BlastRadius }) {
  if (!blast) {
    return <p className="empty-copy">No lineage projection was attached to this finding.</p>;
  }
  const visible = blast.downstream.slice(0, 6);
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="detail-label">Bounded downstream walk</p>
          <p className="mt-1 text-xs text-slate-400">
            {blast.downstream.length} impacted assets · up to {blast.maxHops} hops
            {blast.truncated ? " · result truncated" : ""}
          </p>
        </div>
        <span className={`impact-badge impact-${blast.impact}`}>{blast.impact} impact</span>
      </div>
      <div className="lineage-map">
        <div className="lineage-root">
          <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-emerald-300/10 text-emerald-200">
            <Icon name="database" />
          </span>
          <span className="min-w-0">
            <span className="block text-[10px] uppercase tracking-[0.14em] text-emerald-300/70">
              affected source
            </span>
            <span className="mt-1 block truncate font-mono text-xs text-slate-100">
              {shortUrn(blast.rootUrn)}
            </span>
          </span>
        </div>
        {visible.length > 0 && (
          <div className="lineage-connector" aria-hidden="true">
            <span />
            <Icon name="arrow" />
          </div>
        )}
        <div className="grid min-w-0 flex-1 gap-2 sm:grid-cols-2">
          {visible.map((asset) => (
            <div className="lineage-node" key={asset.urn}>
              <span className="grid size-7 shrink-0 place-items-center rounded-md bg-white/[0.04] text-slate-400">
                <Icon className="size-3.5" name={asset.urn.includes("dashboard") ? "graph" : "layers"} />
              </span>
              <span className="min-w-0">
                <span className="block truncate font-mono text-[11px] text-slate-300">
                  {shortUrn(asset.urn)}
                </span>
                <span className="mt-0.5 block text-[10px] text-slate-400">
                  hop {asset.minHops}
                </span>
              </span>
            </div>
          ))}
          {blast.downstream.length > visible.length && (
            <div className="grid min-h-12 place-items-center rounded-lg border border-dashed border-white/10 text-[11px] text-slate-400">
              +{blast.downstream.length - visible.length} more assets
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ProvenanceView({ events = [] }: { events?: ProvenanceEvent[] }) {
  if (events.length === 0) {
    return <p className="empty-copy">No stable source provenance was attached.</p>;
  }
  return (
    <ol className="relative ml-2 border-l border-white/10 pl-6">
      {events.map((event, index) => (
        <li className={index === events.length - 1 ? "" : "pb-5"} key={`${event.source}:${event.runId}`}>
          <span
            aria-hidden="true"
            className={`absolute -left-[5px] mt-1.5 size-2.5 rounded-full border-2 border-[#0a1513] ${
              event.status === "conflicting" ? "bg-rose-400" : "bg-emerald-300"
            }`}
          />
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p className="font-mono text-xs text-slate-200">{event.source}</p>
              <p className="mt-1 text-[11px] text-slate-400">
                {formatDate(event.observedAt)} · run {event.runId}
              </p>
            </div>
            <span
              className={`rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] ${
                event.status === "conflicting"
                  ? "border-rose-300/20 bg-rose-300/[0.06] text-rose-200"
                  : "border-emerald-300/15 bg-emerald-300/[0.04] text-emerald-200"
              }`}
            >
              {event.status}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}

function EvidenceDossier({ finding }: { finding: Finding }) {
  const [copied, setCopied] = useState(false);
  const copiedTimer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (copiedTimer.current !== null) window.clearTimeout(copiedTimer.current);
    },
    [],
  );
  const dossier = finding.detail.dossier;
  if (!dossier) {
    return <p className="empty-copy">No signed evidence dossier was attached.</p>;
  }

  const copy = async () => {
    if (!navigator.clipboard) return;
    await navigator.clipboard.writeText(dossier.digest);
    setCopied(true);
    if (copiedTimer.current !== null) window.clearTimeout(copiedTimer.current);
    copiedTimer.current = window.setTimeout(() => {
      setCopied(false);
      copiedTimer.current = null;
    }, 1500);
  };

  return (
    <div>
      <div className="dossier">
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.06] text-cyan-200">
            <Icon name="fingerprint" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-semibold text-slate-100">{dossier.dossierId}</p>
              <span className="inline-flex items-center gap-1.5 text-[10px] font-medium text-emerald-200">
                <Icon className="size-3" name="check" />
                Content bound
              </span>
            </div>
            <p className="mt-2 text-[11px] leading-5 text-slate-400">
              {dossier.evidenceCount} evidence records · generated {formatDate(dossier.generatedAt)}
            </p>
          </div>
        </div>
        <dl className="mt-4 grid gap-2">
          <div className="digest-row">
            <dt>Dossier digest</dt>
            <dd>
              <code>{digestTail(dossier.digest)}</code>
              <button aria-label="Copy dossier digest" className="copy-button" onClick={copy} type="button">
                <Icon className="size-3.5" name={copied ? "check" : "copy"} />
              </button>
            </dd>
          </div>
          <div className="digest-row">
            <dt>Policy digest</dt>
            <dd>
              <code>{digestTail(dossier.policyDigest)}</code>
            </dd>
          </div>
          <div className="digest-row">
            <dt>Finding identity</dt>
            <dd>
              <code>{finding.detail.ruleId ?? typeLabels[finding.type]}</code>
            </dd>
          </div>
        </dl>
      </div>
      <p className="mt-3 flex items-start gap-2 text-[10px] leading-4 text-slate-400">
        <Icon className="mt-px size-3 shrink-0" name="shield" />
        Evidence, policy, expected pre-state, and the proposed action are immutable inputs to approval.
      </p>
    </div>
  );
}

interface ApprovalPanelProps {
  approval?: ApprovalReview;
  source: LoadedAudit["source"];
  authStatus: AuthSnapshot["status"];
  controlLoop?: ControlLoopStatus;
}

function ApprovalPanel({ approval, source, authStatus, controlLoop }: ApprovalPanelProps) {
  const [comment, setComment] = useState("");
  const [status, setStatus] = useState<
    | { kind: "idle" }
    | { kind: "sending"; decision: ApprovalDecision }
    | { kind: "success"; decision: ApprovalDecision; preview: boolean }
    | { kind: "error"; message: string }
  >({ kind: "idle" });

  useEffect(() => {
    setComment("");
    setStatus({ kind: "idle" });
  }, [approval?.approvalId]);

  if (!approval) return null;

  const decide = async (decision: ApprovalDecision) => {
    setStatus({ kind: "sending", decision });
    if (source === "fixture") {
      setStatus({ kind: "success", decision, preview: true });
      return;
    }
    try {
      if (authStatus !== "authenticated") {
        throw new Error("Sign in as an authorized steward before recording a live decision.");
      }
      await submitApprovalDecision({
        approvalId: approval.approvalId,
        decision,
        accessToken: getAccessToken(),
        comment,
      });
      setStatus({ kind: "success", decision, preview: false });
    } catch (error) {
      setStatus({
        kind: "error",
        message: error instanceof Error ? error.message : "The approval decision could not be recorded.",
      });
    }
  };

  const busy = status.kind === "sending";
  const liveLocked = source === "live" && authStatus !== "authenticated";
  const terminal = source === "live" && controlLoop?.status === "SUCCEEDED";
  return (
    <section aria-labelledby="approval-title" className="approval-panel" id="control-review">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow text-amber-200/70">Human control · G6</p>
          <h3 className="mt-1 text-base font-semibold text-white" id="approval-title">
            Review the immutable proposal
          </h3>
        </div>
        <span className="rounded-full border border-emerald-300/15 bg-emerald-300/[0.04] px-2.5 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] text-emerald-200">
          {approval.risk} risk
        </span>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <div className="state-card">
          <p className="detail-label">Observed pre-state</p>
          <p className="mt-2 font-mono text-[11px] leading-5 text-slate-400">
            {approval.before.join("\n") || "No classification tags"}
          </p>
        </div>
        <div className="state-card state-after">
          <p className="detail-label text-emerald-300/70">Expected post-state</p>
          <p className="mt-2 font-mono text-[11px] leading-5 text-slate-200">
            {approval.after.join("\n")}
          </p>
        </div>
      </div>

      <dl className="mt-3 grid gap-2 rounded-xl border border-white/[0.06] bg-black/10 p-3 text-[11px]">
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-400">Target</dt>
          <dd className="truncate font-mono text-slate-300">{approval.targetField}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-400">Action</dt>
          <dd className="truncate font-mono text-slate-300">add {approval.proposedTag}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-400">Plan</dt>
          <dd className="font-mono text-slate-400">{digestTail(approval.planDigest)}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-400">Expires</dt>
          <dd className="text-slate-400">{formatDate(approval.expiresAt)}</dd>
        </div>
      </dl>

      <label className="mt-4 block">
        <span className="detail-label">Steward note · optional</span>
        <textarea
          className="mt-2 min-h-20 w-full resize-y rounded-xl border border-white/10 bg-[#07100e] px-3 py-2 text-xs leading-5 text-slate-200 outline-none transition placeholder:text-slate-400 focus:border-emerald-300/40 focus:ring-2 focus:ring-emerald-300/10"
          disabled={busy || liveLocked || terminal}
          maxLength={500}
          onChange={(event) => setComment(event.target.value)}
          placeholder="Record the decision rationale. Action arguments cannot be edited here."
          value={comment}
        />
      </label>

      {source === "fixture" ? (
        <p className="mt-3 rounded-lg border border-amber-300/15 bg-amber-300/[0.04] px-3 py-2 text-[10px] leading-4 text-amber-100/80">
          Fixture preview is non-mutating: these controls only demonstrate the steward decision
          experience and never call an approval or DataHub write endpoint.
        </p>
      ) : (
        terminal ? (
          <p className="mt-3 rounded-lg border border-emerald-300/15 bg-emerald-300/[0.04] px-3 py-2 text-[10px] leading-4 text-emerald-100/80">
            This workflow is terminal ({controlLoop?.result?.outcome ?? "completed"}); its
            one-use approval controls are now closed.
          </p>
        ) : liveLocked && (
          <p className="mt-3 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.04] px-3 py-2 text-[10px] leading-4 text-cyan-100/80">
            Live decisions are locked until Cognito sign-in. Server-side authorizer and
            approver-group checks still decide whether the request is allowed.
          </p>
        )
      )}

      <div className="mt-4 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <button
          className="decision-button decision-reject"
          disabled={busy || liveLocked || terminal}
          onClick={() => void decide("REJECT")}
          type="button"
        >
          Reject proposal
        </button>
        <button
          className="decision-button decision-approve"
          disabled={busy || liveLocked || terminal}
          onClick={() => void decide("APPROVE")}
          type="button"
        >
          {busy && status.decision === "APPROVE" ? (
            <Icon className="size-4 animate-spin" name="refresh" />
          ) : (
            <Icon className="size-4" name="check" />
          )}
          Approve exact plan
        </button>
      </div>

      <div aria-live="polite" className="mt-3 min-h-5 text-[11px] leading-5">
        {status.kind === "success" && (
          <p className={status.preview ? "text-amber-200" : "text-emerald-200"}>
            {status.preview
              ? `Preview only: ${status.decision.toLowerCase()} selected; no backend decision or mutation was sent.`
              : `${status.decision === "APPROVE" ? "Approval" : "Rejection"} recorded. The worker will re-validate the bound plan before any action.`}
          </p>
        )}
        {status.kind === "error" && <p className="text-rose-200">{status.message}</p>}
      </div>
      <p className="mt-2 text-[10px] leading-4 text-slate-400">
        This client sends only approval ID, decision, and optional note. Mutation arguments remain server-owned.
      </p>
    </section>
  );
}

function FindingDetail({
  finding,
  source,
  authStatus,
  controlLoop,
}: {
  finding?: Finding;
  source: LoadedAudit["source"];
  authStatus: AuthSnapshot["status"];
  controlLoop?: ControlLoopStatus;
}) {
  if (!finding) {
    return (
      <div className="grid min-h-[38rem] place-items-center px-8 text-center">
        <div>
          <Icon className="mx-auto size-7 text-slate-400" name="file" />
          <p className="mt-3 text-sm text-slate-400">Select a finding to inspect its evidence.</p>
        </div>
      </div>
    );
  }
  return (
    <article id="judge-tour-provenance">
      <header className="border-b border-white/[0.06] px-5 py-5 sm:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="rounded-full border border-white/[0.07] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-400">
            {finding.detail.ruleId ?? typeLabels[finding.type]}
          </span>
        </div>
        <h2 className="mt-3 max-w-3xl text-lg font-semibold leading-7 tracking-[-0.02em] text-white">
          {finding.summary}
        </h2>
        <p className="mt-2 break-all font-mono text-[10px] leading-4 text-slate-400">{finding.subject}</p>
      </header>

      <div className="space-y-7 px-5 py-6 sm:px-6">
        <section aria-labelledby="blast-title">
          <h3 className="subsection-title" id="blast-title">
            <Icon name="graph" />
            Blast radius
          </h3>
          <div className="mt-4">
            <BlastRadiusView blast={finding.detail.blastRadius} />
          </div>
        </section>

        <div className="section-rule" />

        <section aria-labelledby="provenance-title">
          <h3 className="subsection-title" id="provenance-title">
            <Icon name="fingerprint" />
            Source provenance
          </h3>
          <p className="mt-2 text-[11px] leading-5 text-slate-400">
            Stable pipeline identity establishes source independence; run IDs remain execution evidence.
          </p>
          <div className="mt-4">
            <ProvenanceView events={finding.detail.provenance} />
          </div>
        </section>

        <div className="section-rule" />

        <section aria-labelledby="dossier-title">
          <h3 className="subsection-title" id="dossier-title">
            <Icon name="file" />
            Evidence dossier
          </h3>
          <div className="mt-4">
            <EvidenceDossier finding={finding} />
          </div>
        </section>

        {finding.recommendation && (
          <>
            <div className="section-rule" />
            <section aria-labelledby="recommendation-title">
              <h3 className="subsection-title" id="recommendation-title">
                <Icon name="spark" />
                Governed recommendation
              </h3>
              <p className="mt-3 rounded-xl border border-violet-300/10 bg-violet-300/[0.04] px-4 py-3 text-xs leading-5 text-slate-300">
                {finding.recommendation}
              </p>
            </section>
          </>
        )}

        {finding.detail.ruleId === "G6" && (
          <ApprovalPanel
            approval={finding.detail.approval}
            authStatus={authStatus}
            controlLoop={controlLoop}
            source={source}
          />
        )}
      </div>
    </article>
  );
}

function jsonRecord(value: JsonValue | undefined): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

function jsonArray(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? value : [];
}

function jsonText(value: JsonValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function shortDigest(value: string | undefined): string {
  return value ? `${value.slice(0, 16)}…${value.slice(-8)}` : "Pending";
}

function JsonEvidence({ value }: { value: JsonValue }) {
  const serialized = JSON.stringify(value, null, 2) ?? "null";
  return (
    <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-white/[0.06] bg-black/20 p-3 text-[10px] leading-4 text-slate-300">
      {serialized.length > 3200 ? `${serialized.slice(0, 3200)}\n… bounded UI projection` : serialized}
    </pre>
  );
}

function DigestPill({ label, value }: { label: string; value?: string }) {
  return (
    <span
      className="inline-flex min-w-0 max-w-full items-center gap-1.5 overflow-hidden rounded-full border border-white/[0.07] bg-white/[0.025] px-2.5 py-1 font-mono text-[9px] text-slate-400"
      title={value}
    >
      <span className="shrink-0 font-sans uppercase tracking-[0.12em] text-slate-300">{label}</span>
      <span className="min-w-0 truncate">{shortDigest(value)}</span>
    </span>
  );
}

type AgentStackPanelProps = {
  status?: RuntimeControlLoopStatus;
  authStatus: AuthSnapshot["status"];
  busy: boolean;
  rerunPiiProof: boolean;
  onImprove: () => void;
  onDecision: (decision: "APPROVE" | "REJECT") => void;
};

function AgentStackPanel({
  status,
  authStatus,
  busy,
  rerunPiiProof,
  onImprove,
  onDecision,
}: AgentStackPanelProps) {
  const result = status?.agentStackResult;
  const context = result?.context;
  const contextReceipts = jsonArray(context?.receipts);
  const entityUrns = jsonArray(context?.entityUrns).filter(
    (value): value is string => typeof value === "string",
  );
  const workflow = jsonArray(result?.skills.workflow).filter(
    (value): value is string => typeof value === "string",
  );
  const expectedWorkflow = workflow.length > 0
    ? workflow
    : [
        "datahub-search",
        "datahub-lineage",
        "datahub-quality",
        "datahub-audit",
        "datahub-enrich",
      ];
  const analytics = result?.analytics;
  const analyticsEvents = jsonArray(analytics?.events);
  const quality = jsonRecord(analytics?.contextQuality);
  const improve = status?.improveContext;
  const improveResult =
    improve?.schemaVersion === "archon.datahub-improve-context-projection/v2"
      ? improve
      : undefined;
  const improveEvents = improveResult?.events ?? [];
  const plan = status?.plan;
  const approval = status?.approval;
  const canImprove =
    status?.status === "AWAITING_IMPROVEMENT" &&
    improve?.schemaVersion === "archon.datahub-improve-context-capability/v2" &&
    improve.status === "AVAILABLE";
  const canDecide =
    status?.status === "AWAITING_APPROVAL" &&
    approval?.status === "PENDING" &&
    authStatus === "authenticated";

  return (
    <section
      aria-labelledby="agent-stack-title"
      className="panel mt-6 overflow-hidden"
      data-testid="agent-stack-panel"
      id="agent-stack"
    >
      <div className="panel-heading border-b border-white/[0.06]">
        <div>
          <p className="eyebrow">Closed-loop DataHub context flywheel</p>
          <h2 className="section-title" id="agent-stack-title">
            DataHub Agent Stack · live, receipt-bound execution
          </h2>
          <p className="mt-2 max-w-3xl text-[11px] leading-5 text-slate-400">
            MCP reads feed Agent Context Kit; five pinned Skills ground the Analytics Agent;
            <code className="mx-1 text-emerald-200">/improve-context</code>
            remains proposal-only until a steward approves the exact before/after digest.
          </p>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          {status && (
            <span className="status-pill status-success" data-testid="agent-runtime-profile">
              {status.runtimeEvidence.runtimeBinding.profileId === "cloud"
                ? "DataHub Cloud · managed"
                : "DataHub Core · ephemeral"}
            </span>
          )}
          <span className={`status-pill ${status ? "status-success" : "status-neutral"}`}>
            {status ? `${status.status} · ${status.phase}` : "Awaiting live run"}
          </span>
          <DigestPill label="run" value={status?.runtimeEvidence.digest} />
        </div>
      </div>

      <div aria-live="polite" className="grid gap-4 p-4 lg:grid-cols-2 xl:grid-cols-4">
        <article className="rounded-xl border border-white/[0.06] bg-white/[0.018] p-4">
          <p className="eyebrow">DataHub MCP Server</p>
          <h3 className="mt-2 text-sm font-semibold text-white">Bounded graph reads</h3>
          <p className="mt-2 text-[11px] leading-5 text-slate-400">
            {contextReceipts.length > 0
              ? `${contextReceipts.length} sanitized tool receipts returned by the ACK SDK.`
              : "Search, entities, schema, lineage and quality receipts will appear here."}
          </p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {contextReceipts.slice(0, 8).map((receipt, index) => {
              const projected = jsonRecord(receipt);
              return (
                <span className="status-pill status-neutral" key={`${jsonText(projected?.tool) ?? "tool"}-${index}`}>
                  {jsonText(projected?.tool) ?? `receipt-${index + 1}`}
                </span>
              );
            })}
          </div>
          <DigestPill label="context" value={jsonText(context?.digest)} />
        </article>

        <article className="rounded-xl border border-white/[0.06] bg-white/[0.018] p-4">
          <p className="eyebrow">Agent Context Kit</p>
          <h3 className="mt-2 text-sm font-semibold text-white">Provenance envelope</h3>
          <p className="mt-2 text-[11px] leading-5 text-slate-400">
            {entityUrns.length > 0
              ? `${entityUrns.length} canonical dataset URN${entityUrns.length === 1 ? "" : "s"} selected.`
              : "Unknown stays unknown until a canonical dataset is resolved."}
          </p>
          {entityUrns.slice(0, 3).map((urn) => (
            <p className="mt-2 break-all font-mono text-[9px] leading-4 text-cyan-100/80" key={urn}>
              {urn}
            </p>
          ))}
          <p className="mt-3 text-[10px] text-slate-400">
            Unknown preserved: <strong className="text-slate-200">{context?.unknownPreserved === true ? "yes" : "no"}</strong>
          </p>
        </article>

        <article className="rounded-xl border border-white/[0.06] bg-white/[0.018] p-4">
          <p className="eyebrow">DataHub Skills</p>
          <h3 className="mt-2 text-sm font-semibold text-white">Five-step grounded workflow</h3>
          <ol className="mt-3 space-y-2">
            {expectedWorkflow.map((skill, index) => (
              <li className="flex items-center gap-2 text-[10px] text-slate-300" key={skill}>
                <span className={`flex size-5 items-center justify-center rounded-full ${result ? "bg-emerald-300/10 text-emerald-200" : "bg-white/[0.04] text-slate-500"}`}>
                  {result ? <Icon className="size-3" name="check" /> : index + 1}
                </span>
                <span className="font-mono">{skill}</span>
              </li>
            ))}
          </ol>
          <DigestPill label="skills" value={jsonText(result?.skills.digest)} />
        </article>

        <article className="rounded-xl border border-white/[0.06] bg-white/[0.018] p-4">
          <p className="eyebrow">Analytics Agent</p>
          <h3 className="mt-2 text-sm font-semibold text-white">SQL · result · chart trace</h3>
          <div className="mt-3 flex items-end gap-3">
            <span className="text-3xl font-semibold text-gradient">
              {typeof quality?.score === "number" ? `${quality.score}/5` : "—"}
            </span>
            <span className="pb-1 text-[10px] text-slate-400">
              {jsonText(quality?.label) ?? "Context score pending"}
            </span>
          </div>
          <p className="mt-2 text-[10px] leading-4 text-slate-400">
            {jsonText(quality?.reason) ?? `${analyticsEvents.length} bounded streaming events`}
          </p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {analyticsEvents.map((event, index) => {
              const projected = jsonRecord(event);
              return (
                <span className="status-pill status-neutral" key={`${jsonText(projected?.event) ?? "event"}-${index}`}>
                  {jsonText(projected?.event) ?? `event-${index + 1}`}
                </span>
              );
            })}
          </div>
          <DigestPill label="analytics" value={jsonText(analytics?.digest)} />
        </article>
      </div>

      <div className="grid gap-4 border-t border-white/[0.06] p-4 lg:grid-cols-2">
        <article className="rounded-xl border border-cyan-300/10 bg-cyan-300/[0.025] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="eyebrow">Explicit bonus operation</p>
              <h3 className="mt-2 text-sm font-semibold text-white">/improve-context proposal</h3>
              <p className="mt-2 max-w-xl text-[11px] leading-5 text-slate-400">
                The opaque Analytics Agent handle remains backend-only. This button dispatches a
                separate profile-bound read-only job; its rotated handle is stripped before projection.
              </p>
            </div>
            <button
              className="run-button"
              disabled={!canImprove || busy}
              onClick={onImprove}
              type="button"
            >
              <Icon className={busy ? "size-4 animate-spin" : "size-4"} name={busy ? "refresh" : "spark"} />
              Generate proposal
            </button>
          </div>
          {improveResult && (
            <div className="mt-3">
              <div className="flex flex-wrap gap-2">
                <span className="status-pill status-success">Proposal only</span>
                <DigestPill label="proposal" value={improveResult.resultDigest} />
                <DigestPill label="receipt" value={status?.plan?.improveReceiptDigest} />
              </div>
              {improveEvents.length > 0 && <JsonEvidence value={improveEvents} />}
            </div>
          )}
        </article>

        <article className="rounded-xl border border-amber-300/10 bg-amber-300/[0.025] p-4">
          <p className="eyebrow">Human authority boundary</p>
          <h3 className="mt-2 text-sm font-semibold text-white">Governed PII tag write-back</h3>
          {plan ? (
            <>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <div className="rounded-lg border border-white/[0.06] bg-black/15 p-3">
                  <p className="text-[9px] uppercase tracking-[0.13em] text-slate-500">Verified before</p>
                  <p className="mt-2 break-all font-mono text-[10px] text-slate-300">
                    {plan.expectedBefore.tagUrns.join(", ") || "No tags"}
                  </p>
                  <DigestPill label="before" value={plan.expectedBeforeDigest} />
                </div>
                <div className="rounded-lg border border-emerald-300/10 bg-emerald-300/[0.025] p-3">
                  <p className="text-[9px] uppercase tracking-[0.13em] text-emerald-200/70">Expected after</p>
                  <p className="mt-2 break-all font-mono text-[10px] text-emerald-100">
                    {plan.expectedAfter.tagUrns.join(", ")}
                  </p>
                  <DigestPill label="after" value={plan.expectedAfterDigest} />
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <button className="run-button" disabled={!canDecide || busy} onClick={() => onDecision("APPROVE")} type="button">
                  <Icon className="size-4" name="check" /> Approve exact plan
                </button>
                <button className="secondary-button" disabled={!canDecide || busy} onClick={() => onDecision("REJECT")} type="button">
                  Reject proposal
                </button>
              </div>
              <p className="mt-2 text-[10px] text-slate-400">
                {authStatus === "authenticated"
                  ? `Approval ${approval?.status.toLowerCase() ?? "pending"}; mutation authority is isolated from the control role.`
                  : "Cognito steward authentication is required; decisions fail closed."}
              </p>
            </>
          ) : (
            <p className="mt-3 text-[11px] leading-5 text-slate-400">
              The exact plan appears only after verified tag-read and improve-context receipts.
            </p>
          )}
        </article>
      </div>

      {(status?.remediation || rerunPiiProof) && (
        <div className="border-t border-emerald-300/10 bg-emerald-300/[0.025] p-4" data-testid="governed-proof">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className="size-4 text-emerald-200" name="check" />
            <strong className="text-xs text-emerald-100">
              {rerunPiiProof
                ? "Run-again proof: a new ACK context read observed PII on the source column."
                : status?.contextDelta
                  ? "Official DataHub MCP add_tags + post-write ACK and Analytics rerun verified."
                  : "Official DataHub MCP add_tags verified; post-write context verification is running."}
            </strong>
            {status?.remediation?.mutationExecutor === "official-datahub-mcp" && (
              <span className="status-pill status-success">Official MCP · add_tags</span>
            )}
            {status?.remediation?.authorizationEvidence && (
              <span className="status-pill status-success" data-testid="kms-authority-proof">
                KMS-signed authority verified
              </span>
            )}
            {status?.skillCompletion && (
              <span className="status-pill status-success" data-testid="enrich-skill-completion">
                datahub-enrich · executed-with-human-approval
              </span>
            )}
            <DigestPill label="receipt" value={status?.remediation?.receiptDigest} />
            <DigestPill label="KMS key ref" value={status?.remediation?.authorizationEvidence.keyReferenceDigest} />
            <DigestPill label="signed envelope" value={status?.remediation?.authorizationEvidence.envelopeDigest} />
            <DigestPill label="skill artifact" value={status?.skillCompletion?.sourceArtifactDigest} />
            <DigestPill label="skill preview" value={status?.skillCompletion?.previewSkillReceiptDigest} />
            <DigestPill label="skill grounding" value={status?.skillCompletion?.skillGroundingDigest} />
            <DigestPill label="skill execution" value={status?.skillCompletion?.officialMcpMutationReceiptDigest} />
            <DigestPill label="policy" value={status?.remediation?.policyDigest} />
            <DigestPill label="approval" value={status?.remediation?.officialMcpMutation.approvalDigest} />
            <DigestPill label="after" value={status?.remediation?.afterDigest} />
          </div>
          {status?.contextDelta && (
            <div className="mt-3 grid gap-2 sm:grid-cols-2" data-testid="context-delta">
              <div className="rounded-lg border border-white/[0.06] bg-black/15 p-3">
                <p className="text-[9px] uppercase tracking-[0.13em] text-slate-500">
                  ACK context · changed
                </p>
                <DigestPill label="before" value={status.contextDelta.beforeContextDigest} />
                <DigestPill label="after" value={status.contextDelta.afterContextDigest} />
              </div>
              <div className="rounded-lg border border-emerald-300/10 bg-emerald-300/[0.025] p-3">
                <p className="text-[9px] uppercase tracking-[0.13em] text-emerald-200/70">
                  Analytics result · changed
                </p>
                <DigestPill label="before" value={status.contextDelta.beforeAnalyticsDigest} />
                <DigestPill label="after" value={status.contextDelta.afterAnalyticsDigest} />
              </div>
            </div>
          )}
          <p className="mt-2 text-[10px] leading-4 text-slate-400">
            The profile-bound read companion and ACK path remain read-only. A separate writer-only official MCP process executed the approved tool,
            then fresh source reads proved PII; no automatic downstream tag propagation is claimed.
          </p>
        </div>
      )}
    </section>
  );
}

export function App() {
  const auth = useSyncExternalStore(subscribeToAuth, getAuthSnapshot, getAuthSnapshot);
  const [audit] = useState<LoadedAudit>({
    envelope: previewAudit,
    source: "fixture",
    fallbackReason:
      "Deterministic showcase mode: this regression fixture is non-mutating. The live DataHub Agent Stack is shown in its dedicated panel.",
  });
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [type, setType] = useState<FindingType | "all">("all");
  const [query, setQuery] = useState(AGENT_STACK_DATASET_URN);
  const [question, setQuestion] = useState(AGENT_STACK_QUESTION);
  const [loading, setLoading] = useState(false);
  const [runError, setRunError] = useState<string>();
  const [controlLoop, setControlLoop] = useState<ControlLoopStatus>();
  const [runtimeRun, setRuntimeRun] = useState<RuntimeControlLoopStatus>();
  const [runtimeSession, setRuntimeSession] =
    useState<RuntimeSessionStatus>();
  const [lastRemediatedAuditId, setLastRemediatedAuditId] = useState<string>();
  const [rerunOriginAuditId, setRerunOriginAuditId] = useState<string>();
  const [selectedId, setSelectedId] = useState(
    findingIdentity(previewAudit.report.findings[0]!),
  );
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    void initializeAuthentication();
  }, []);

  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );

  const report = audit.envelope.report;
  const filtered = useMemo(
    () =>
      report.findings.filter(
        (finding) =>
          (severity === "all" || finding.severity === severity) &&
          (type === "all" || finding.type === type),
      ),
    [report.findings, severity, type],
  );
  const selected =
    filtered.find((finding) => findingIdentity(finding) === selectedId) ?? filtered[0];
  const runtimeContextHasPii = (
    JSON.stringify(runtimeRun?.agentStackResult?.context) ?? ""
  ).includes("urn:li:tag:PII");
  const rerunPiiProof = Boolean(
    rerunOriginAuditId &&
      runtimeRun &&
      runtimeRun.auditId !== rerunOriginAuditId &&
      runtimeContextHasPii,
  );
  const runtimeRunActive = Boolean(
    runtimeRun &&
      ["RUNNING", "AWAITING_IMPROVEMENT", "AWAITING_APPROVAL"].includes(
        runtimeRun.status,
      ),
  );
  const reviewProofTarget =
    controlLoop?.status === "SUCCEEDED" &&
    controlLoop.result &&
    controlLoop.result.outcome !== "READ_ONLY_COMPLETE"
      ? "judge-tour-terminal-proof"
      : selected?.detail.approval
        ? "control-review"
        : "judge-evidence";

  useEffect(() => {
    if (selected && findingIdentity(selected) !== selectedId) {
      setSelectedId(findingIdentity(selected));
    }
  }, [selected, selectedId]);

  const high = report.findings.filter((finding) => finding.severity === "high").length;
  const impacted = new Set(
    report.findings.flatMap((finding) =>
      (finding.detail.blastRadius?.downstream ?? []).map((asset) => asset.urn),
    ),
  ).size;
  const lineageRate =
    report.classification.totalEntities > 0
      ? Math.round((report.classification.withLineage / report.classification.totalEntities) * 100)
      : 0;
  const integrityScore = Math.max(
    0,
    100 -
      report.findings.reduce(
        (sum, finding) => sum + { high: 8, medium: 3, low: 1 }[finding.severity],
        0,
      ),
  );

  const assertRunnableSession = (): RuntimeSessionStatus | undefined => {
    if (auth.status !== "authenticated") {
      setRunError("Sign in as a judge or steward before starting the live Agent Stack.");
      return undefined;
    }
    if (!runtimeSession) {
      setRunError("Launch a pinned DataHub runtime before running the live Agent Stack.");
      return undefined;
    }
    if (!runtimeSession.canRun) {
      setRunError(
        runtimeSession.state === "STARTING"
          ? "The pinned runtime is still starting. Wait for READY."
          : "This pinned runtime is not runnable. Start a new session.",
      );
      return undefined;
    }
    return runtimeSession;
  };

  const applyRuntimeResult = (result: RuntimeControlLoopStatus) => {
    setRuntimeRun(result);
    if (result.status === "FAILED") {
      setRunError(`Agent Stack failed closed (${result.error?.code ?? "unknown"}).`);
    }
    if (result.status === "SUCCEEDED" && result.remediation?.verified) {
      setLastRemediatedAuditId(result.auditId);
    }
  };

  const runAudit = async (event?: FormEvent) => {
    event?.preventDefault();
    const session = assertRunnableSession();
    if (!session) return;
    if (query !== AGENT_STACK_DATASET_URN || question !== AGENT_STACK_QUESTION) {
      setRunError("Use the canonical deterministic dataset URN and analytics question shown below.");
      return;
    }
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setLoading(true);
    setRunError(undefined);
    setControlLoop(undefined);
    setRerunOriginAuditId(lastRemediatedAuditId);
    setRuntimeRun(undefined);
    try {
      const result = await loadRuntimeAgentStack(
        query,
        question,
        session.sessionId,
        getAccessToken(),
        nextController.signal,
        setRuntimeRun,
      );
      applyRuntimeResult(result);
    } catch (error) {
      if (!nextController.signal.aborted) {
        setRunError(error instanceof Error ? error.message : "The Agent Stack could not be completed.");
      }
    } finally {
      if (!nextController.signal.aborted) setLoading(false);
    }
  };

  const requestImproveProposal = async () => {
    if (!runtimeRun || runtimeRun.status !== "AWAITING_IMPROVEMENT") return;
    if (!assertRunnableSession()) return;
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setLoading(true);
    setRunError(undefined);
    try {
      const result = await requestRuntimeImproveContext(
        runtimeRun.auditId,
        getAccessToken(),
        nextController.signal,
        setRuntimeRun,
      );
      applyRuntimeResult(result);
    } catch (error) {
      if (!nextController.signal.aborted) {
        setRunError(error instanceof Error ? error.message : "The improve-context proposal failed.");
      }
    } finally {
      if (!nextController.signal.aborted) setLoading(false);
    }
  };

  const decideRuntimePlan = async (decision: "APPROVE" | "REJECT") => {
    if (!runtimeRun || runtimeRun.status !== "AWAITING_APPROVAL") return;
    if (!assertRunnableSession()) return;
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setLoading(true);
    setRunError(undefined);
    try {
      await submitRuntimeApproval(
        runtimeRun.auditId,
        decision,
        getAccessToken(),
        decision === "APPROVE"
          ? "Judge approved the exact content-addressed PII tag plan."
          : "Judge rejected the proposed write-back.",
        nextController.signal,
      );
      const result = await resumeRuntimeAgentStack(
        runtimeRun.auditId,
        getAccessToken(),
        nextController.signal,
        setRuntimeRun,
      );
      applyRuntimeResult(result);
    } catch (error) {
      if (!nextController.signal.aborted) {
        setRunError(error instanceof Error ? error.message : "The governed decision failed.");
      }
    } finally {
      if (!nextController.signal.aborted) setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07100e] text-slate-300">
      <a className="skip-link" href="#main-content">
        Skip to integrity overview
      </a>
      <div className="ambient-grid" aria-hidden="true" />
      <aside className="sidebar">
        <a aria-label="Archon home" className="brand-mark" href="#overview">
          <span className="brand-glyph">
            <Icon className="size-5" name="shield" />
          </span>
          <span className="hidden sm:block">
            <span className="block text-sm font-semibold tracking-[-0.02em] text-white">Archon</span>
            <span className="mt-0.5 block text-[9px] uppercase tracking-[0.15em] text-slate-400">
              Control plane
            </span>
          </span>
        </a>
        <nav aria-label="Primary" className="mt-10 flex flex-1 flex-col gap-2">
          <a
            aria-label="Overview"
            className="nav-item nav-active"
            href="#overview"
          >
            <Icon name="graph" />
            <span className="hidden sm:inline">Overview</span>
          </a>
          <a aria-label="Findings" className="nav-item" href="#findings">
            <Icon name="warning" />
            <span className="hidden sm:inline">Findings</span>
          </a>
          <a
            aria-label="Review remediation"
            className="nav-item"
            href="#control-review"
          >
            <Icon name="fingerprint" />
            <span className="hidden sm:inline">Review</span>
          </a>
        </nav>
        <div className="hidden rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 sm:block">
          <div className="flex items-center gap-2 text-[10px] text-slate-400">
            <Icon className="size-3.5 text-emerald-300" name="shield" />
            Zero-trust writes
          </div>
          <p className="mt-2 text-[9px] leading-4 text-slate-400">
            Read and mutation credentials are isolated.
          </p>
        </div>
      </aside>

      <div className="pl-[4.5rem] sm:pl-52">
        <header className="topbar flex-wrap sm:flex-nowrap">
          <form
            className="relative order-2 min-w-0 basis-full sm:order-1 sm:basis-auto sm:max-w-md sm:flex-1"
            onSubmit={(event) => void runAudit(event)}
          >
            <label className="sr-only" htmlFor="catalog-scope">
              Canonical DataHub dataset URN
            </label>
            <Icon
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400"
              name="search"
            />
            <input
              className="w-full rounded-xl border border-white/[0.07] bg-white/[0.025] py-2.5 pl-10 pr-3 text-xs text-slate-200 outline-none transition placeholder:text-slate-400 focus:border-emerald-300/30 focus:bg-white/[0.04] focus:ring-2 focus:ring-emerald-300/[0.07]"
              id="catalog-scope"
              maxLength={256}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Scope by asset, domain, or platform"
              type="search"
              value={query}
            />
          </form>
          <div className="order-1 flex w-full min-w-0 items-center justify-end gap-2 sm:order-2 sm:w-auto sm:shrink-0 sm:gap-3">
            <AuthControl auth={auth} />
            <SourceBadge source={runtimeRun ? "live" : audit.source} />
            <button
              aria-label={loading ? "Header Agent Stack in progress" : runtimeRun ? "Run Agent Stack again from header" : "Run Agent Stack from header"}
              className="run-button"
              disabled={
                loading ||
                runtimeRunActive ||
                query !== AGENT_STACK_DATASET_URN ||
                question !== AGENT_STACK_QUESTION ||
                runtimeSession?.canRun !== true ||
                auth.status !== "authenticated"
              }
              id="judge-tour-run-audit"
              onClick={() => void runAudit()}
              title={RUN_DISABLED_HINT}
              type="button"
            >
              <Icon
                className={loading ? "size-4 animate-spin" : "size-4"}
                name={loading ? "refresh" : runtimeRun ? "refresh" : "play"}
              />
              <span className="hidden sm:inline">
                {loading ? "Running…" : runtimeRun ? "Run again" : "Run Agent Stack"}
              </span>
            </button>
          </div>
        </header>

        <main className="mx-auto max-w-[100rem] px-4 py-7 sm:px-6 lg:px-8 lg:py-9" id="main-content">
          <section aria-labelledby="overview-title" id="overview">
            <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
              <div className="max-w-3xl">
                <p className="eyebrow">DataHub context graph integrity</p>
                <h1
                  className="mt-3 text-3xl font-semibold leading-[1.1] tracking-[-0.045em] text-white sm:text-4xl"
                  id="overview-title"
                >
                  Know when your catalog
                  <span className="text-gradient"> stops telling one truth.</span>
                </h1>
                <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400">
                  Archon detects governance regressions and cross-source contradictions, traces
                  their downstream blast radius, then prepares evidence-bound remediation for a
                  human steward.
                </p>
              </div>
              <div className="score-card">
                <div
                  className="score-ring"
                  aria-label={`Integrity score ${integrityScore} out of 100`}
                  role="img"
                >
                  <svg aria-hidden="true" className="score-ring-graphic" viewBox="0 0 40 40">
                    <circle
                      cx="20"
                      cy="20"
                      fill="none"
                      pathLength="100"
                      r="16"
                      stroke="rgba(255, 255, 255, 0.06)"
                      strokeWidth="3"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      fill="none"
                      pathLength="100"
                      r="16"
                      stroke="#6ee7b7"
                      strokeDasharray={`${integrityScore} ${100 - integrityScore}`}
                      strokeLinecap="round"
                      strokeWidth="3"
                    />
                  </svg>
                  <span className="relative">{integrityScore}</span>
                </div>
                <div>
                  <p className="text-xs font-semibold text-slate-100">Integrity posture</p>
                  <p className="mt-1 text-[11px] text-slate-400">
                    {high > 0 ? `${high} high-priority controls need review` : "No high-priority controls"}
                  </p>
                </div>
              </div>
            </div>

            <div aria-live="polite" className="mt-5">
              {auth.status === "error" && (
                <div className="mb-2 flex items-start gap-2 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] px-3 py-2 text-[11px] leading-5 text-cyan-100/80">
                  <Icon className="mt-0.5 size-3.5 shrink-0" name="shield" />
                  Approval authentication is fail-closed: {auth.message}
                </div>
              )}
              {controlLoop && (
                <>
                  <div
                    className={`mb-2 flex items-start gap-2 rounded-xl border px-3 py-2 text-[11px] leading-5 ${
                      controlLoop.status === "SUCCEEDED"
                        ? "border-emerald-300/15 bg-emerald-300/[0.04] text-emerald-100/80"
                        : ["FAILED", "TIMED_OUT", "ABORTED"].includes(controlLoop.status)
                          ? "border-rose-300/15 bg-rose-300/[0.04] text-rose-200"
                          : "border-cyan-300/15 bg-cyan-300/[0.04] text-cyan-100/80"
                    }`}
                  >
                    <Icon
                      className="mt-0.5 size-3.5 shrink-0"
                      name={
                        controlLoop.status === "SUCCEEDED"
                          ? "check"
                          : ["FAILED", "TIMED_OUT", "ABORTED"].includes(controlLoop.status)
                            ? "warning"
                            : "shield"
                      }
                    />
                    {controlLoopMessage(controlLoop)}
                  </div>
                  <TerminalEvidence status={controlLoop} />
                </>
              )}
              {((audit.fallbackReason && !runtimeRun) || runError) && (
                <div
                  className={`flex items-start gap-2 rounded-xl border px-3 py-2 text-[11px] leading-5 ${
                    runError
                      ? "border-rose-300/15 bg-rose-300/[0.04] text-rose-200"
                      : "border-amber-300/15 bg-amber-300/[0.04] text-amber-100/80"
                  }`}
                >
                  <Icon className="mt-0.5 size-3.5 shrink-0" name={runError ? "warning" : "database"} />
                  {runError ?? audit.fallbackReason}
                </div>
              )}
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                detail={`${Object.keys(report.classification.platforms).length} connected platforms`}
                icon="database"
                label="Catalogued assets"
                value={report.classification.totalEntities.toLocaleString("en-US")}
              />
              <Metric
                accent={high > 0}
                detail={`${high} high severity · ${report.findings.length - high} triage queue`}
                icon="warning"
                label="Open findings"
                value={String(report.findings.length).padStart(2, "0")}
              />
              <Metric
                detail="Deduplicated across every open finding"
                icon="layers"
                label="Downstream exposure"
                value={String(impacted).padStart(2, "0")}
              />
              <Metric
                detail={`${report.classification.withLineage.toLocaleString("en-US")} assets with lineage`}
                icon="graph"
                label="Lineage mapped"
                value={`${lineageRate}%`}
              />
            </div>
          </section>

          <RuntimeControl
            getAccessToken={
              auth.status === "authenticated" ? getAccessToken : undefined
            }
            onSessionChange={setRuntimeSession}
          />

          <section aria-labelledby="agent-input-title" className="panel mt-6 p-4">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-end">
              <div className="min-w-0 flex-1">
                <p className="eyebrow">Deterministic judge inputs</p>
                <h2 className="section-title" id="agent-input-title">Run the canonical Agent Stack journey</h2>
                <label className="mt-4 block text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400" htmlFor="agent-dataset-urn">
                  Dataset URN
                </label>
                <input
                  className="mt-2 w-full rounded-xl border border-white/[0.07] bg-black/15 px-3 py-2.5 font-mono text-[10px] text-slate-200 outline-none focus:border-emerald-300/30 focus:ring-2 focus:ring-emerald-300/[0.07]"
                  id="agent-dataset-urn"
                  maxLength={1024}
                  onChange={(event) => setQuery(event.target.value)}
                  value={query}
                />
              </div>
              <div className="min-w-0 flex-[1.4]">
                <label className="block text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400" htmlFor="agent-question">
                  Analytics question
                </label>
                <textarea
                  className="mt-2 min-h-20 w-full resize-y rounded-xl border border-white/[0.07] bg-black/15 px-3 py-2.5 text-xs leading-5 text-slate-200 outline-none focus:border-emerald-300/30 focus:ring-2 focus:ring-emerald-300/[0.07]"
                  id="agent-question"
                  maxLength={512}
                  onChange={(event) => setQuestion(event.target.value)}
                  value={question}
                />
              </div>
              <button
                aria-label={loading ? "Canonical Agent Stack in progress" : runtimeRun ? "Run canonical Agent Stack again" : "Run canonical Agent Stack"}
                className="run-button shrink-0"
                disabled={
                  loading || runtimeRunActive ||
                  query !== AGENT_STACK_DATASET_URN ||
                  question !== AGENT_STACK_QUESTION ||
                  runtimeSession?.canRun !== true ||
                  auth.status !== "authenticated"
                }
                onClick={() => void runAudit()}
                title={RUN_DISABLED_HINT}
                type="button"
              >
                <Icon className={loading ? "size-4 animate-spin" : "size-4"} name={loading ? "refresh" : runtimeRun ? "refresh" : "play"} />
                {loading ? "Running…" : runtimeRun ? "Run again" : "Run Agent Stack"}
              </button>
            </div>
            <p className="mt-4 border-t border-white/[0.06] pt-3 text-[11px] leading-5 text-slate-400">
              <span className="font-semibold text-slate-300">
                Run Agent Stack stays disabled on this public demo by design, not by failure.
              </span>{" "}
              {RUN_DISABLED_HINT} Everything on this page is already the output of a completed
              pass: open the findings, prepare and verify the evidence pack, then reject the
              proposal at the human authority boundary. The demo video shows the live path
              executing against DataHub Core v1.6.0, and the README documents how to run it
              against your own instance.
            </p>
          </section>

          <AgentStackPanel
            authStatus={auth.status}
            busy={loading}
            onDecision={(decision) => void decideRuntimePlan(decision)}
            onImprove={() => void requestImproveProposal()}
            rerunPiiProof={rerunPiiProof}
            status={runtimeRun}
          />

          <div className="mt-6">
            <PipelineTrace trace={report.trace} />
          </div>

          <ModelProvenancePanel provenance={report.modelProvenance} />

          <EvidencePack audit={audit} controlLoop={controlLoop} />

          <section aria-labelledby="findings-title" className="mt-6" id="findings">
            <div className="panel-heading panel rounded-b-none border-b-0">
              <div>
                <p className="eyebrow">Evidence explorer</p>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <h2 className="section-title mt-0" id="findings-title">
                    Integrity findings
                  </h2>
                  <span className="source-badge source-fixture">Deterministic fixture evidence</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <label className="filter-control">
                  <span className="sr-only">Filter by severity</span>
                  <select
                    aria-label="Filter findings by severity"
                    onChange={(event) => setSeverity(event.target.value as Severity | "all")}
                    value={severity}
                  >
                    <option value="all">All severity</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <Icon name="chevron" />
                </label>
                <label className="filter-control">
                  <span className="sr-only">Filter by control type</span>
                  <select
                    aria-label="Filter findings by type"
                    onChange={(event) => setType(event.target.value as FindingType | "all")}
                    value={type}
                  >
                    <option value="all">All controls</option>
                    <option value="contradiction">Contradictions</option>
                    <option value="lineage_gap">Lineage gaps</option>
                    <option value="governance_violation">Governance</option>
                  </select>
                  <Icon name="chevron" />
                </label>
              </div>
            </div>
            <div className="grid overflow-hidden rounded-b-2xl border border-white/[0.07] bg-[#0a1513]/95 xl:grid-cols-[22rem_minmax(0,1fr)]">
              <div className="max-h-[64rem] overflow-y-auto border-b border-white/[0.06] xl:border-b-0 xl:border-r">
                <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3 text-[10px] uppercase tracking-[0.13em] text-slate-400">
                  <span>{filtered.length} results</span>
                  <span>severity ↓</span>
                </div>
                <FindingList
                  findings={[...filtered].sort(
                    (a, b) => severityRank[b.severity] - severityRank[a.severity],
                  )}
                  onSelect={(finding) => setSelectedId(findingIdentity(finding))}
                  selectedId={selected ? findingIdentity(selected) : undefined}
                />
              </div>
              <div className="min-w-0">
                <FindingDetail
                  finding={selected}
                  authStatus={auth.status}
                  controlLoop={controlLoop}
                  source={audit.source}
                />
              </div>
            </div>
          </section>

          <footer className="mt-8 flex flex-col gap-2 border-t border-white/[0.05] pt-5 text-[10px] text-slate-400 sm:flex-row sm:items-center sm:justify-between">
            <p>Archon Metadata Integrity Control Plane · read-first, human-gated</p>
            <p className="font-mono">
              scan {report.scanId} · release {audit.envelope.releaseSha.slice(0, 12)}
            </p>
          </footer>
        </main>
      </div>
      <GuidedTour targetIds={{ "review-proof": reviewProofTarget }} />
    </div>
  );
}
