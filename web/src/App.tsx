import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type FormEvent,
} from "react";
import { loadAudit, submitApprovalDecision } from "./api";
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
      <dt className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500">
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
          <dt className="text-slate-600">Checks</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.outcome === "REJECTED"
              ? "Not invoked"
              : `${passed}/${result.verification.checks.length} passed`}
          </dd>
        </div>
        <div>
          <dt className="text-slate-600">Receipt events</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.verification.eventCount}
          </dd>
        </div>
        <div>
          <dt className="text-slate-600">Rollback</dt>
          <dd className="mt-0.5 text-slate-300">
            {result.verification.rollbackAvailability}
          </dd>
        </div>
        <div>
          <dt className="text-slate-600">Completed</dt>
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
  return (
    <span className={`source-badge ${source === "live" ? "source-live" : "source-fixture"}`}>
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
      {source === "live" ? "Live DataHub" : "Fixture preview"}
    </span>
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
        className="hidden items-center gap-1.5 rounded-full border border-white/[0.07] px-2.5 py-1.5 text-[10px] text-slate-500 md:inline-flex"
      >
        <Icon className="size-3 animate-spin" name="refresh" />
        {auth.status === "loading" ? "Loading auth" : "Opening sign-in"}
      </span>
    );
  }

  const unavailable = auth.status === "error" && !auth.recoverable;
  return (
    <button
      className="rounded-lg border border-cyan-300/15 bg-cyan-300/[0.04] px-2.5 py-1.5 text-[10px] font-semibold text-cyan-100 transition enabled:hover:border-cyan-300/30 enabled:hover:bg-cyan-300/[0.07] disabled:cursor-not-allowed disabled:border-white/[0.05] disabled:bg-transparent disabled:text-slate-600"
      disabled={unavailable}
      onClick={() => void beginSignIn().catch(() => undefined)}
      title={auth.status === "error" ? auth.message : "Authenticate through Cognito"}
      type="button"
    >
      {unavailable ? "Approval auth unavailable" : "Steward sign in"}
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
                <p className="mt-1 line-clamp-2 text-[11px] leading-4 text-slate-500">
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
          <p className="mt-1 text-xs text-slate-500">Adjust the severity or control filter.</p>
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
                  <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-500">
                    {finding.detail.ruleId ?? typeLabels[finding.type]}
                  </span>
                  <SeverityBadge severity={finding.severity} />
                </span>
                <span className="mt-2 block text-sm font-medium leading-5 text-slate-100">
                  {finding.summary}
                </span>
                <span className="mt-2 flex items-center gap-2 text-[11px] text-slate-500">
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
                  selected ? "-rotate-90 text-emerald-200" : "text-slate-600"
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
          <p className="mt-1 text-xs text-slate-500">
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
                <span className="mt-0.5 block text-[10px] text-slate-600">
                  hop {asset.minHops}
                </span>
              </span>
            </div>
          ))}
          {blast.downstream.length > visible.length && (
            <div className="grid min-h-12 place-items-center rounded-lg border border-dashed border-white/10 text-[11px] text-slate-500">
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
              <p className="mt-1 text-[11px] text-slate-500">
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
          {event.value && (
            <p className="mt-2 rounded-lg border border-white/[0.05] bg-black/10 px-3 py-2 font-mono text-[11px] leading-5 text-slate-400">
              {event.value}
            </p>
          )}
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
            <p className="mt-2 text-[11px] leading-5 text-slate-500">
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
      <p className="mt-3 flex items-start gap-2 text-[10px] leading-4 text-slate-600">
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
          <dt className="text-slate-500">Target</dt>
          <dd className="truncate font-mono text-slate-300">{approval.targetField}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-500">Action</dt>
          <dd className="truncate font-mono text-slate-300">add {approval.proposedTag}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-500">Plan</dt>
          <dd className="font-mono text-slate-400">{digestTail(approval.planDigest)}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-slate-500">Expires</dt>
          <dd className="text-slate-400">{formatDate(approval.expiresAt)}</dd>
        </div>
      </dl>

      <label className="mt-4 block">
        <span className="detail-label">Steward note · optional</span>
        <textarea
          className="mt-2 min-h-20 w-full resize-y rounded-xl border border-white/10 bg-[#07100e] px-3 py-2 text-xs leading-5 text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-emerald-300/40 focus:ring-2 focus:ring-emerald-300/10"
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
      <p className="mt-2 text-[10px] leading-4 text-slate-600">
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
          <Icon className="mx-auto size-7 text-slate-700" name="file" />
          <p className="mt-3 text-sm text-slate-500">Select a finding to inspect its evidence.</p>
        </div>
      </div>
    );
  }
  return (
    <article>
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
        <p className="mt-2 break-all font-mono text-[10px] leading-4 text-slate-600">{finding.subject}</p>
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
          <p className="mt-2 text-[11px] leading-5 text-slate-500">
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

export function App() {
  const auth = useSyncExternalStore(subscribeToAuth, getAuthSnapshot, getAuthSnapshot);
  const [audit, setAudit] = useState<LoadedAudit>({
    envelope: previewAudit,
    source: "fixture",
    fallbackReason:
      "Deterministic showcase mode. Run an audit to connect to the hosted control plane.",
  });
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [type, setType] = useState<FindingType | "all">("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [runError, setRunError] = useState<string>();
  const [controlLoop, setControlLoop] = useState<ControlLoopStatus>();
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

  const runAudit = async (event?: FormEvent) => {
    event?.preventDefault();
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setLoading(true);
    setRunError(undefined);
    setControlLoop(undefined);
    try {
      const result = await loadAudit(
        query,
        nextController.signal,
        (status, progressAudit) => {
          setControlLoop(status);
          if (progressAudit) {
            setAudit(progressAudit);
            setSelectedId((current) =>
              progressAudit.envelope.report.findings.some(
                (finding) => findingIdentity(finding) === current,
              )
                ? current
                : progressAudit.envelope.report.findings[0]
                  ? findingIdentity(progressAudit.envelope.report.findings[0])
                  : "",
            );
          }
        },
      );
      setAudit(result);
      setControlLoop(result.controlLoop);
      setSelectedId(
        result.envelope.report.findings[0]
          ? findingIdentity(result.envelope.report.findings[0])
          : "",
      );
    } catch (error) {
      if (!nextController.signal.aborted) {
        setRunError(error instanceof Error ? error.message : "The audit could not be completed.");
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
            <span className="mt-0.5 block text-[9px] uppercase tracking-[0.15em] text-slate-600">
              Control plane
            </span>
          </span>
        </a>
        <nav aria-label="Primary" className="mt-10 flex flex-1 flex-col gap-2">
          <a className="nav-item nav-active" href="#overview">
            <Icon name="graph" />
            <span className="hidden sm:inline">Overview</span>
          </a>
          <a className="nav-item" href="#findings">
            <Icon name="warning" />
            <span className="hidden sm:inline">Findings</span>
          </a>
          <a className="nav-item" href="#control-review">
            <Icon name="fingerprint" />
            <span className="hidden sm:inline">Review</span>
          </a>
        </nav>
        <div className="hidden rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 sm:block">
          <div className="flex items-center gap-2 text-[10px] text-slate-500">
            <Icon className="size-3.5 text-emerald-300" name="shield" />
            Zero-trust writes
          </div>
          <p className="mt-2 text-[9px] leading-4 text-slate-700">
            Read and mutation credentials are isolated.
          </p>
        </div>
      </aside>

      <div className="pl-[4.5rem] sm:pl-52">
        <header className="topbar">
          <form className="relative min-w-0 flex-1 sm:max-w-md" onSubmit={(event) => void runAudit(event)}>
            <label className="sr-only" htmlFor="catalog-scope">
              Scope audit by asset, domain, or platform
            </label>
            <Icon
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-600"
              name="search"
            />
            <input
              className="w-full rounded-xl border border-white/[0.07] bg-white/[0.025] py-2.5 pl-10 pr-3 text-xs text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-emerald-300/30 focus:bg-white/[0.04] focus:ring-2 focus:ring-emerald-300/[0.07]"
              id="catalog-scope"
              maxLength={256}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Scope by asset, domain, or platform"
              type="search"
              value={query}
            />
          </form>
          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <AuthControl auth={auth} />
            <SourceBadge source={audit.source} />
            <button
              className="run-button"
              disabled={loading}
              onClick={() => void runAudit()}
              type="button"
            >
              <Icon
                className={`size-4 ${
                  loading && controlLoop?.status !== "AWAITING_APPROVAL"
                    ? "animate-spin"
                    : ""
                }`}
                name={
                  controlLoop?.status === "AWAITING_APPROVAL"
                    ? "shield"
                    : loading
                      ? "refresh"
                      : "play"
                }
              />
              <span className="hidden sm:inline">
                {controlLoop?.status === "AWAITING_APPROVAL"
                  ? "Awaiting steward"
                  : loading
                    ? "Auditing…"
                    : "Run audit"}
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
                  <p className="mt-1 text-[11px] text-slate-500">
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
              {(audit.fallbackReason || runError) && (
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

          <div className="mt-6">
            <PipelineTrace trace={report.trace} />
          </div>

          <section aria-labelledby="findings-title" className="mt-6" id="findings">
            <div className="panel-heading panel rounded-b-none border-b-0">
              <div>
                <p className="eyebrow">Evidence explorer</p>
                <h2 className="section-title" id="findings-title">
                  Integrity findings
                </h2>
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
                <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3 text-[10px] uppercase tracking-[0.13em] text-slate-600">
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

          <footer className="mt-8 flex flex-col gap-2 border-t border-white/[0.05] pt-5 text-[10px] text-slate-700 sm:flex-row sm:items-center sm:justify-between">
            <p>Archon Metadata Integrity Control Plane · read-first, human-gated</p>
            <p className="font-mono">
              scan {report.scanId} · release {audit.envelope.releaseSha.slice(0, 12)}
            </p>
          </footer>
        </main>
      </div>
    </div>
  );
}
