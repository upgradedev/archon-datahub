import { useEffect, useId, useRef, useState } from "react";

export const GUIDED_TOUR_STORAGE_KEY = "archon-datahub.judge-tour.v1";

export type GuidedTourOutcome = "completed" | "dismissed";
export type GuidedTourStepId =
  | "run-audit"
  | "inspect-provenance"
  | "review-proof";

export interface GuidedTourStep {
  readonly id: GuidedTourStepId;
  readonly title: string;
  readonly description: string;
  readonly targetId: string;
}

export const GUIDED_TOUR_STEPS = [
  {
    id: "run-audit",
    title: "Run a governed audit",
    description:
      "Start the bounded, read-first audit. This orientation never starts it for you.",
    targetId: "judge-tour-run-audit",
  },
  {
    id: "inspect-provenance",
    title: "Inspect temporal provenance and blast radius",
    description:
      "Follow stable ingestion identities through recovered history, then inspect the downstream assets affected by the finding.",
    targetId: "judge-tour-provenance",
  },
  {
    id: "review-proof",
    title: "Review the exact plan and terminal proof",
    description:
      "The steward owns the decision. Approval stays bound to the exact plan, and a terminal receipt records the independently verified outcome.",
    targetId: "judge-tour-approval-proof",
  },
] as const satisfies readonly GuidedTourStep[];

export interface GuidedTourProps {
  readonly targetIds?: Partial<Record<GuidedTourStepId, string>>;
}

function readOutcome(): GuidedTourOutcome | null {
  if (typeof window === "undefined") return null;

  try {
    const value = window.localStorage.getItem(GUIDED_TOUR_STORAGE_KEY);
    return value === "completed" || value === "dismissed" ? value : null;
  } catch {
    return null;
  }
}

function writeOutcome(outcome: GuidedTourOutcome): void {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.setItem(GUIDED_TOUR_STORAGE_KEY, outcome);
  } catch {
    // Storage may be unavailable in hardened or private browser contexts.
  }
}

function clearOutcome(): void {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.removeItem(GUIDED_TOUR_STORAGE_KEY);
  } catch {
    // The tour remains usable in memory when storage is unavailable.
  }
}

export function GuidedTour({ targetIds }: GuidedTourProps = {}) {
  const titleId = useId();
  const descriptionId = useId();
  const [open, setOpen] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [outcome, setOutcome] = useState<GuidedTourOutcome | null>(readOutcome);
  const [focusEpoch, setFocusEpoch] = useState(0);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef(false);
  const step = GUIDED_TOUR_STEPS[stepIndex];
  const targetId = targetIds?.[step.id] ?? step.targetId;

  useEffect(() => {
    if (open) {
      headingRef.current?.focus();
    } else if (restoreFocusRef.current) {
      restoreFocusRef.current = false;
      triggerRef.current?.focus();
    }
  }, [focusEpoch, open]);

  const restart = () => {
    clearOutcome();
    setOutcome(null);
    setStepIndex(0);
    restoreFocusRef.current = true;
    setOpen(true);
    setFocusEpoch((current) => current + 1);
  };

  const close = (nextOutcome: GuidedTourOutcome) => {
    writeOutcome(nextOutcome);
    setOutcome(nextOutcome);
    setOpen(false);
  };

  const showTarget = () => {
    if (!targetId) return;

    document.getElementById(targetId)?.scrollIntoView({
      behavior: "smooth",
      block: "center",
      inline: "nearest",
    });
  };

  return (
    <aside
      aria-label="Optional judge orientation"
      className="fixed inset-x-3 bottom-3 z-50 flex flex-col items-stretch gap-2 sm:left-auto sm:right-6 sm:w-[28rem]"
    >
      {open && (
        <section
          aria-describedby={descriptionId}
          aria-labelledby={titleId}
          aria-modal="false"
          className="max-h-[min(34rem,calc(100vh-6rem))] overflow-y-auto rounded-2xl border border-emerald-300/20 bg-[#0a1513]/95 p-4 text-slate-200 shadow-2xl shadow-black/40 backdrop-blur sm:p-5"
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              close("dismissed");
            }
          }}
          role="dialog"
        >
          <div
            aria-live="polite"
            className="text-[10px] font-semibold uppercase tracking-[0.15em] text-emerald-200/70"
          >
            Step {stepIndex + 1} of {GUIDED_TOUR_STEPS.length}
          </div>
          <h2
            className="mt-2 text-base font-semibold leading-6 text-white sm:text-lg"
            id={titleId}
            ref={headingRef}
            tabIndex={-1}
          >
            {step.title}
          </h2>
          <p
            className="mt-2 text-xs leading-5 text-slate-300 sm:text-sm sm:leading-6"
            id={descriptionId}
          >
            {step.description}
          </p>
          <p className="mt-3 rounded-xl border border-cyan-300/10 bg-cyan-300/[0.035] px-3 py-2 text-[11px] leading-5 text-cyan-100/75">
            Passive orientation: no audit, approval, mutation, or API request is
            performed.
          </p>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              className="rounded-lg border border-white/10 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-white/20 hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
              onClick={showTarget}
              type="button"
            >
              Show this area
            </button>
            <span className="text-[10px] leading-4 text-slate-500">
              Scrolls only after this explicit action.
            </span>
          </div>

          <div className="mt-5 flex flex-col-reverse gap-2 border-t border-white/[0.07] pt-4 sm:flex-row sm:items-center">
            <button
              className="rounded-lg px-3 py-2 text-xs font-semibold text-slate-400 hover:bg-white/[0.04] hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300 sm:mr-auto"
              onClick={() => close("dismissed")}
              type="button"
            >
              Dismiss tour
            </button>
            {stepIndex > 0 && (
              <button
                className="rounded-lg border border-white/10 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-white/20 hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
                onClick={() => setStepIndex((current) => current - 1)}
                type="button"
              >
                Back
              </button>
            )}
            {stepIndex < GUIDED_TOUR_STEPS.length - 1 ? (
              <button
                className="rounded-lg border border-emerald-300/20 bg-emerald-300/10 px-3 py-2 text-xs font-semibold text-emerald-100 hover:bg-emerald-300/15 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
                onClick={() => setStepIndex((current) => current + 1)}
                type="button"
              >
                Next
              </button>
            ) : (
              <button
                className="rounded-lg border border-emerald-300/20 bg-emerald-300/10 px-3 py-2 text-xs font-semibold text-emerald-100 hover:bg-emerald-300/15 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
                onClick={() => close("completed")}
                type="button"
              >
                Finish tour
              </button>
            )}
          </div>
        </section>
      )}

      <div aria-live="polite" className="flex items-center justify-end gap-2">
        {!open && outcome && (
          <span className="rounded-full border border-white/10 bg-[#0a1513]/90 px-3 py-2 text-[10px] text-slate-400">
            Tour {outcome}.
          </span>
        )}
        <button
          className="rounded-full border border-emerald-300/20 bg-[#0a1513]/95 px-4 py-2.5 text-xs font-semibold text-emerald-100 shadow-lg shadow-black/30 hover:bg-emerald-300/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
          onClick={restart}
          ref={triggerRef}
          type="button"
        >
          {open || outcome ? "Restart judge tour" : "Start judge tour"}
        </button>
      </div>
    </aside>
  );
}
