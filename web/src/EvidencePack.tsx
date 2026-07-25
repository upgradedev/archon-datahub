import { useEffect, useRef, useState } from "react";
import {
  buildBrowserEvidencePack,
  downloadEvidenceFile,
  manifestFile,
  verifyBrowserEvidencePack,
  type BrowserEvidencePack,
} from "./evidence-pack";
import type { ControlLoopStatus, LoadedAudit } from "./types";

type Preparation =
  | {
      audit: LoadedAudit;
      controlLoop: ControlLoopStatus | undefined;
      state: "idle" | "building";
    }
  | {
      audit: LoadedAudit;
      controlLoop: ControlLoopStatus | undefined;
      state: "ready";
      pack: BrowserEvidencePack;
    }
  | {
      audit: LoadedAudit;
      controlLoop: ControlLoopStatus | undefined;
      state: "error";
      message: string;
    };

export function EvidencePack({
  audit,
  controlLoop,
}: {
  audit: LoadedAudit;
  controlLoop?: ControlLoopStatus;
}) {
  const generation = useRef(0);
  const currentInput = useRef({ audit, controlLoop });
  currentInput.current = { audit, controlLoop };
  const [preparation, setPreparation] = useState<Preparation>({
    audit,
    controlLoop,
    state: "idle",
  });
  const active =
    preparation.audit === audit && preparation.controlLoop === controlLoop
      ? preparation
      : ({ audit, controlLoop, state: "idle" } as const);
  const pack = active.state === "ready" ? active.pack : undefined;

  useEffect(() => {
    generation.current += 1;
    setPreparation({ audit, controlLoop, state: "idle" });
    return () => {
      generation.current += 1;
    };
  }, [audit, controlLoop]);

  const inputIsCurrent = (
    token: number,
    expectedAudit: LoadedAudit,
    expectedControlLoop: ControlLoopStatus | undefined,
  ) =>
    generation.current === token &&
    currentInput.current.audit === expectedAudit &&
    currentInput.current.controlLoop === expectedControlLoop;

  const prepare = async () => {
    const expectedAudit = audit;
    const expectedControlLoop = controlLoop;
    const token = generation.current + 1;
    generation.current = token;
    setPreparation({
      audit: expectedAudit,
      controlLoop: expectedControlLoop,
      state: "building",
    });
    try {
      const next = await buildBrowserEvidencePack(
        expectedAudit,
        expectedControlLoop,
      );
      if (!inputIsCurrent(token, expectedAudit, expectedControlLoop)) return;
      if (!next.verification.valid) {
        throw new Error("The browser could not verify every evidence check.");
      }
      setPreparation({
        audit: expectedAudit,
        controlLoop: expectedControlLoop,
        state: "ready",
        pack: next,
      });
    } catch (error) {
      if (!inputIsCurrent(token, expectedAudit, expectedControlLoop)) return;
      setPreparation({
        audit: expectedAudit,
        controlLoop: expectedControlLoop,
        state: "error",
        message:
          error instanceof Error
            ? error.message
            : "Evidence preparation failed closed.",
      });
    }
  };

  const failCurrentDownload = (error: unknown, expectedToken: number) => {
    if (
      generation.current !== expectedToken ||
      currentInput.current.audit !== audit ||
      currentInput.current.controlLoop !== controlLoop
    ) {
      return;
    }
    generation.current += 1;
    setPreparation({
      audit,
      controlLoop,
      state: "error",
      message:
        error instanceof Error
          ? error.message
          : "Evidence download failed closed.",
    });
  };

  const downloadManifest = async () => {
    if (!pack) return;
    const expectedAudit = audit;
    const expectedControlLoop = controlLoop;
    const token = generation.current;
    try {
      const file = await manifestFile(pack);
      if (!inputIsCurrent(token, expectedAudit, expectedControlLoop)) return;
      await downloadEvidenceFile(file, () =>
        inputIsCurrent(token, expectedAudit, expectedControlLoop),
      );
    } catch (error) {
      failCurrentDownload(error, token);
    }
  };

  const downloadFile = async (
    file: BrowserEvidencePack["files"][number],
  ) => {
    if (!pack) return;
    const expectedAudit = audit;
    const expectedControlLoop = controlLoop;
    const token = generation.current;
    if (
      currentInput.current.audit !== audit ||
      currentInput.current.controlLoop !== controlLoop
    ) {
      return;
    }
    try {
      const verification = await verifyBrowserEvidencePack(pack);
      if (!inputIsCurrent(token, expectedAudit, expectedControlLoop)) return;
      if (!verification.valid) {
        throw new Error("Evidence changed after preparation.");
      }
      await downloadEvidenceFile(file, () =>
        inputIsCurrent(token, expectedAudit, expectedControlLoop),
      );
    } catch (error) {
      failCurrentDownload(error, token);
    }
  };

  return (
    <section
      aria-busy={active.state === "building"}
      aria-labelledby="evidence-pack-title"
      className="panel mt-6 overflow-hidden"
      id="judge-evidence"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Portable, exactly allowlisted</p>
          <h2 className="section-title" id="evidence-pack-title">
            Judge evidence pack
          </h2>
        </div>
        <span className="rounded-full border border-cyan-300/15 bg-cyan-300/[0.04] px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-cyan-100">
          WebCrypto self-check
        </span>
      </div>
      <div className="grid gap-5 border-t border-white/[0.06] p-5 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
        <div>
          <p className="max-w-2xl text-xs leading-5 text-slate-400">
            Export an exact public allowlist as JSON, steward Markdown, and
            SARIF. Raw finding detail, actor/value fields, private evidence
            objects, credential-bearing fields, and orchestration state are
            outside the schema; credential-shaped allowed text is rejected. A
            terminal file contains only its public result projection.
          </p>
          <p className="mt-2 max-w-2xl text-[11px] leading-5 text-amber-100/70">
            WebCrypto proves internal manifest, file, and source-field
            consistency after generation. It does not authenticate origin; the
            separately attested CI artifact is the external provenance path.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              className="run-button"
              disabled={active.state === "building"}
              onClick={() => void prepare()}
              type="button"
            >
              {active.state === "building"
                ? "Verifying…"
                : "Prepare & verify pack"}
            </button>
            {pack && (
              <>
                <button
                  className="rounded-lg border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-300 transition hover:border-white/20 hover:text-white"
                  onClick={() => void downloadManifest()}
                  type="button"
                >
                  Download manifest
                </button>
                {pack.files.map((file) => (
                  <button
                    className="rounded-lg border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-300 transition hover:border-white/20 hover:text-white"
                    key={file.path}
                    onClick={() => void downloadFile(file)}
                    type="button"
                  >
                    {file.path.split("/").at(-1)}
                  </button>
                ))}
              </>
            )}
          </div>
          <p
            aria-live="polite"
            className={`mt-3 text-[11px] ${
              active.state === "error"
                ? "text-rose-200"
                : "text-slate-500"
            }`}
          >
            {active.state === "ready" && pack
              ? `${pack.files.length} files verified · ${pack.manifest.evidenceClass.replaceAll("_", " ").toLowerCase()}`
              : active.state === "error"
                ? active.message
                : "No files are generated or downloaded until requested."}
          </p>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-black/10 p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-500">
            Named self-consistency checks
          </p>
          {pack ? (
            <ul className="mt-3 grid gap-2 text-[10px]">
              {pack.verification.checks.map((check) => (
                <li
                  className="flex items-center justify-between gap-3"
                  key={check.checkId}
                >
                  <code className="text-slate-400">{check.checkId}</code>
                  <span
                    className={
                      check.passed ? "text-emerald-300" : "text-rose-300"
                    }
                  >
                    {check.passed ? "PASS" : "FAIL"}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-[11px] leading-5 text-slate-600">
              Downloads remain disabled until schema, fixed file set, digests,
              public projection, summary, internal source fields, and privacy
              scan all pass.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
