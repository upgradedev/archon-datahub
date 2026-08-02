import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
} from "react";
import {
  extendRuntimeSession,
  getRuntimeProfiles,
  getRuntimeSession,
  startRuntimeSession,
  stopRuntimeSession,
  type RuntimeProfileProjection,
  type RuntimeProfilesResponse,
  type RuntimeRequest,
  type RuntimeSessionStatus,
} from "./runtime-api";

interface RuntimeControlProps {
  getAccessToken?: () => string;
  onSessionChange?: (session: RuntimeSessionStatus | undefined) => void;
}

const SESSION_STORAGE_KEY = "archon.runtime-session/v1";
const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const TERMINAL_STATES = new Set(["STOPPED", "EXPIRED", "UNAVAILABLE"]);

const requestLabels: Record<RuntimeRequest, string> = {
  auto: "Auto · best available",
  cloud: "DataHub Cloud",
  core: "DataHub Core sandbox",
};

const availabilityTone: Record<
  RuntimeProfileProjection["availability"],
  string
> = {
  READY: "border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200",
  LAUNCHABLE: "border-cyan-300/20 bg-cyan-300/[0.06] text-cyan-100",
  STARTING: "border-cyan-300/20 bg-cyan-300/[0.06] text-cyan-100",
  BUSY: "border-amber-300/20 bg-amber-300/[0.06] text-amber-100",
  UNAVAILABLE: "border-white/[0.08] bg-white/[0.025] text-slate-400",
};

const capabilityLabels = [
  ["mcpRead", "MCP"],
  ["mcpGovernedWrite", "Governed write"],
  ["agentContextKit", "Context Kit"],
  ["dataHubSkills", "Skills"],
  ["analyticsAgent", "Analytics"],
] as const;

function formatCountdown(seconds: number): string {
  const bounded = Math.max(0, Math.min(seconds, 2 * 60 * 60));
  const hours = Math.floor(bounded / 3600);
  const minutes = Math.floor((bounded % 3600) / 60);
  const remainder = bounded % 60;
  return hours > 0
    ? [hours, minutes, remainder]
        .map((value) => String(value).padStart(2, "0"))
        .join(":")
    : [minutes, remainder]
        .map((value) => String(value).padStart(2, "0"))
        .join(":");
}

function RuntimeProfile({
  profile,
}: {
  profile: RuntimeProfileProjection;
}) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/10 p-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[11px] font-semibold text-slate-100">
          {profile.profileId === "cloud"
            ? "DataHub Cloud"
            : "DataHub Core"}
        </p>
        <span
          className={
            "rounded-full border px-2 py-1 text-[9px] font-semibold tracking-[0.08em] " +
            availabilityTone[profile.availability]
          }
        >
          {profile.availability}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {capabilityLabels.map(([key, label]) => (
          <span
            className={
              "rounded-full border px-2 py-1 text-[9px] " +
              (profile.capabilities[key]
                ? "border-emerald-300/15 bg-emerald-300/[0.04] text-emerald-100/80"
                : "border-white/[0.06] bg-white/[0.02] text-slate-500")
            }
            key={key}
          >
            {label}
          </span>
        ))}
      </div>
      <p className="mt-2 truncate font-mono text-[9px] text-slate-500">
        {profile.generation ?? "No verified generation"}
      </p>
    </div>
  );
}

function Registry({
  registry,
}: {
  registry: RuntimeProfilesResponse;
}) {
  return (
    <div className="mt-3 grid gap-2 md:grid-cols-2">
      {registry.profiles.map((profile) => (
        <RuntimeProfile key={profile.profileId} profile={profile} />
      ))}
    </div>
  );
}

export function RuntimeControl({
  getAccessToken,
  onSessionChange,
}: RuntimeControlProps) {
  const [requestedProfile, setRequestedProfile] =
    useState<RuntimeRequest>("auto");
  const [registry, setRegistry] = useState<RuntimeProfilesResponse>();
  const [session, setSession] = useState<RuntimeSessionStatus>();
  const [remainingSeconds, setRemainingSeconds] = useState(0);
  const [pending, setPending] = useState<
    "registry" | "recover" | "start" | "extend" | "stop"
  >();
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController | null>(null);
  const receivedAt = useRef(0);
  const receivedRemaining = useRef(0);

  const publish = useCallback(
    (next: RuntimeSessionStatus | undefined) => {
      setSession(next);
      onSessionChange?.(next);
      try {
        if (next && !TERMINAL_STATES.has(next.state)) {
          window.sessionStorage.setItem(
            SESSION_STORAGE_KEY,
            next.sessionId,
          );
        } else {
          window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
        }
      } catch {
        // Session recovery is an availability convenience. The server remains
        // authoritative and no binding or credential is ever persisted.
      }
      if (next) {
        receivedAt.current = Date.now();
        receivedRemaining.current = next.remainingSeconds;
        setRemainingSeconds(next.remainingSeconds);
      } else {
        receivedRemaining.current = 0;
        setRemainingSeconds(0);
      }
    },
    [onSessionChange],
  );

  useEffect(() => {
    let stored: string | null = null;
    try {
      stored = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    } catch {
      return undefined;
    }
    if (stored === null) return undefined;
    if (!SESSION_ID.test(stored)) {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
      setError("An invalid saved runtime capability was discarded.");
      return undefined;
    }
    let active = true;
    setPending("recover");
    void getRuntimeSession(stored)
      .then((recovered) => {
        if (active) {
          setError(undefined);
          publish(recovered);
        }
      })
      .catch((recoveryError: unknown) => {
        if (!active) return;
        if (
          recoveryError &&
          typeof recoveryError === "object" &&
          "status" in recoveryError &&
          recoveryError.status === 404
        ) {
          window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
        }
        setError(
          recoveryError instanceof Error
            ? recoveryError.message
            : "The saved runtime session could not be recovered.",
        );
      })
      .finally(() => {
        if (active) setPending(undefined);
      });
    return () => {
      active = false;
    };
  }, [publish]);

  useEffect(() => {
    if (
      !session ||
      !["STARTING", "READY", "STOPPING"].includes(session.state)
    ) {
      return undefined;
    }
    const id = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - receivedAt.current) / 1000);
      setRemainingSeconds(
        Math.max(0, receivedRemaining.current - elapsed),
      );
    }, 1000);
    return () => window.clearInterval(id);
  }, [session?.sessionId, session?.state]);

  useEffect(() => {
    if (
      !session ||
      !["STARTING", "READY", "STOPPING"].includes(session.state)
    ) {
      return undefined;
    }
    let active = true;
    const poll = async () => {
      try {
        const next = await getRuntimeSession(session.sessionId);
        if (active) {
          setError(undefined);
          publish(next);
        }
      } catch (pollError) {
        if (active) {
          setError(
            pollError instanceof Error
              ? pollError.message
              : "Runtime status is unavailable.",
          );
        }
      }
    };
    const id = window.setInterval(() => void poll(), 5000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [session?.sessionId, session?.state]);

  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );

  const freshController = () => {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    return next;
  };

  const refreshRegistry = async () => {
    const nextController = freshController();
    setPending("registry");
    setError(undefined);
    try {
      setRegistry(await getRuntimeProfiles(nextController.signal));
    } catch (registryError) {
      if (!nextController.signal.aborted) {
        setError(
          registryError instanceof Error
            ? registryError.message
            : "Runtime registry is unavailable.",
        );
      }
    } finally {
      if (!nextController.signal.aborted) setPending(undefined);
    }
  };

  const launch = async () => {
    const nextController = freshController();
    setPending("start");
    setError(undefined);
    try {
      publish(
        await startRuntimeSession(
          requestedProfile,
          getAccessToken?.() ?? "",
          nextController.signal,
        ),
      );
    } catch (startError) {
      if (!nextController.signal.aborted) {
        setError(
          startError instanceof Error
            ? startError.message
            : "The runtime session could not be started.",
        );
      }
    } finally {
      if (!nextController.signal.aborted) setPending(undefined);
    }
  };

  const extend = async () => {
    if (!session) return;
    const nextController = freshController();
    setPending("extend");
    setError(undefined);
    try {
      publish(
        await extendRuntimeSession(
          session.sessionId,
          getAccessToken?.() ?? "",
          nextController.signal,
        ),
      );
    } catch (extendError) {
      if (!nextController.signal.aborted) {
        setError(
          extendError instanceof Error
            ? extendError.message
            : "The runtime lease could not be extended.",
        );
      }
    } finally {
      if (!nextController.signal.aborted) setPending(undefined);
    }
  };

  const stop = async () => {
    if (!session) return;
    const nextController = freshController();
    setPending("stop");
    setError(undefined);
    try {
      publish(
        await stopRuntimeSession(
          session.sessionId,
          getAccessToken?.() ?? "",
          nextController.signal,
        ),
      );
    } catch (stopError) {
      if (!nextController.signal.aborted) {
        setError(
          stopError instanceof Error
            ? stopError.message
            : "The runtime teardown could not be requested.",
        );
      }
    } finally {
      if (!nextController.signal.aborted) setPending(undefined);
    }
  };

  const terminal = session && TERMINAL_STATES.has(session.state);

  return (
    <section
      aria-labelledby="runtime-control-title"
      className="panel mt-6 overflow-hidden"
      id="runtime-control"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Portable DataHub runtime</p>
          <h2 className="section-title" id="runtime-control-title">
            Judge runtime control
          </h2>
          <p className="mt-2 max-w-3xl text-[11px] leading-5 text-slate-400">
            Auto uses Cloud only when MCP, Agent Context Kit, Skills,
            Analytics Agent, and governed write are all freshly verified.
            Otherwise it launches the reproducible Core sandbox. Explicit
            Cloud never falls back.
          </p>
        </div>
        <button
          className="rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 py-2 text-[10px] font-semibold text-slate-300 transition hover:border-emerald-300/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
          disabled={pending !== undefined}
          onClick={() => void refreshRegistry()}
          type="button"
        >
          {pending === "registry" ? "Checking…" : "Check readiness"}
        </button>
      </div>

      <div className="border-t border-white/[0.06] p-5">
        {registry ? <Registry registry={registry} /> : null}

        {!session || terminal ? (
          <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
            <label className="block">
              <span className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                Runtime preference
              </span>
              <select
                aria-label="DataHub runtime preference"
                className="w-full rounded-xl border border-white/[0.08] bg-[#091512] px-3 py-3 text-xs text-slate-100 outline-none focus:border-emerald-300/30 focus:ring-2 focus:ring-emerald-300/[0.07]"
                disabled={pending !== undefined}
                onChange={(event: ChangeEvent<HTMLSelectElement>) =>
                  setRequestedProfile(event.target.value as RuntimeRequest)
                }
                value={requestedProfile}
              >
                <option value="auto">{requestLabels.auto}</option>
                <option value="cloud">{requestLabels.cloud}</option>
                <option value="core">{requestLabels.core}</option>
              </select>
            </label>
            <button
              className="run-button min-h-11 justify-center"
              disabled={pending !== undefined || getAccessToken === undefined}
              onClick={() => void launch()}
              type="button"
            >
              {pending === "start"
                ? "Starting runtime…"
                : terminal
                  ? "Start new pinned session"
                  : "Launch pinned session"}
            </button>
          </div>
          {getAccessToken === undefined ? (
            <p className="mt-2 text-[10px] text-amber-100/80">
              Sign in as the judge or steward to launch a paid runtime.
            </p>
          ) : null}
        ) : (
          <div
            aria-live="polite"
            className="mt-4 rounded-xl border border-white/[0.07] bg-black/10 p-4"
          >
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-emerald-300/15 bg-emerald-300/[0.05] px-2 py-1 text-[9px] font-semibold tracking-[0.08em] text-emerald-100">
                    {session.state}
                  </span>
                  <span className="text-xs font-semibold text-slate-100">
                    {session.resolvedProfile === "cloud"
                      ? "DataHub Cloud"
                      : "Ephemeral DataHub Core"}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {session.requestedProfile === "auto"
                      ? "resolved automatically"
                      : "explicit selection"}
                  </span>
                </div>
                <p className="mt-2 text-[10px] leading-5 text-slate-400">
                  Binding is immutable for this session. A generation or
                  capability-digest change fails closed; it never silently
                  switches runtime.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-2 text-right">
                  <p className="text-[9px] uppercase tracking-[0.12em] text-slate-500">
                    Server lease
                  </p>
                  <p className="mt-1 font-mono text-lg font-semibold text-white">
                    {formatCountdown(remainingSeconds)}
                  </p>
                </div>
                <button
                  className="rounded-lg border border-emerald-300/20 bg-emerald-300/[0.06] px-3 py-2 text-[10px] font-semibold text-emerald-100 disabled:cursor-not-allowed disabled:opacity-40"
                  disabled={
                    pending !== undefined ||
                    getAccessToken === undefined ||
                    !session.canExtend ||
                    session.state !== "READY"
                  }
                  onClick={() => void extend()}
                  type="button"
                >
                  {pending === "extend" ? "Extending…" : "Extend 30 min"}
                </button>
                <button
                  className="rounded-lg border border-rose-300/20 bg-rose-300/[0.05] px-3 py-2 text-[10px] font-semibold text-rose-100 disabled:cursor-not-allowed disabled:opacity-40"
                  disabled={pending !== undefined || getAccessToken === undefined}
                  onClick={() => void stop()}
                  type="button"
                >
                  {pending === "stop" ? "Stopping…" : "Stop & teardown"}
                </button>
              </div>
            </div>
          </div>
        )}

        {error ? (
          <p
            aria-live="assertive"
            className="mt-3 rounded-xl border border-rose-300/15 bg-rose-300/[0.04] px-3 py-2 text-[11px] leading-5 text-rose-200"
            role="alert"
          >
            {error}
          </p>
        ) : null}

        <p className="mt-3 text-[9px] leading-4 text-slate-500">
          DynamoDB is the lease authority. CloudWatch records telemetry only;
          the Core sandbox tears down after 30 minutes idle and always by the
          two-hour hard limit.
        </p>
      </div>
    </section>
  );
}
