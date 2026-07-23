// Fixed live-harvest budgets for the two hosted execution paths.
//
// These are code-level ceilings, not environment knobs: a deployment cannot silently
// weaken them. The synchronous preview must return inside API Gateway's integration
// timeout. The durable audit worker may do more work, but must still leave ample time
// inside its two-hour Step Functions callback deadline.

export type AuditExecutionProfile = "synchronous-preview" | "async-worker";

export interface LiveHarvestPolicy {
  maxEntities: number;
  maxHistoricalVersions: number;
  lineageConcurrency: number;
  historyConcurrency: number;
  operationTimeoutMs: number;
  harvestDeadlineMs: number;
  pipelineDeadlineMs: number;
}

export const LIVE_HARVEST_POLICIES: Readonly<
  Record<AuditExecutionProfile, Readonly<LiveHarvestPolicy>>
> = Object.freeze({
  "synchronous-preview": Object.freeze({
    // One exact demo dataset keeps search, entity hydration, lineage, and all four
    // versioned-aspect reads within the public request budget.
    maxEntities: 1,
    maxHistoricalVersions: 2,
    lineageConcurrency: 1,
    historyConcurrency: 4,
    operationTimeoutMs: 4_000,
    harvestDeadlineMs: 18_000,
    pipelineDeadlineMs: 25_000,
  }),
  "async-worker": Object.freeze({
    // 25 * 4 aspects * (v0 + 12 retained + the required end probe), with eight
    // concurrent readers, is bounded well below the worker's two-hour callback.
    maxEntities: 25,
    maxHistoricalVersions: 12,
    lineageConcurrency: 8,
    historyConcurrency: 8,
    operationTimeoutMs: 10_000,
    harvestDeadlineMs: 75 * 60_000,
    pipelineDeadlineMs: 90 * 60_000,
  }),
});

export type DataHubHarvestErrorCode =
  | "MCP_TOOL_ERROR"
  | "MCP_RESPONSE_INVALID"
  | "SEARCH_LIMIT_EXCEEDED"
  | "SEARCH_RESPONSE_INCOMPLETE"
  | "ENTITY_RESPONSE_INCOMPLETE"
  | "LINEAGE_RESPONSE_INCOMPLETE"
  | "HISTORY_CAPABILITY_REQUIRED"
  | "HARVEST_DEADLINE_EXCEEDED"
  | "PIPELINE_DEADLINE_EXCEEDED";

export class DataHubHarvestError extends Error {
  constructor(
    readonly code: DataHubHarvestErrorCode,
    message: string
  ) {
    super(message);
    this.name = "DataHubHarvestError";
  }
}

export function harvestPolicy(
  profile: AuditExecutionProfile
): Readonly<LiveHarvestPolicy> {
  return LIVE_HARVEST_POLICIES[profile];
}

export function requireDirectHistoryCapability(
  gmsUrl: string | undefined
): string {
  const value = gmsUrl?.trim();
  if (!value) {
    throw new DataHubHarvestError(
      "HISTORY_CAPABILITY_REQUIRED",
      "Live hosted audits require a direct DataHub GMS endpoint for complete aspect history."
    );
  }
  return value;
}

export function deadlineSignal(
  timeoutMs: number,
  parent?: AbortSignal
): AbortSignal {
  const deadline = AbortSignal.timeout(timeoutMs);
  return parent ? AbortSignal.any([parent, deadline]) : deadline;
}

export async function waitWithinDeadline<T>(
  operation: Promise<T>,
  signal: AbortSignal,
  code: Extract<
    DataHubHarvestErrorCode,
    "HARVEST_DEADLINE_EXCEEDED" | "PIPELINE_DEADLINE_EXCEEDED"
  >
): Promise<T> {
  if (signal.aborted) {
    throw new DataHubHarvestError(code, deadlineMessage(code));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback();
    };
    const onAbort = (): void => {
      finish(() => reject(new DataHubHarvestError(code, deadlineMessage(code))));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void operation.then(
      (value) => finish(() => resolve(value)),
      (error: unknown) => finish(() => reject(error))
    );
  });
}

export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  signal: AbortSignal,
  operation: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new RangeError("concurrency must be a positive integer");
  }
  const output = new Array<R>(items.length);
  let cursor = 0;
  let failed = false;
  let failure: unknown;
  const worker = async (): Promise<void> => {
    while (true) {
      if (failed) return;
      if (signal.aborted) {
        failed = true;
        failure = new DataHubHarvestError(
          "HARVEST_DEADLINE_EXCEEDED",
          deadlineMessage("HARVEST_DEADLINE_EXCEEDED")
        );
        return;
      }
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      try {
        output[index] = await operation(items[index]!, index);
      } catch (error) {
        if (!failed) {
          failed = true;
          failure = error;
        }
        return;
      }
    }
  };
  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, items.length) },
      () => worker()
    )
  );
  if (failed) throw failure;
  return output;
}

function deadlineMessage(
  code: Extract<
    DataHubHarvestErrorCode,
    "HARVEST_DEADLINE_EXCEEDED" | "PIPELINE_DEADLINE_EXCEEDED"
  >
): string {
  return code === "PIPELINE_DEADLINE_EXCEEDED"
    ? "The audit pipeline exceeded its hosted execution deadline."
    : "The DataHub harvest exceeded its hosted execution deadline.";
}
