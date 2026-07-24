// Fail-closed reader for DataHub's versioned-aspect OpenAPI surface.
//
// DataHub addresses the current aspect as version=0 and retained historical rows as
// version=1..N. A useful contradiction audit needs BOTH: after A→B, history contains the
// displaced A while v0 contains current B. This reader always fetches v0, then enumerates
// retained rows until the first 404. Auth, server, malformed-response, network, timeout,
// and safety-limit failures are errors — never a silent "end of history".

import type {
  DhVersionedAspect,
  MutableAspectName,
} from "./version-history.js";

export type VersionHistoryReadErrorCode =
  | "HTTP_ERROR"
  | "INVALID_RESPONSE"
  | "HISTORY_LIMIT_EXCEEDED";

export class VersionHistoryReadError extends Error {
  constructor(
    readonly code: VersionHistoryReadErrorCode,
    message: string,
    readonly url: string,
    readonly status?: number
  ) {
    super(message);
    this.name = "VersionHistoryReadError";
  }
}

export interface VersionHistoryReadOptions {
  fetchFn?: typeof fetch;
  maxHistoricalVersions?: number;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
}

interface LocatedVersion {
  slot: number;
  entry: DhVersionedAspect;
}

function endpoint(
  gmsUrl: string,
  urn: string,
  aspect: MutableAspectName,
  version: number
): string {
  const base = gmsUrl.replace(/\/+$/, "");
  return (
    `${base}/openapi/v3/entity/dataset/${encodeURIComponent(urn)}/${aspect}` +
    `?systemMetadata=true&version=${version}`
  );
}

function isWrappedAspect(value: unknown): value is DhVersionedAspect {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<DhVersionedAspect>;
  return candidate.value === null || (
    typeof candidate.value === "object" &&
    candidate.value !== null &&
    !Array.isArray(candidate.value)
  );
}

async function readSlot(
  fetchFn: typeof fetch,
  url: string,
  aspect: MutableAspectName,
  headers: Record<string, string>,
  requestTimeoutMs: number,
  signal?: AbortSignal
): Promise<DhVersionedAspect | null> {
  const requestSignal = signal
    ? AbortSignal.any([signal, AbortSignal.timeout(requestTimeoutMs)])
    : AbortSignal.timeout(requestTimeoutMs);
  const response = await fetchFn(url, {
    headers,
    signal: requestSignal,
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new VersionHistoryReadError(
      "HTTP_ERROR",
      `DataHub version-history read failed with HTTP ${response.status}`,
      url,
      response.status
    );
  }

  let body: Record<string, unknown>;
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new VersionHistoryReadError(
      "INVALID_RESPONSE",
      "DataHub version-history response was not valid JSON",
      url,
      response.status
    );
  }
  const wrapped = body?.[aspect];
  if (!isWrappedAspect(wrapped)) {
    throw new VersionHistoryReadError(
      "INVALID_RESPONSE",
      `DataHub response did not contain a valid ${aspect} aspect wrapper`,
      url,
      response.status
    );
  }
  return wrapped;
}

function dedupeAndOrder(located: LocatedVersion[]): DhVersionedAspect[] {
  const seen = new Set<string>();
  const unique = located.filter(({ entry }) => {
    const key = JSON.stringify({
      value: entry.value,
      systemMetadata: entry.systemMetadata ?? null,
    });
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // lastObserved is the strongest chronological signal. If it is absent/equal, DataHub's
  // slot order is used: a larger historical slot is older; v0 is current and therefore last.
  unique.sort((a, b) => {
    const aTime = a.entry.systemMetadata?.lastObserved;
    const bTime = b.entry.systemMetadata?.lastObserved;
    if (
      typeof aTime === "number" &&
      typeof bTime === "number" &&
      aTime !== bTime
    ) {
      return aTime - bTime;
    }
    return b.slot - a.slot;
  });
  return unique.map(({ entry }) => entry);
}

export async function readAspectVersionHistory(
  gmsUrl: string,
  token: string | undefined,
  urn: string,
  aspect: MutableAspectName,
  options: VersionHistoryReadOptions = {}
): Promise<DhVersionedAspect[]> {
  const fetchFn = options.fetchFn ?? fetch;
  const maxHistoricalVersions = options.maxHistoricalVersions ?? 50;
  const requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
  if (!Number.isInteger(maxHistoricalVersions) || maxHistoricalVersions < 1) {
    throw new RangeError("maxHistoricalVersions must be a positive integer");
  }
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
    throw new RangeError("requestTimeoutMs must be positive");
  }

  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const currentUrl = endpoint(gmsUrl, urn, aspect, 0);
  const current = await readSlot(
    fetchFn,
    currentUrl,
    aspect,
    headers,
    requestTimeoutMs,
    options.signal
  );
  if (!current) return [];

  const located: LocatedVersion[] = [{ slot: 0, entry: current }];
  for (let slot = 1; slot <= maxHistoricalVersions + 1; slot++) {
    const url = endpoint(gmsUrl, urn, aspect, slot);
    const historical = await readSlot(
      fetchFn,
      url,
      aspect,
      headers,
      requestTimeoutMs,
      options.signal
    );
    if (!historical) break;
    if (slot > maxHistoricalVersions) {
      throw new VersionHistoryReadError(
        "HISTORY_LIMIT_EXCEEDED",
        `DataHub retained more than ${maxHistoricalVersions} ${aspect} versions; refusing a partial audit`,
        url
      );
    }
    located.push({ slot, entry: historical });
  }
  return dedupeAndOrder(located);
}
