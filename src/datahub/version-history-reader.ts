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

export interface CurrentAspectReadOptions {
  fetchFn?: typeof fetch;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
}

export type DatasetLineageType = "COPY" | "TRANSFORMED" | "VIEW";

export interface DeclaredUpstreamLineage {
  upstream: string;
  type: DatasetLineageType;
}

interface LocatedVersion {
  slot: number;
  entry: DhVersionedAspect;
}

type DirectAspectName = MutableAspectName | "upstreamLineage";

function endpoint(
  gmsUrl: string,
  urn: string,
  aspect: DirectAspectName,
  version: number
): string {
  const base = gmsUrl.replace(/\/+$/, "");
  return (
    `${base}/openapi/v3/entity/dataset/${encodeURIComponent(urn)}/${aspect}` +
    `?systemMetadata=true&version=${version}`
  );
}

function isDirectAspectEnvelope(value: unknown): value is DhVersionedAspect {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<DhVersionedAspect>;
  const validValue =
    candidate.value === null ||
    (typeof candidate.value === "object" &&
      candidate.value !== null &&
      !Array.isArray(candidate.value));
  const validSystemMetadata =
    candidate.systemMetadata === undefined ||
    candidate.systemMetadata === null ||
    (typeof candidate.systemMetadata === "object" &&
      !Array.isArray(candidate.systemMetadata));
  return (
    Object.prototype.hasOwnProperty.call(candidate, "value") &&
    validValue &&
    validSystemMetadata
  );
}

const DATASET_URN_PREFIX =
  "urn:li:dataset:(urn:li:dataPlatform:";
const DATASET_LINEAGE_TYPES = new Set<DatasetLineageType>([
  "COPY",
  "TRANSFORMED",
  "VIEW",
]);

function isExactDatasetUrn(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !value.startsWith(DATASET_URN_PREFIX) ||
    !value.endsWith(")") ||
    /[\s\u0000-\u001f\u007f]/u.test(value)
  ) {
    return false;
  }
  const tuple = value.slice(DATASET_URN_PREFIX.length, -1).split(",");
  return (
    tuple.length === 3 &&
    tuple.every(
      (part) =>
        part.length > 0 &&
        !part.includes("(") &&
        !part.includes(")")
    )
  );
}

function invalidCurrentLineage(url: string, message: string): never {
  throw new VersionHistoryReadError(
    "INVALID_RESPONSE",
    `DataHub current upstreamLineage response ${message}`,
    url
  );
}

function parseDeclaredUpstreams(
  value: Record<string, unknown>,
  url: string
): DeclaredUpstreamLineage[] {
  const upstreams = value["upstreams"];
  if (!Array.isArray(upstreams)) {
    invalidCurrentLineage(url, "did not contain a raw value.upstreams array");
  }

  const seen = new Set<string>();
  const declared: DeclaredUpstreamLineage[] = [];
  for (const raw of upstreams) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      invalidCurrentLineage(url, "contained a malformed upstream entry");
    }
    const entry = raw as Record<string, unknown>;
    const dataset = entry["dataset"];
    const type = entry["type"];
    if (!isExactDatasetUrn(dataset)) {
      invalidCurrentLineage(url, "contained an invalid dataset URN");
    }
    if (!DATASET_LINEAGE_TYPES.has(type as DatasetLineageType)) {
      invalidCurrentLineage(url, "contained an invalid lineage type");
    }
    if (seen.has(dataset)) {
      invalidCurrentLineage(url, "contained a duplicate dataset URN");
    }
    seen.add(dataset);
    declared.push({
      upstream: dataset,
      type: type as DatasetLineageType,
    });
  }
  return declared.sort((left, right) =>
    left.upstream < right.upstream
      ? -1
      : left.upstream > right.upstream
        ? 1
        : 0
  );
}

async function readSlot(
  fetchFn: typeof fetch,
  url: string,
  aspect: DirectAspectName,
  headers: Record<string, string>,
  requestTimeoutMs: number,
  signal?: AbortSignal
): Promise<DhVersionedAspect | null> {
  const requestSignal = signal
    ? AbortSignal.any([signal, AbortSignal.timeout(requestTimeoutMs)])
    : AbortSignal.timeout(requestTimeoutMs);
  const response = await fetchFn(url, {
    headers,
    redirect: "error",
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

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new VersionHistoryReadError(
      "INVALID_RESPONSE",
      "DataHub version-history response was not valid JSON",
      url,
      response.status
    );
  }
  if (!isDirectAspectEnvelope(body)) {
    throw new VersionHistoryReadError(
      "INVALID_RESPONSE",
      `DataHub direct ${aspect} response was not a valid GenericAspectV3 envelope`,
      url,
      response.status
    );
  }
  return body;
}

// A 404 means "no current declaration available" only after the full live harvest has
// already proved this URN is an audited dataset root through search and strict hydration.
// It is not resolution proof: the live audit reconciles [] against the complete MCP
// direct-upstream result and rejects any resolved-but-undeclared URN.
export async function readCurrentUpstreamLineage(
  gmsUrl: string,
  token: string | undefined,
  urn: string,
  options: CurrentAspectReadOptions = {}
): Promise<DeclaredUpstreamLineage[]> {
  const fetchFn = options.fetchFn ?? fetch;
  const requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
    throw new RangeError("requestTimeoutMs must be positive");
  }

  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const url = endpoint(gmsUrl, urn, "upstreamLineage", 0);
  const current = await readSlot(
    fetchFn,
    url,
    "upstreamLineage",
    headers,
    requestTimeoutMs,
    options.signal
  );
  if (!current) return [];
  if (current.value === null) {
    invalidCurrentLineage(url, "contained a null current value");
  }
  return parseDeclaredUpstreams(current.value, url);
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
