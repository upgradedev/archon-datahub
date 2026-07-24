import type { TagProjection, TagProjectionReader } from "../remediation/contracts.js";
import { createTagProjection } from "../remediation/planner.js";

export class TagProjectionReadError extends Error {
  constructor(
    readonly code:
      | "INVALID_CONFIGURATION"
      | "INVALID_TARGET"
      | "HTTP_ERROR"
      | "INVALID_RESPONSE",
    message: string
  ) {
    super(message);
    this.name = "TagProjectionReadError";
  }
}

interface DirectTagProjectionReaderOptions {
  gmsUrl: string;
  token: string;
  fetchFn?: typeof fetch;
  requestTimeoutMs?: number;
}

function fail(
  code: TagProjectionReadError["code"],
  message: string
): never {
  throw new TagProjectionReadError(code, message);
}

function endpoint(gmsUrl: string, entityUrn: string): string {
  return (
    `${gmsUrl.replace(/\/+$/u, "")}/openapi/v3/entity/dataset/` +
    `${encodeURIComponent(entityUrn)}/schemaMetadata?systemMetadata=true&version=0`
  );
}

function tagUrns(value: unknown): string[] {
  if (value === undefined) return [];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_RESPONSE", "Field globalTags must be an object.");
  }
  const tags = (value as { tags?: unknown }).tags;
  if (!Array.isArray(tags)) {
    fail("INVALID_RESPONSE", "Field globalTags.tags must be an array.");
  }
  const urns = tags.map((entry) => {
    if (
      !entry ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      typeof (entry as { tag?: unknown }).tag !== "string" ||
      !/^urn:li:tag:[^,\s]+$/u.test((entry as { tag: string }).tag)
    ) {
      fail("INVALID_RESPONSE", "Field tag identity must be a DataHub tag URN.");
    }
    return (entry as { tag: string }).tag;
  });
  return [...new Set(urns)].sort((a, b) => a.localeCompare(b));
}

export function parseTagProjectionResponse(
  value: unknown,
  target: { entityUrn: string; columnPath: string }
): TagProjection {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_RESPONSE", "DataHub schemaMetadata response must be an object.");
  }
  const wrapper = (value as { schemaMetadata?: unknown }).schemaMetadata;
  if (!wrapper || typeof wrapper !== "object" || Array.isArray(wrapper)) {
    fail("INVALID_RESPONSE", "DataHub response is missing schemaMetadata.");
  }
  const aspect = (wrapper as { value?: unknown }).value;
  if (!aspect || typeof aspect !== "object" || Array.isArray(aspect)) {
    fail("INVALID_RESPONSE", "DataHub schemaMetadata value is absent.");
  }
  const fields = (aspect as { fields?: unknown }).fields;
  if (!Array.isArray(fields)) {
    fail("INVALID_RESPONSE", "DataHub schemaMetadata.fields must be an array.");
  }
  const matches = fields.filter(
    (field) =>
      field &&
      typeof field === "object" &&
      !Array.isArray(field) &&
      (field as { fieldPath?: unknown }).fieldPath === target.columnPath
  );
  if (matches.length !== 1) {
    fail(
      "INVALID_RESPONSE",
      "The requested field must resolve to exactly one schemaMetadata field."
    );
  }
  return createTagProjection({
    entityUrn: target.entityUrn,
    columnPath: target.columnPath,
    tags: tagUrns((matches[0] as { globalTags?: unknown }).globalTags),
  });
}

export class DirectGmsTagProjectionReader implements TagProjectionReader {
  readonly #gmsUrl: string;
  readonly #token: string;
  readonly #fetch: typeof fetch;
  readonly #requestTimeoutMs: number;

  constructor(options: DirectTagProjectionReaderOptions) {
    let parsed: URL;
    try {
      parsed = new URL(options.gmsUrl);
    } catch {
      fail("INVALID_CONFIGURATION", "The read GMS URL is invalid.");
    }
    if (parsed.protocol !== "https:") {
      fail("INVALID_CONFIGURATION", "The read GMS URL must use HTTPS.");
    }
    if (!options.token.trim()) {
      fail("INVALID_CONFIGURATION", "A distinct read token is required.");
    }
    this.#gmsUrl = parsed.toString();
    this.#token = options.token;
    this.#fetch = options.fetchFn ?? fetch;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    if (
      !Number.isFinite(this.#requestTimeoutMs) ||
      this.#requestTimeoutMs < 1_000 ||
      this.#requestTimeoutMs > 60_000
    ) {
      fail("INVALID_CONFIGURATION", "The read timeout is outside the allowed range.");
    }
  }

  async readTagProjection(target: {
    entityUrn: string;
    columnPath: string;
  }): Promise<TagProjection> {
    if (
      !target.entityUrn.startsWith("urn:li:dataset:") ||
      target.entityUrn.length > 2048 ||
      !target.columnPath.trim() ||
      target.columnPath.length > 1024
    ) {
      fail("INVALID_TARGET", "The tag projection target is invalid.");
    }
    const response = await this.#fetch(endpoint(this.#gmsUrl, target.entityUrn), {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.#token}`,
      },
      redirect: "error",
      signal: AbortSignal.timeout(this.#requestTimeoutMs),
    });
    if (!response.ok) {
      fail("HTTP_ERROR", `DataHub schemaMetadata read failed with HTTP ${response.status}.`);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      fail("INVALID_RESPONSE", "DataHub schemaMetadata response is not valid JSON.");
    }
    return parseTagProjectionResponse(body, target);
  }
}
