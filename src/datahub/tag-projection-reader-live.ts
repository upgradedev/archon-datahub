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

function endpoint(gmsUrl: string): string {
  return `${gmsUrl.replace(/\/+$/u, "")}/openapi/v3/entity/dataset/batchGet`;
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

function record(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_RESPONSE", message);
  }
  return value as Record<string, unknown>;
}

function aspectValue(
  entity: Record<string, unknown>,
  aspectName: "schemaMetadata" | "editableSchemaMetadata",
  required: boolean
): Record<string, unknown> | undefined {
  const wrapper = entity[aspectName];
  if (wrapper === undefined && !required) return undefined;
  const envelope = record(
    wrapper,
    `DataHub response is missing a valid ${aspectName} wrapper.`
  );
  if (!Object.prototype.hasOwnProperty.call(envelope, "value")) {
    fail("INVALID_RESPONSE", `DataHub ${aspectName} wrapper is missing value.`);
  }
  return record(
    envelope["value"],
    `DataHub ${aspectName} value must be an object.`
  );
}

function fieldsByPath(
  value: unknown,
  collectionName: "schemaMetadata.fields" | "editableSchemaMetadata.editableSchemaFieldInfo"
): Map<string, Record<string, unknown>> {
  if (!Array.isArray(value)) {
    fail("INVALID_RESPONSE", `DataHub ${collectionName} must be an array.`);
  }
  const fields = new Map<string, Record<string, unknown>>();
  for (const candidate of value) {
    const field = record(candidate, `Every ${collectionName} entry must be an object.`);
    const fieldPath = field["fieldPath"];
    if (typeof fieldPath !== "string" || !fieldPath.trim()) {
      fail("INVALID_RESPONSE", `Every ${collectionName} entry must have a fieldPath.`);
    }
    if (fields.has(fieldPath)) {
      fail("INVALID_RESPONSE", `DataHub ${collectionName} contains a duplicate fieldPath.`);
    }
    fields.set(fieldPath, field);
  }
  return fields;
}

export function parseTagProjectionResponse(
  value: unknown,
  target: { entityUrn: string; columnPath: string }
): TagProjection {
  if (!Array.isArray(value) || value.length !== 1) {
    fail(
      "INVALID_RESPONSE",
      "DataHub tag projection batchGet must return exactly one entity."
    );
  }
  const entity = record(
    value[0],
    "DataHub tag projection batchGet entity must be an object."
  );
  if (entity["urn"] !== target.entityUrn) {
    fail("INVALID_RESPONSE", "DataHub tag projection batchGet returned the wrong entity.");
  }

  const schemaMetadata = aspectValue(entity, "schemaMetadata", true)!;
  const schemaFields = fieldsByPath(
    schemaMetadata["fields"],
    "schemaMetadata.fields"
  );
  const schemaField = schemaFields.get(target.columnPath);
  if (!schemaField) {
    fail(
      "INVALID_RESPONSE",
      "The requested field must resolve to exactly one schemaMetadata field."
    );
  }

  const editableSchemaMetadata = aspectValue(
    entity,
    "editableSchemaMetadata",
    false
  );
  let editableField: Record<string, unknown> | undefined;
  if (editableSchemaMetadata) {
    editableField = fieldsByPath(
      editableSchemaMetadata["editableSchemaFieldInfo"],
      "editableSchemaMetadata.editableSchemaFieldInfo"
    ).get(target.columnPath);
  }

  const tags = [
    ...tagUrns(schemaField["globalTags"]),
    ...tagUrns(editableField?.["globalTags"]),
  ];
  return createTagProjection({
    entityUrn: target.entityUrn,
    columnPath: target.columnPath,
    tags: [...new Set(tags)].sort((a, b) => a.localeCompare(b)),
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
    const response = await this.#fetch(endpoint(this.#gmsUrl), {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.#token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([
        {
          urn: target.entityUrn,
          schemaMetadata: {},
          editableSchemaMetadata: {},
        },
      ]),
      redirect: "error",
      signal: AbortSignal.timeout(this.#requestTimeoutMs),
    });
    if (!response.ok) {
      fail(
        "HTTP_ERROR",
        `DataHub tag projection batchGet failed with HTTP ${response.status}.`
      );
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      fail("INVALID_RESPONSE", "DataHub tag projection batchGet is not valid JSON.");
    }
    return parseTagProjectionResponse(body, target);
  }
}
