import { createHash } from "node:crypto";

export type Sha256Digest = `sha256:${string}`;

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

function normalize(value: unknown, ancestors: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError("Only finite JSON numbers can be canonicalized.");
    }
    return Object.is(value, -0) ? 0 : value;
  }

  if (
    value === undefined ||
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    throw new CanonicalizationError(`Unsupported JSON value: ${typeof value}.`);
  }

  if (typeof value !== "object") {
    throw new CanonicalizationError("Unsupported value.");
  }
  if (ancestors.has(value)) {
    throw new CanonicalizationError("Circular values cannot be canonicalized.");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalize(item, ancestors));
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalizationError("Only plain JSON objects can be canonicalized.");
    }

    const record = value as Record<string, unknown>;
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      normalized[key] = normalize(record[key], ancestors);
    }
    return normalized;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value, new Set<object>()));
}

export function digest(value: unknown): Sha256Digest {
  const hash = createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
  return `sha256:${hash}`;
}

export function verifyDigest(value: unknown, expected: Sha256Digest): boolean {
  return /^sha256:[a-f0-9]{64}$/u.test(expected) && digest(value) === expected;
}

export function withoutDigest<T extends { digest: Sha256Digest }>(value: T): Omit<T, "digest"> {
  const { digest: _digest, ...unsigned } = value;
  return unsigned;
}
