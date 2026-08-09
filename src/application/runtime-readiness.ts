export interface DatasetScopeLookup {
  search(query?: string): Promise<readonly string[]>;
}

export type DataHubRuntimeMode = "fixture" | "live";

export type RuntimeReadiness =
  | { readonly status: "ready"; readonly datahubMode: DataHubRuntimeMode }
  | {
      readonly status: "unavailable";
      readonly datahubMode: "live";
      readonly reason: "configuration_missing" | "scope_not_exact" | "provider_unreachable";
    };

export interface RuntimeReadinessProbe {
  check(): Promise<RuntimeReadiness>;
}

export interface DataHubRuntimeReadinessOptions {
  readonly mode: DataHubRuntimeMode;
  readonly demoQuery?: string;
  readonly cacheTtlMs?: number;
}

/**
 * Proves that the configured public scope can be resolved before advertising a live runtime.
 * The result is deliberately small and never carries provider errors, endpoints, or credentials.
 */
export class DataHubRuntimeReadinessProbe implements RuntimeReadinessProbe {
  private cached?: { readonly expiresAt: number; readonly value: RuntimeReadiness };
  private pending?: Promise<RuntimeReadiness>;
  private readonly cacheTtlMs: number;

  constructor(
    private readonly datahub: DatasetScopeLookup,
    private readonly options: DataHubRuntimeReadinessOptions
  ) {
    const ttl = options.cacheTtlMs ?? 10_000;
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 60_000) {
      throw new Error("readiness cache TTL must be an integer between 0 and 60000 milliseconds");
    }
    this.cacheTtlMs = ttl;
  }

  async check(): Promise<RuntimeReadiness> {
    if (this.options.mode === "fixture") {
      return { status: "ready", datahubMode: "fixture" };
    }

    const now = Date.now();
    if (this.cached && this.cached.expiresAt > now) return this.cached.value;
    if (this.pending) return this.pending;

    this.pending = this.checkLive().then((value) => {
      this.cached = { value, expiresAt: Date.now() + this.cacheTtlMs };
      return value;
    });
    try {
      return await this.pending;
    } finally {
      this.pending = undefined;
    }
  }

  private async checkLive(): Promise<RuntimeReadiness> {
    const query = this.options.demoQuery;
    if (!query) {
      return {
        status: "unavailable",
        datahubMode: "live",
        reason: "configuration_missing",
      };
    }
    try {
      const urns = await this.datahub.search(query);
      return urns.length === 1
        ? { status: "ready", datahubMode: "live" }
        : { status: "unavailable", datahubMode: "live", reason: "scope_not_exact" };
    } catch {
      return {
        status: "unavailable",
        datahubMode: "live",
        reason: "provider_unreachable",
      };
    }
  }
}
