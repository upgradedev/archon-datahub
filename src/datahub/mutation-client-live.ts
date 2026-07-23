// Network shell for the deliberately separate, tag-only DataHub mutation capability.
//
// The wire contract is pinned to mcp-server-datahub 0.6.0:
//   add_tags/remove_tags(
//     tag_urns: List[str],
//     entity_urns: List[str],
//     column_paths: Optional[List[Optional[str]]]
//   )
//
// Unlike the read client, this adapter never falls back to DATAHUB_MCP_URL or
// DATAHUB_GMS_TOKEN. A write-capable deployment must supply an explicitly separate endpoint
// and credential. The public Archon MCP server does not import or expose this module.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { digest } from "../remediation/integrity.js";
import type {
  DataHubMutationClient,
  MutationCallOptions,
  MutationDigestReceipt,
  TagMutationRequest,
} from "./mutation-client.js";

export const PINNED_DATAHUB_MUTATION_SERVER = "mcp-server-datahub@0.6.0";

const REQUIRED_MUTATION_TOOLS = ["add_tags", "remove_tags"] as const;
const MAX_MUTATION_ITEMS = 1;
const DEFAULT_INITIALIZATION_TIMEOUT_MS = 30_000;
const CONNECTION_CLEANUP_TIMEOUT_MS = 2_000;

type MutationTool = (typeof REQUIRED_MUTATION_TOOLS)[number];
type MutationTransport =
  | StreamableHTTPClientTransport
  | StdioClientTransport;

export interface LiveDataHubMutationClientOptions {
  initializationTimeoutMs?: number;
}

interface OfficialTagMutationArguments extends Record<string, unknown> {
  tag_urns: string[];
  entity_urns: string[];
  column_paths?: Array<string | null>;
}

export class DataHubMutationError extends Error {
  constructor(
    readonly code:
      | "INVALID_REQUEST"
      | "WRITE_CONFIG_MISSING"
      | "CONNECTION_FAILED"
      | "REQUIRED_TOOLS_MISSING"
      | "MCP_ERROR"
      | "INVALID_MCP_RESPONSE",
    message: string
  ) {
    super(message);
    this.name = "DataHubMutationError";
  }
}

function fail(
  code: DataHubMutationError["code"],
  message: string
): never {
  throw new DataHubMutationError(code, message);
}

function assertStringArray(
  value: readonly string[],
  field: "tagUrns" | "entityUrns"
): void {
  if (!Array.isArray(value) || value.length === 0) {
    fail("INVALID_REQUEST", `${field} must contain at least one URN.`);
  }
  if (value.length > MAX_MUTATION_ITEMS) {
    fail("INVALID_REQUEST", `${field} exceeds the ${MAX_MUTATION_ITEMS}-item safety limit.`);
  }
  if (value.some((item) => typeof item !== "string" || item.trim().length === 0)) {
    fail("INVALID_REQUEST", `${field} must contain only non-empty URNs.`);
  }
}

function officialArguments(request: TagMutationRequest): OfficialTagMutationArguments {
  assertStringArray(request.tagUrns, "tagUrns");
  assertStringArray(request.entityUrns, "entityUrns");

  if (request.tagUrns.some((urn) => !urn.startsWith("urn:li:tag:"))) {
    fail("INVALID_REQUEST", "tagUrns must contain DataHub tag URNs.");
  }
  if (request.entityUrns.some((urn) => !urn.startsWith("urn:li:"))) {
    fail("INVALID_REQUEST", "entityUrns must contain DataHub entity URNs.");
  }

  const args: OfficialTagMutationArguments = {
    tag_urns: [...request.tagUrns],
    entity_urns: [...request.entityUrns],
  };
  if (request.columnPaths !== undefined) {
    if (!Array.isArray(request.columnPaths)) {
      fail("INVALID_REQUEST", "columnPaths must be an array when supplied.");
    }
    if (request.columnPaths.length !== request.entityUrns.length) {
      fail("INVALID_REQUEST", "columnPaths length must match entityUrns length.");
    }
    if (
      request.columnPaths.some(
        (path) => path !== null && typeof path !== "string"
      )
    ) {
      fail("INVALID_REQUEST", "columnPaths may contain only strings or null.");
    }
    args.column_paths = [...request.columnPaths];
  }
  return args;
}

function parseSuccessfulResponse(result: unknown): unknown {
  const response = result as {
    isError?: boolean;
    structuredContent?: unknown;
    content?: Array<{ type?: string; text?: string }>;
  };
  if (response?.isError === true) {
    fail("MCP_ERROR", "DataHub mutation failed closed because the MCP tool returned an error.");
  }

  let payload = response?.structuredContent;
  if (payload === undefined) {
    const text = response?.content?.find(
      (item) => item.type === "text" && typeof item.text === "string"
    )?.text;
    if (text === undefined) {
      fail("INVALID_MCP_RESPONSE", "DataHub mutation failed closed on an empty MCP response.");
    }
    try {
      payload = JSON.parse(text);
    } catch {
      fail("INVALID_MCP_RESPONSE", "DataHub mutation failed closed on a non-JSON MCP response.");
    }
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    (payload as { success?: unknown }).success !== true
  ) {
    fail(
      "INVALID_MCP_RESPONSE",
      "DataHub mutation failed closed because MCP did not attest success."
    );
  }
  return payload;
}

function runtimeEnvironment(): Record<string, string> {
  const keep = [
    "PATH",
    "Path",
    "SYSTEMROOT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "UV_CACHE_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
  ];
  return Object.fromEntries(
    keep.flatMap((name) => {
      const value = process.env[name];
      return value === undefined ? [] : [[name, value]];
    })
  );
}

async function boundedOperation<T>(input: {
  operation: () => Promise<T>;
  timeoutMs: number;
  signal?: AbortSignal;
  code: DataHubMutationError["code"];
  message: string;
}): Promise<T> {
  if (input.signal?.aborted) {
    throw new DataHubMutationError(input.code, input.message);
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
      callback();
    };
    const onAbort = (): void => {
      finish(() => reject(new DataHubMutationError(input.code, input.message)));
    };
    timer = setTimeout(() => {
      finish(() => reject(new DataHubMutationError(input.code, input.message)));
    }, input.timeoutMs);
    timer.unref();
    input.signal?.addEventListener("abort", onAbort, { once: true });

    void Promise.resolve()
      .then(input.operation)
      .then((value) => finish(() => resolve(value)))
      .catch((error: unknown) => finish(() => reject(error)));
  });
}

async function closeConnection(
  client: Client | undefined,
  transport: MutationTransport | undefined
): Promise<void> {
  if (!client && !transport) return;
  await boundedOperation({
    operation: async () => {
      await Promise.allSettled([
        ...(client ? [client.close()] : transport ? [transport.close()] : []),
      ]);
    },
    timeoutMs: CONNECTION_CLEANUP_TIMEOUT_MS,
    code: "MCP_ERROR",
    message: "DataHub mutation connection cleanup exceeded its deadline.",
  }).catch(() => undefined);
}

export class LiveDataHubMutationClient implements DataHubMutationClient {
  readonly #suppliedClient?: Client;
  readonly #initializationTimeoutMs: number;
  #client?: Client;
  #transport?: MutationTransport;
  #ready?: Promise<void>;

  // The optional connected client is an explicit test seam. Production callers construct
  // without arguments and therefore must pass the separate write configuration checks below.
  constructor(
    connectedClient?: Client,
    options: LiveDataHubMutationClientOptions = {}
  ) {
    const timeout = options.initializationTimeoutMs ?? DEFAULT_INITIALIZATION_TIMEOUT_MS;
    if (!Number.isFinite(timeout) || timeout <= 0) {
      fail("INVALID_REQUEST", "initializationTimeoutMs must be a positive finite value.");
    }
    this.#initializationTimeoutMs = timeout;
    this.#suppliedClient = connectedClient;
    this.#client = connectedClient;
  }

  async addTags(
    request: TagMutationRequest,
    options?: MutationCallOptions
  ): Promise<MutationDigestReceipt> {
    return this.#mutate("add_tags", request, options);
  }

  async removeTags(
    request: TagMutationRequest,
    options?: MutationCallOptions
  ): Promise<MutationDigestReceipt> {
    return this.#mutate("remove_tags", request, options);
  }

  async #ensureReady(signal?: AbortSignal): Promise<void> {
    let attempt = this.#ready;
    if (!attempt) {
      attempt = this.#initialize(signal);
      this.#ready = attempt;
      void attempt.catch(() => {
        if (this.#ready === attempt) this.#ready = undefined;
      });
    }
    const readyAttempt = attempt;
    return boundedOperation({
      operation: () => readyAttempt,
      timeoutMs: this.#initializationTimeoutMs,
      ...(signal ? { signal } : {}),
      code: "MCP_ERROR",
      message: "DataHub mutation initialization did not complete within its deadline.",
    });
  }

  async #initialize(signal?: AbortSignal): Promise<void> {
    let client = this.#suppliedClient;
    let transport: MutationTransport | undefined;

    if (!client) {
      const writeToken = process.env.DATAHUB_WRITE_GMS_TOKEN?.trim();
      if (!writeToken) {
        fail(
          "WRITE_CONFIG_MISSING",
          "DATAHUB_WRITE_GMS_TOKEN is required; read credentials are never used for mutation."
        );
      }

      const httpEndpoint = process.env.DATAHUB_WRITE_MCP_URL?.trim();
      try {
        client = new Client(
          { name: "archon-datahub-write", version: "0.1.0" },
          { capabilities: {} }
        );
        if (httpEndpoint) {
          transport = new StreamableHTTPClientTransport(new URL(httpEndpoint), {
            requestInit: { headers: { Authorization: `Bearer ${writeToken}` } },
          });
        } else {
          const gmsEndpoint = process.env.DATAHUB_WRITE_GMS_URL?.trim();
          if (!gmsEndpoint) {
            fail(
              "WRITE_CONFIG_MISSING",
              "DATAHUB_WRITE_MCP_URL or DATAHUB_WRITE_GMS_URL is required for mutation."
            );
          }
          transport = new StdioClientTransport({
            command: "uvx",
            args: [PINNED_DATAHUB_MUTATION_SERVER],
            env: {
              ...runtimeEnvironment(),
              DATAHUB_GMS_URL: gmsEndpoint,
              DATAHUB_GMS_TOKEN: writeToken,
              TOOLS_IS_MUTATION_ENABLED: "true",
            },
          });
        }
        await boundedOperation({
          operation: () => client!.connect(transport!),
          timeoutMs: this.#initializationTimeoutMs,
          ...(signal ? { signal } : {}),
          code: "CONNECTION_FAILED",
          message:
            "Unable to connect to the separately configured DataHub mutation endpoint.",
        });
      } catch (error) {
        await closeConnection(client, transport);
        if (error instanceof DataHubMutationError) throw error;
        fail(
          "CONNECTION_FAILED",
          "Unable to connect to the separately configured DataHub mutation endpoint."
        );
      }
    }

    let tools: Awaited<ReturnType<Client["listTools"]>>;
    try {
      tools = await boundedOperation({
        operation: () => client!.listTools(),
        timeoutMs: this.#initializationTimeoutMs,
        ...(signal ? { signal } : {}),
        code: "MCP_ERROR",
        message: "DataHub mutation failed closed during MCP tool discovery.",
      });
    } catch (error) {
      if (!this.#suppliedClient) await closeConnection(client, transport);
      if (error instanceof DataHubMutationError) throw error;
      fail("MCP_ERROR", "DataHub mutation failed closed during MCP tool discovery.");
    }
    const available = new Set(tools.tools.map((tool) => tool.name));
    const missing = REQUIRED_MUTATION_TOOLS.filter((tool) => !available.has(tool));
    if (missing.length > 0) {
      if (!this.#suppliedClient) await closeConnection(client, transport);
      fail(
        "REQUIRED_TOOLS_MISSING",
        `DataHub mutation endpoint is missing required tool(s): ${missing.join(", ")}.`
      );
    }
    this.#client = client;
    this.#transport = transport;
  }

  async #invalidateConnection(): Promise<void> {
    this.#ready = undefined;
    if (this.#suppliedClient) return;
    const client = this.#client;
    const transport = this.#transport;
    this.#client = undefined;
    this.#transport = undefined;
    await closeConnection(client, transport);
  }

  async #mutate(
    tool: MutationTool,
    request: TagMutationRequest,
    options?: MutationCallOptions
  ): Promise<MutationDigestReceipt> {
    const args = officialArguments(request);
    await this.#ensureReady(options?.signal);
    const client = this.#client;
    if (!client) {
      fail("CONNECTION_FAILED", "DataHub mutation connection is not initialized.");
    }

    let result: unknown;
    try {
      result = await client.callTool(
        { name: tool, arguments: args },
        undefined,
        {
          ...(options?.signal ? { signal: options.signal } : {}),
          timeout: options?.timeoutMs ?? 120_000,
        }
      );
    } catch {
      await this.#invalidateConnection();
      fail("MCP_ERROR", "DataHub mutation failed closed during the MCP tool call.");
    }
    const successfulResponse = parseSuccessfulResponse(result);
    // Bind the receipt to the typed port request that the control loop approved. The
    // operation itself is bound separately by the signed remediation plan and the fact that
    // this client exposes distinct addTags/removeTags methods (never a caller-supplied name).
    const approvedRequest = {
      tagUrns: [...args.tag_urns],
      entityUrns: [...args.entity_urns],
      ...(args.column_paths === undefined
        ? {}
        : { columnPaths: [...args.column_paths] }),
    };
    return {
      requestDigest: digest(approvedRequest),
      responseDigest: digest(successfulResponse),
    };
  }
}
