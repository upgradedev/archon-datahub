// Minimal production HTTP boundary for the hosted demo.
//
// The long-running container owns audit execution; AWS API Gateway/WAF/Cognito provide the
// public auth/rate-limit boundary. This server deliberately exposes no remediation/write
// route. Governed writes run in a separate worker with a separate credential.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import {
  createDataHubClient,
  hasDataHubCreds,
  type DataHubClient,
} from "../datahub/mcp-client.js";
import { AuditPipeline } from "../pipeline/pipeline.js";
import { DataHubHarvestError } from "../datahub/harvest-policy.js";

const MAX_BODY_BYTES = 8 * 1024;
const MAX_QUERY_CHARS = 256;

export interface HttpServerDeps {
  datahub: DataHubClient;
  pipeline: AuditPipeline;
  releaseSha?: string;
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cache-Control", "no-store");
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  requestId: string
): void {
  applySecurityHeaders(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("X-Request-Id", requestId);
  response.end(`${JSON.stringify(body)}\n`);
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const contentType = String(request.headers["content-type"] ?? "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new HttpInputError(415, "content-type must be application/json");
  }
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_BODY_BYTES) throw new HttpInputError(413, "request body is too large");
    chunks.push(buffer);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new HttpInputError(400, "request body must be a JSON object");
  }
}

function queryFrom(body: Record<string, unknown>): string | undefined {
  if (body.query === undefined || body.query === null || body.query === "") {
    throw new HttpInputError(400, "a narrow dataset query is required");
  }
  if (typeof body.query !== "string") throw new HttpInputError(400, "query must be a string");
  const query = body.query.trim();
  if (query.length > MAX_QUERY_CHARS) {
    throw new HttpInputError(400, `query must be at most ${MAX_QUERY_CHARS} characters`);
  }
  if (/[\u0000-\u001f\u007f]/u.test(query)) {
    throw new HttpInputError(400, "query contains control characters");
  }
  if (!query || query === "*") {
    throw new HttpInputError(400, "query must be narrow and cannot be a wildcard");
  }
  return query;
}

class HttpInputError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function requestIdOf(request: IncomingMessage): string {
  const supplied = request.headers["x-request-id"];
  const candidate = Array.isArray(supplied) ? supplied[0] : supplied;
  return typeof candidate === "string" && /^[A-Za-z0-9._-]{1,128}$/u.test(candidate)
    ? candidate
    : randomUUID();
}

export function createArchonHttpServer(deps: HttpServerDeps): Server {
  const releaseSha = deps.releaseSha || process.env.ARCHON_RELEASE_SHA || "dev";
  return createServer(async (request, response) => {
    const requestId = requestIdOf(request);
    const method = request.method ?? "GET";
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    try {
      if (method === "GET" && pathname === "/healthz") {
        return sendJson(response, 200, { status: "ok", releaseSha }, requestId);
      }
      if (method === "GET" && pathname === "/readyz") {
        return sendJson(
          response,
          200,
          { status: "ready", releaseSha, datahubMode: hasDataHubCreds() ? "live" : "fixture" },
          requestId
        );
      }
      if (method === "POST" && pathname === "/api/audits") {
        const body = await readJsonBody(request);
        const report = await deps.pipeline.run(
          deps.datahub,
          queryFrom(body),
          { executionProfile: "synchronous-preview" }
        );
        return sendJson(response, 200, { requestId, releaseSha, report }, requestId);
      }
      if (pathname === "/api/audits") {
        response.setHeader("Allow", "POST");
        return sendJson(response, 405, { error: "method_not_allowed", requestId }, requestId);
      }
      return sendJson(response, 404, { error: "not_found", requestId }, requestId);
    } catch (error: unknown) {
      if (error instanceof HttpInputError) {
        return sendJson(
          response,
          error.status,
          { error: "invalid_request", message: error.message, requestId },
          requestId
        );
      }
      if (error instanceof DataHubHarvestError) {
        const scopeError = error.code === "SEARCH_LIMIT_EXCEEDED";
        const historyError =
          error.code === "HISTORY_CAPABILITY_REQUIRED";
        const deadlineError =
          error.code === "HARVEST_DEADLINE_EXCEEDED" ||
          error.code === "PIPELINE_DEADLINE_EXCEEDED";
        return sendJson(
          response,
          scopeError ? 422 : deadlineError ? 504 : historyError ? 503 : 502,
          {
            error: scopeError
              ? "audit_scope_too_broad"
              : deadlineError
                ? "audit_deadline_exceeded"
                : historyError
                  ? "audit_history_capability_required"
                  : "datahub_response_incomplete",
            requestId,
          },
          requestId
        );
      }
      // Never serialize raw provider/MCP errors: they can contain endpoint details.
      process.stderr.write(`[http] audit_failed request_id=${requestId}\n`);
      return sendJson(response, 502, { error: "audit_failed", requestId }, requestId);
    }
  });
}

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? "8080");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  const server = createArchonHttpServer({
    datahub: await createDataHubClient(),
    pipeline: new AuditPipeline(),
  });
  server.listen(port, "0.0.0.0", () => {
    process.stderr.write(`archon-datahub HTTP ready on :${port}\n`);
  });
  const stop = (signal: string): void => {
    server.close(() => {
      process.stderr.write(`archon-datahub HTTP stopped (${signal})\n`);
      process.exit(0);
    });
  };
  process.once("SIGTERM", () => stop("SIGTERM"));
  process.once("SIGINT", () => stop("SIGINT"));
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (isMain) {
  main().catch(() => {
    process.stderr.write("archon-datahub HTTP failed to start\n");
    process.exit(1);
  });
}
