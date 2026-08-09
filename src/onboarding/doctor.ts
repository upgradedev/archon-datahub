import { pathToFileURL } from "node:url";

const MAX_QUERY_CHARS = 256;
const MAX_RESPONSE_CHARS = 1_000_000;

type FetchPort = (
  input: string | URL,
  init?: RequestInit
) => Promise<Response>;

export interface OnboardingDoctorOptions {
  readonly apiUrl: string;
  readonly datahubGmsUrl: string;
  readonly query: string;
  readonly request?: FetchPort;
  readonly write?: (message: string) => void;
  readonly readinessTimeoutMs?: number;
  readonly auditTimeoutMs?: number;
}

export interface OnboardingDoctorSummary {
  readonly releaseSha: string;
  readonly findings: number;
  readonly traceSteps: number;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid JSON object`);
  }
  return value as Record<string, unknown>;
}

function exactOrigin(value: string, label: string, protocols: readonly string[]): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute URL`);
  }
  if (
    !protocols.includes(parsed.protocol) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(`${label} must be a credential-free origin using ${protocols.join(" or ")}`);
  }
  return parsed;
}

function exactQuery(value: string): string {
  if (
    value.length === 0 ||
    value.length > MAX_QUERY_CHARS ||
    value !== value.trim() ||
    /[*?\u0000-\u001f\u007f]/u.test(value) ||
    value === "{}"
  ) {
    throw new Error("ARCHON_DEMO_QUERY must be one exact, trimmed dataset query without wildcards");
  }
  return value;
}

function positiveTimeout(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 120_000) {
    throw new Error(`${label} must be an integer between 1 and 120000 milliseconds`);
  }
  return value;
}

async function json(response: Response, label: string): Promise<Record<string, unknown>> {
  const body = await response.text();
  if (body.length > MAX_RESPONSE_CHARS) {
    throw new Error(`${label} response exceeded the bounded doctor limit`);
  }
  try {
    return record(JSON.parse(body), label);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(label)) throw error;
    throw new Error(`${label} returned invalid JSON`);
  }
}

export async function runOnboardingDoctor(
  options: OnboardingDoctorOptions
): Promise<OnboardingDoctorSummary> {
  const api = exactOrigin(options.apiUrl, "ARCHON_API_URL", ["http:", "https:"]);
  exactOrigin(options.datahubGmsUrl, "DATAHUB_GMS_URL", ["https:"]);
  const query = exactQuery(options.query);
  const request = options.request ?? fetch;
  const readinessTimeout = positiveTimeout(
    options.readinessTimeoutMs ?? 15_000,
    "readiness timeout"
  );
  const auditTimeout = positiveTimeout(options.auditTimeoutMs ?? 90_000, "audit timeout");

  const readinessResponse = await request(new URL("/readyz", api), {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(readinessTimeout),
  });
  const readiness = await json(readinessResponse, "readiness");
  const releaseSha = readiness["releaseSha"];
  if (
    !readinessResponse.ok ||
    readiness["status"] !== "ready" ||
    readiness["datahubMode"] !== "live" ||
    typeof releaseSha !== "string" ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(releaseSha)
  ) {
    throw new Error("readiness did not prove a live, reachable, exact DataHub scope");
  }

  const auditResponse = await request(new URL("/api/audits", api), {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-request-id": "archon-onboarding-doctor",
    },
    body: JSON.stringify({ query }),
    signal: AbortSignal.timeout(auditTimeout),
  });
  const audit = await json(auditResponse, "audit");
  const report = record(audit["report"], "audit report");
  if (
    !auditResponse.ok ||
    audit["releaseSha"] !== releaseSha ||
    !Array.isArray(report["findings"]) ||
    !Array.isArray(report["trace"])
  ) {
    throw new Error("scoped audit did not return a valid report from the ready release");
  }

  const summary = {
    releaseSha,
    findings: report["findings"].length,
    traceSteps: report["trace"].length,
  };
  (options.write ?? ((message) => process.stdout.write(`${message}\n`)))(
    `Archon doctor passed: ready/live release ${summary.releaseSha}; scoped audit returned ${summary.findings} finding(s) across ${summary.traceSteps} trace step(s).`
  );
  return summary;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  await runOnboardingDoctor({
    apiUrl: required("ARCHON_API_URL"),
    datahubGmsUrl: required("ARCHON_DATAHUB_GMS_URL"),
    query: required("ARCHON_DEMO_QUERY"),
  });
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (isMain) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unknown failure";
    process.stderr.write(`Archon doctor failed: ${message}\n`);
    process.exit(1);
  });
}
