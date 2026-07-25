import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildBrowserEvidencePack,
  canonicalJson,
  downloadEvidenceFile,
  sha256,
  verifyBrowserEvidencePack,
  type BrowserEvidencePack,
  type EvidencePackFile,
} from "./evidence-pack";
import { previewAudit } from "./fixtures";
import modelProvenanceCorpus from "../../contracts/model-provenance-v1.cases.json";
import type {
  ControlLoopStatus,
  LoadedAudit,
} from "./types";

const fixtureAudit: LoadedAudit = {
  envelope: previewAudit,
  source: "fixture",
};
const SHA256_ABC =
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

function bytesFromHex(value: string): ArrayBuffer {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(
      value.slice(index * 2, index * 2 + 2),
      16,
    );
  }
  return bytes.buffer;
}

function sourceBytes(source: BufferSource): Uint8Array {
  return source instanceof ArrayBuffer
    ? new Uint8Array(source)
    : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function materializeCredentialMacros(value: unknown): unknown {
  let encoded = JSON.stringify(value);
  for (const [name, fragments] of Object.entries(
    modelProvenanceCorpus.credentialMacros,
  )) {
    encoded = encoded.replaceAll(
      `{{credential:${name}}}`,
      fragments.join(""),
    );
  }
  return JSON.parse(encoded) as unknown;
}

beforeEach(() => {
  vi.stubGlobal("crypto", {
    subtle: {
      digest: async (algorithm: AlgorithmIdentifier, source: BufferSource) => {
        if (algorithm !== "SHA-256") {
          throw new Error("unexpected digest algorithm");
        }
        const input = sourceBytes(source);
        if (new TextDecoder().decode(input) === "abc") {
          return bytesFromHex(SHA256_ABC);
        }
        const output = new Uint8Array(32);
        for (const [index, byte] of input.entries()) {
          const slot = index % output.length;
          output[slot] =
            (output[slot] ?? 0) ^ byte ^ ((index * 131) & 0xff);
        }
        return output.buffer;
      },
    },
  } as unknown as Crypto);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function file(
  path: string,
  mediaType: string,
  content: string,
): Promise<EvidencePackFile> {
  return {
    path,
    mediaType,
    bytes: new TextEncoder().encode(content).byteLength,
    sha256: await sha256(content),
    content,
  };
}

async function reseal(
  pack: BrowserEvidencePack,
  files: EvidencePackFile[],
  manifestOverrides: Partial<BrowserEvidencePack["manifest"]> = {},
): Promise<BrowserEvidencePack> {
  const manifest = {
    ...pack.manifest,
    ...manifestOverrides,
    files: files.map(
      ({ path, mediaType, bytes, sha256: fileDigest }) => ({
        path,
        mediaType,
        bytes,
        sha256: fileDigest,
      }),
    ),
  };
  return {
    ...pack,
    manifest,
    manifestDigest: await sha256(canonicalJson(manifest)),
    files,
  };
}

describe("browser judge evidence pack", () => {
  it("keeps evidence export conformant with the shared provenance corpus", async () => {
    expect(modelProvenanceCorpus.schemaVersion).toBe(
      "archon.model-provenance-conformance/v1",
    );
    for (const candidate of modelProvenanceCorpus.cases) {
      const provenance = materializeCredentialMacros(candidate.value);
      const loaded = structuredClone(fixtureAudit);
      loaded.source =
        (
          provenance as {
            source?: unknown;
          }
        ).source === "live-provider"
          ? "live"
          : "fixture";
      (
        loaded.envelope.report as unknown as Record<string, unknown>
      ).modelProvenance = provenance;

      if (candidate.valid) {
        await expect(buildBrowserEvidencePack(loaded)).resolves.toMatchObject({
          schemaVersion: "archon.browser-evidence-pack/v1",
        });
      } else {
        await expect(buildBrowserEvidencePack(loaded)).rejects.toThrow(
          /model runtime provenance|public allowlist/iu,
        );
      }
    }
  });

  it("builds a deterministic exact public projection with honest integrity claims", async () => {
    const first = await buildBrowserEvidencePack(fixtureAudit);
    const second = await buildBrowserEvidencePack(fixtureAudit);

    expect(await sha256("abc")).toBe(`sha256:${SHA256_ABC}`);
    expect(canonicalJson(first.manifest)).toEqual(
      canonicalJson(second.manifest),
    );
    expect(first.manifestDigest).toEqual(second.manifestDigest);
    expect(first.verification.valid).toBe(true);
    expect(first.files.map((entry) => entry.path)).toEqual([
      "audit/report.json",
      "audit/report.md",
      "audit/report.sarif",
    ]);
    expect(first.manifest.evidenceClass).toBe(
      "SYNTHETIC_SHOWCASE_FIXTURE",
    );
    expect(first.manifest.integrity).toEqual({
      model: "SELF_CONSISTENCY_ONLY",
      authenticityClaimed: false,
      sourceBinding: "INTERNAL_FIELDS_CONSISTENT",
    });
    expect(first.manifest.claims).toEqual({
      projectionPolicy: "EXACT_PUBLIC_ALLOWLIST_V1",
      credentialHandling: "SCHEMA_EXCLUDED_AND_PATTERN_REJECTED",
      includesRawOrchestrationState: false,
      includesPrivateEvidenceObjects: false,
    });

    const reportFile = first.files.find(
      (entry) => entry.path === "audit/report.json",
    );
    expect(reportFile).toBeDefined();
    const reportText = reportFile?.content ?? "";
    expect(reportText).toContain(
      '"schemaVersion": "archon.browser-audit-projection/v1"',
    );
    expect(reportText).not.toContain('"values"');
    expect(reportText).not.toContain('"actor"');
    expect(reportText).not.toContain('"value"');
    expect(reportText).not.toContain('"trace"');
    expect(JSON.stringify(first)).not.toContain("taskToken");
    expect(JSON.stringify(first)).not.toContain("DATAHUB_GMS_TOKEN");

    const report = JSON.parse(reportText) as {
      modelProvenance?: unknown;
    };
    expect(report.modelProvenance).toEqual(
      fixtureAudit.envelope.report.modelProvenance,
    );
    const markdown = first.files.find(
      (entry) => entry.path === "audit/report.md",
    );
    expect(markdown?.content).toContain("## Model runtime provenance");
    expect(markdown?.content).toContain("- Model call: `no`");
    expect(markdown?.content).toContain(
      "No provider model API call occurred",
    );
    const sarifFile = first.files.find(
      (entry) => entry.path === "audit/report.sarif",
    );
    const sarif = JSON.parse(sarifFile?.content ?? "{}") as {
      runs?: Array<{
        properties?: { modelProvenance?: unknown };
      }>;
    };
    expect(sarif.runs?.[0]?.properties?.modelProvenance).toEqual(
      report.modelProvenance,
    );
  });

  it("renders live privacy-safe model provenance consistently across all public artifacts", async () => {
    const liveModelProvenance = {
      schemaVersion: "archon.model-runtime-provenance/v1",
      source: "live-provider",
      modelCall: true,
      provider: "qwen",
      requestedModel: "qwen/qwen3-235b-a22b",
      returnedModel: "qwen/qwen3-235b-a22b",
      providerResponseId: "resp_qwen_20260725_0001",
      tokenUsage: {
        inputTokens: 384,
        outputTokens: 96,
        totalTokens: 480,
      },
      latencyMs: 842,
    } as const;
    const liveAudit: LoadedAudit = {
      source: "live",
      envelope: {
        ...fixtureAudit.envelope,
        report: {
          ...fixtureAudit.envelope.report,
          modelProvenance: liveModelProvenance,
        },
      },
    };

    const pack = await buildBrowserEvidencePack(liveAudit);
    expect(pack.verification.valid).toBe(true);
    const reportFile = pack.files.find(
      (entry) => entry.path === "audit/report.json",
    );
    const report = JSON.parse(reportFile?.content ?? "{}") as {
      modelProvenance?: unknown;
    };
    expect(report.modelProvenance).toEqual(liveModelProvenance);

    const markdown = pack.files.find(
      (entry) => entry.path === "audit/report.md",
    );
    expect(markdown?.content).toContain("- Model call: `yes`");
    expect(markdown?.content).toContain("- Provider: `qwen`");
    expect(markdown?.content).toContain(
      "- Token usage: 384 input / 96 output / 480 total",
    );
    expect(markdown?.content).toContain(
      "- Client-observed latency: 842 ms",
    );

    const sarifFile = pack.files.find(
      (entry) => entry.path === "audit/report.sarif",
    );
    const sarif = JSON.parse(sarifFile?.content ?? "{}") as {
      runs?: Array<{
        properties?: { modelProvenance?: unknown };
      }>;
    };
    expect(sarif.runs?.[0]?.properties?.modelProvenance).toEqual(
      liveModelProvenance,
    );
  });

  it("fails verification when one public artifact is modified", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const tampered = {
      ...pack,
      files: pack.files.map((entry, index) =>
        index === 0
          ? { ...entry, content: `${entry.content}tampered` }
          : entry,
      ),
    };

    const verification = await verifyBrowserEvidencePack(tampered);
    expect(verification.valid).toBe(false);
    expect(
      verification.checks.find(
        (check) => check.checkId === "FILE_DIGESTS_VALID",
      )?.passed,
    ).toBe(false);
  });

  it("drops arbitrary raw detail and rejects credential-shaped public text", async () => {
    const extraPrivateDetail = structuredClone(fixtureAudit);
    const rawDetail =
      extraPrivateDetail.envelope.report.findings[0]!
        .detail as unknown as Record<string, unknown>;
    rawDetail["secret"] = "ordinary-private-provider-value";
    rawDetail["raw_provider_debug"] = {
      opaque: "must-not-enter-the-pack",
    };
    const pack = await buildBrowserEvidencePack(extraPrivateDetail);
    const serialized = JSON.stringify(pack);
    expect(serialized).not.toContain("ordinary-private-provider-value");
    expect(serialized).not.toContain("must-not-enter-the-pack");
    expect(serialized).not.toContain("raw_provider_debug");

    const credentialInAllowedField: LoadedAudit = {
      ...fixtureAudit,
      envelope: {
        ...fixtureAudit.envelope,
        report: {
          ...fixtureAudit.envelope.report,
          narrative:
            "Provider returned Bearer abcdefghijklmnopqrstuvwxyz0123456789",
        },
      },
    };
    await expect(
      buildBrowserEvidencePack(credentialInAllowedField),
    ).rejects.toThrow(/credential-shaped value/u);

    const credentialInDynamicKey: LoadedAudit = {
      ...fixtureAudit,
      envelope: {
        ...fixtureAudit.envelope,
        report: {
          ...fixtureAudit.envelope.report,
          classification: {
            ...fixtureAudit.envelope.report.classification,
            domains: {
              ...fixtureAudit.envelope.report.classification.domains,
              "token=abcdefghijklmnopqrstuvwxyz": 1,
            },
          },
        },
      },
    };
    await expect(
      buildBrowserEvidencePack(credentialInDynamicKey),
    ).rejects.toThrow(/credential-shaped key/u);
  });

  it("rejects credential-shaped substrings embedded in model provenance", async () => {
    const loaded = structuredClone(fixtureAudit);
    loaded.source = "live";
    loaded.envelope.report.modelProvenance = {
      schemaVersion: "archon.model-runtime-provenance/v1",
      source: "live-provider",
      modelCall: true,
      provider: "custom",
      requestedModel: "custom-model",
      returnedModel: "custom-model",
      providerResponseId: "response-safe-001",
      tokenUsage: null,
      latencyMs: 12,
    };
    loaded.envelope.report.modelProvenance.returnedModel =
      `model_sk-${"x".repeat(32)}`;
    await expect(buildBrowserEvidencePack(loaded)).rejects.toThrow(
      /invalid|outside the exact public allowlist/u,
    );

    loaded.envelope.report.modelProvenance.returnedModel = "qwen-plus";
    loaded.envelope.report.modelProvenance.providerResponseId =
      `resp_sk-${"x".repeat(32)}`;
    await expect(buildBrowserEvidencePack(loaded)).rejects.toThrow(
      /invalid|outside the exact public allowlist/u,
    );
  });

  it("rejects aligned short secret and JWT shapes anywhere in public evidence", async () => {
    const unsafeValues = [
      `sk-${"x".repeat(12)}`,
      `eyJ${"a".repeat(8)}.${"b".repeat(8)}.${"c".repeat(8)}`,
    ];
    for (const unsafeValue of unsafeValues) {
      const loaded = structuredClone(fixtureAudit);
      loaded.envelope.report.narrative = `Provider diagnostic ${unsafeValue}`;
      await expect(buildBrowserEvidencePack(loaded)).rejects.toThrow(
        /credential-shaped value/u,
      );
    }
  });

  it("rejects extra private model provenance fields before export", async () => {
    const privateProvenance: LoadedAudit = {
      ...fixtureAudit,
      envelope: {
        ...fixtureAudit.envelope,
        report: {
          ...fixtureAudit.envelope.report,
          modelProvenance: {
            ...fixtureAudit.envelope.report.modelProvenance,
            endpoint: "https://provider.example.invalid/v1",
            prompt: "must-never-enter-the-pack",
          } as unknown as LoadedAudit["envelope"]["report"]["modelProvenance"],
        },
      },
    };

    await expect(
      buildBrowserEvidencePack(privateProvenance),
    ).rejects.toThrow(/exact public allowlist/u);
  });

  it("checks cancellation after the asynchronous digest and before download", async () => {
    const digest = deferred<ArrayBuffer>();
    vi.stubGlobal("crypto", {
      subtle: {
        digest: vi.fn().mockReturnValue(digest.promise),
      },
    } as unknown as Crypto);
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => undefined);
    let current = true;
    const pending = downloadEvidenceFile(
      {
        path: "audit/report.json",
        mediaType: "application/json",
        bytes: 3,
        sha256: `sha256:${"a".repeat(64)}`,
        content: "{}\n",
      },
      () => current,
    );

    current = false;
    digest.resolve(bytesFromHex("a".repeat(64)));
    await pending;

    expect(click).not.toHaveBeenCalled();
    click.mockRestore();
  });

  it("rejects a control-loop status that is not bound to the audit", async () => {
    const mismatched: ControlLoopStatus = {
      schemaVersion: "archon.control-loop-status/v1",
      auditId: "different-audit",
      status: "RUNNING",
      updatedAt: "2026-07-25T12:00:00.000Z",
    };

    await expect(
      buildBrowserEvidencePack(fixtureAudit, mismatched),
    ).rejects.toThrow(/does not match the audit request/u);
  });

  it("detects internally inconsistent source fields even after resealing", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const manifest = {
      ...pack.manifest,
      source: {
        ...pack.manifest.source,
        scanId: "different-scan",
      },
    };
    const resealed = {
      ...pack,
      manifest,
      manifestDigest: await sha256(canonicalJson(manifest)),
    };

    const verification = await verifyBrowserEvidencePack(resealed);
    expect(
      verification.checks.find(
        (check) => check.checkId === "MANIFEST_DIGEST_VALID",
      )?.passed,
    ).toBe(true);
    expect(
      verification.checks.find(
        (check) => check.checkId === "SOURCE_FIELDS_CONSISTENT",
      )?.passed,
    ).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("rejects extra files even when every digest is recomputed", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const extra = await file(
      "private/debug.json",
      "application/json",
      '{"debug":"not allowed"}\n',
    );
    const resealed = await reseal(pack, [...pack.files, extra]);

    const verification = await verifyBrowserEvidencePack(resealed);
    expect(
      verification.checks.find(
        (check) => check.checkId === "MANIFEST_DIGEST_VALID",
      )?.passed,
    ).toBe(true);
    expect(
      verification.checks.find(
        (check) => check.checkId === "FILE_SET_EXACT",
      )?.passed,
    ).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("rejects a non-exact report projection even when files are resealed", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const reportIndex = pack.files.findIndex(
      (entry) => entry.path === "audit/report.json",
    );
    expect(reportIndex).toBeGreaterThanOrEqual(0);
    const report = JSON.parse(
      pack.files[reportIndex]?.content ?? "{}",
    ) as Record<string, unknown>;
    report["unexpected"] = "not in the public contract";
    const changed = await file(
      "audit/report.json",
      "application/json",
      `${JSON.stringify(report, null, 2)}\n`,
    );
    const files = pack.files.map((entry, index) =>
      index === reportIndex ? changed : entry,
    );
    const resealed = await reseal(pack, files);

    const verification = await verifyBrowserEvidencePack(resealed);
    expect(
      verification.checks.find(
        (check) => check.checkId === "FILE_DIGESTS_VALID",
      )?.passed,
    ).toBe(true);
    expect(
      verification.checks.find(
        (check) => check.checkId === "PUBLIC_PROJECTION_VALID",
      )?.passed,
    ).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("fails closed on legacy report projections without model provenance", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const reportIndex = pack.files.findIndex(
      (entry) => entry.path === "audit/report.json",
    );
    expect(reportIndex).toBeGreaterThanOrEqual(0);
    const report = JSON.parse(
      pack.files[reportIndex]?.content ?? "{}",
    ) as Record<string, unknown>;
    delete report["modelProvenance"];
    const changed = await file(
      "audit/report.json",
      "application/json",
      `${JSON.stringify(report, null, 2)}\n`,
    );
    const files = pack.files.map((entry, index) =>
      index === reportIndex ? changed : entry,
    );
    const resealed = await reseal(pack, files);

    const verification = await verifyBrowserEvidencePack(resealed);
    expect(
      verification.checks.find(
        (check) => check.checkId === "FILE_DIGESTS_VALID",
      )?.passed,
    ).toBe(true);
    expect(
      verification.checks.find(
        (check) => check.checkId === "PUBLIC_PROJECTION_VALID",
      )?.passed,
    ).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("rejects a valid JSON provenance change when Markdown and SARIF replay do not match", async () => {
    const pack = await buildBrowserEvidencePack(fixtureAudit);
    const reportIndex = pack.files.findIndex(
      (entry) => entry.path === "audit/report.json",
    );
    expect(reportIndex).toBeGreaterThanOrEqual(0);
    const report = JSON.parse(
      pack.files[reportIndex]?.content ?? "{}",
    ) as {
      modelProvenance?: Record<string, unknown>;
    };
    expect(report.modelProvenance).toBeDefined();
    if (report.modelProvenance) {
      report.modelProvenance["requestedModel"] =
        "archon-deterministic-fixture-narrator-v2";
    }
    const changed = await file(
      "audit/report.json",
      "application/json",
      `${JSON.stringify(report, null, 2)}\n`,
    );
    const files = pack.files.map((entry, index) =>
      index === reportIndex ? changed : entry,
    );
    const resealed = await reseal(pack, files);

    const verification = await verifyBrowserEvidencePack(resealed);
    expect(
      verification.checks.find(
        (check) => check.checkId === "FILE_DIGESTS_VALID",
      )?.passed,
    ).toBe(true);
    expect(
      verification.checks.find(
        (check) => check.checkId === "PUBLIC_PROJECTION_VALID",
      )?.passed,
    ).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("includes only the exact public terminal projection", async () => {
    const status: ControlLoopStatus = {
      schemaVersion: "archon.control-loop-status/v1",
      auditId: fixtureAudit.envelope.requestId,
      status: "SUCCEEDED",
      updatedAt: "2026-07-25T12:00:00.000Z",
      releaseSha: fixtureAudit.envelope.releaseSha,
      result: {
        outcome: "VERIFIED",
        receiptDigest: `sha256:${"7".repeat(64)}`,
        executionEvidenceDigest: `sha256:${"8".repeat(64)}`,
        completedAt: "2026-07-25T11:59:59.000Z",
        verification: {
          checks: [
            { checkId: "TARGET_UNCHANGED", passed: true },
            { checkId: "PREEXISTING_TAGS_PRESERVED", passed: true },
            { checkId: "POLICY_TAG_PRESENT", passed: true },
            { checkId: "NO_UNEXPECTED_TAGS", passed: true },
            { checkId: "APPROVAL_BINDING_VALID", passed: true },
          ],
          eventCount: 7,
          rollbackAvailability: "ELIGIBLE",
        },
      },
    };
    const pack = await buildBrowserEvidencePack(fixtureAudit, status);

    expect(pack.verification.valid).toBe(true);
    expect(pack.manifest.summary.terminalOutcome).toBe("VERIFIED");
    expect(pack.files.map((entry) => entry.path)).toContain(
      "control/terminal-proof.json",
    );
    const terminal = pack.files.find(
      (entry) => entry.path === "control/terminal-proof.json",
    );
    expect(terminal?.content).not.toContain("taskToken");
    expect(terminal?.content).not.toContain("approval");
  });
});
