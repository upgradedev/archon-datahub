import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const evidenceMocks = vi.hoisted(() => ({
  build: vi.fn(),
  download: vi.fn(),
  manifest: vi.fn(),
  verify: vi.fn(),
}));

vi.mock("./evidence-pack", () => ({
  buildBrowserEvidencePack: evidenceMocks.build,
  downloadEvidenceFile: evidenceMocks.download,
  manifestFile: evidenceMocks.manifest,
  verifyBrowserEvidencePack: evidenceMocks.verify,
}));

import { EvidencePack } from "./EvidencePack";
import type {
  BrowserEvidencePack,
  EvidencePackFile,
} from "./evidence-pack";
import { previewAudit } from "./fixtures";
import type { LoadedAudit } from "./types";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function audit(requestId: string): LoadedAudit {
  return {
    envelope: {
      ...previewAudit,
      requestId,
    },
    source: "fixture",
  };
}

function pack(marker: string, fileCount: number): BrowserEvidencePack {
  const files: EvidencePackFile[] = Array.from(
    { length: fileCount },
    (_, index) => ({
      path: `audit/${marker}-${index}.json`,
      mediaType: "application/json",
      bytes: 3,
      sha256: `sha256:${String(index + 1).repeat(64)}`,
      content: "{}\n",
    }),
  );
  return {
    manifest: {
      schemaVersion: "archon.browser-evidence-pack/v1",
      evidenceClass: "SYNTHETIC_SHOWCASE_FIXTURE",
      integrity: {
        model: "SELF_CONSISTENCY_ONLY",
        authenticityClaimed: false,
        sourceBinding: "INTERNAL_FIELDS_CONSISTENT",
      },
      source: {
        requestId: marker,
        releaseSha: "fixture-release",
        scanId: "fixture-scan",
        sourceKind: "fixture",
      },
      claims: {
        projectionPolicy: "EXACT_PUBLIC_ALLOWLIST_V1",
        credentialHandling: "SCHEMA_EXCLUDED_AND_PATTERN_REJECTED",
        includesRawOrchestrationState: false,
        includesPrivateEvidenceObjects: false,
      },
      summary: {
        entities: 1,
        findings: 0,
        contradictions: 0,
        lineageGaps: 0,
        governanceViolations: 0,
        terminalOutcome: "NOT_AVAILABLE",
      },
      files: files.map(
        ({ path, mediaType, bytes, sha256: fileDigest }) => ({
          path,
          mediaType,
          bytes,
          sha256: fileDigest,
        }),
      ),
    },
    manifestDigest: `sha256:${"a".repeat(64)}`,
    files,
    verification: {
      valid: true,
      checks: [{ checkId: "MANIFEST_SCHEMA_VALID", passed: true }],
    },
  };
}

beforeEach(() => {
  evidenceMocks.build.mockReset();
  evidenceMocks.download.mockReset();
  evidenceMocks.manifest.mockReset();
  evidenceMocks.verify.mockReset();
  evidenceMocks.verify.mockResolvedValue({ valid: true, checks: [] });
});

describe("EvidencePack", () => {
  it("ignores an older build that resolves after the audit changes", async () => {
    const first = deferred<BrowserEvidencePack>();
    const second = deferred<BrowserEvidencePack>();
    evidenceMocks.build.mockImplementation((value: LoadedAudit) =>
      value.envelope.requestId === "audit-a"
        ? first.promise
        : second.promise,
    );
    const auditA = audit("audit-a");
    const auditB = audit("audit-b");
    const view = render(<EvidencePack audit={auditA} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Prepare & verify pack" }),
    );
    view.rerender(<EvidencePack audit={auditB} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare & verify pack" }),
    );

    await act(async () => {
      first.resolve(pack("audit-a", 1));
      await first.promise;
    });
    expect(screen.queryByText(/1 files verified/u)).not.toBeInTheDocument();
    expect(screen.getByText("Verifying…")).toBeInTheDocument();

    await act(async () => {
      second.resolve(pack("audit-b", 2));
      await second.promise;
    });
    expect(await screen.findByText(/2 files verified/u)).toBeInTheDocument();
    expect(screen.queryByText(/1 files verified/u)).not.toBeInTheDocument();
  });

  it("fails closed when manifest re-verification rejects", async () => {
    const readyPack = pack("audit-a", 1);
    evidenceMocks.build.mockResolvedValue(readyPack);
    evidenceMocks.manifest.mockRejectedValue(
      new Error("manifest verification failed"),
    );
    render(<EvidencePack audit={audit("audit-a")} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Prepare & verify pack" }),
    );
    expect(await screen.findByText(/1 files verified/u)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Download manifest" }),
    );

    expect(
      await screen.findByText("manifest verification failed"),
    ).toBeInTheDocument();
    expect(evidenceMocks.download).not.toHaveBeenCalled();
  });

  it("cancels a download when the audit changes during its digest await", async () => {
    const digest = deferred<void>();
    const click = vi.fn();
    evidenceMocks.build.mockResolvedValue(pack("audit-a", 1));
    evidenceMocks.download.mockImplementation(
      async (
        _file: EvidencePackFile,
        mayDownload: () => boolean,
      ) => {
        await digest.promise;
        if (mayDownload()) click();
      },
    );
    const auditA = audit("audit-a");
    const auditB = audit("audit-b");
    const view = render(<EvidencePack audit={auditA} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Prepare & verify pack" }),
    );
    expect(await screen.findByText(/1 files verified/u)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "audit-a-0.json" }),
    );
    await waitFor(() =>
      expect(evidenceMocks.download).toHaveBeenCalledTimes(1),
    );

    view.rerender(<EvidencePack audit={auditB} />);
    await act(async () => {
      digest.resolve();
      await digest.promise;
    });

    expect(click).not.toHaveBeenCalled();
  });
});
