// Deliberately narrow DataHub write seam for Archon's G6 remediation loop.
//
// This is NOT part of DataHubClient and is NOT exposed by Archon's public MCP server.
// The capability is intentionally limited to the two tag mutations supported by the
// accepted G6 control: callers cannot pass arbitrary tool names or arbitrary arguments.

import type { Sha256Digest } from "../remediation/integrity.js";

export interface TagMutationRequest {
  readonly tagUrns: readonly string[];
  readonly entityUrns: readonly string[];
  readonly columnPaths?: readonly (string | null)[];
}

// A successful mutation returns evidence digests only. The upstream MCP response is never
// allowed across this boundary because messages may contain tenant metadata or operational
// details that do not belong in an approval receipt.
export interface MutationDigestReceipt {
  readonly requestDigest: Sha256Digest;
  readonly responseDigest: Sha256Digest;
}

export interface MutationCallOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export interface DataHubMutationClient {
  addTags(
    request: TagMutationRequest,
    options?: MutationCallOptions
  ): Promise<MutationDigestReceipt>;
  removeTags(
    request: TagMutationRequest,
    options?: MutationCallOptions
  ): Promise<MutationDigestReceipt>;
}

// Keep construction lazy, as with the read client: consumers that only audit a catalog never
// load transport code and therefore never acquire a write-capable dependency path.
export async function createDataHubMutationClient(): Promise<DataHubMutationClient> {
  const { LiveDataHubMutationClient } = await import("./mutation-client-live.js");
  return new LiveDataHubMutationClient();
}
