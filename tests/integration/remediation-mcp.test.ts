// Integration contract for the private DataHub write adapter. The SDK Client and Server
// communicate over an in-memory MCP transport: no network, subprocess, token, or filesystem
// artifact is involved.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  DataHubMutationError,
  LiveDataHubMutationClient,
  PINNED_DATAHUB_MUTATION_SERVER,
  type LiveDataHubMutationClientOptions,
} from "../../src/datahub/mutation-client-live.js";
import { digest } from "../../src/remediation/integrity.js";

const TAG_PROPERTIES = {
  tag_urns: { type: "array", items: { type: "string" } },
  entity_urns: { type: "array", items: { type: "string" } },
  column_paths: {
    type: "array",
    items: { anyOf: [{ type: "string" }, { type: "null" }] },
  },
} as const;

function mutationTool(name: "add_tags" | "remove_tags"): Tool {
  return {
    name,
    description: `Pinned DataHub ${name} mutation.`,
    inputSchema: {
      type: "object",
      properties: TAG_PROPERTIES,
      required: ["tag_urns", "entity_urns"],
      additionalProperties: false,
    },
  };
}

interface CapturedCall {
  name: string;
  arguments: Record<string, unknown>;
}

async function connect(
  tools: Tool[],
  respond: (call: CapturedCall) => CallToolResult,
  options: {
    discover?: () => Promise<{ tools: Tool[] }>;
    client?: LiveDataHubMutationClientOptions;
  } = {}
): Promise<{
  mutationClient: LiveDataHubMutationClient;
  calls: CapturedCall[];
  close: () => Promise<void>;
}> {
  const calls: CapturedCall[] = [];
  const server = new Server(
    { name: "datahub-mutation-fixture", version: "0.6.0" },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(
    ListToolsRequestSchema,
    options.discover ?? (async () => ({ tools }))
  );
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const call = {
      name: request.params.name,
      arguments: (request.params.arguments ?? {}) as Record<string, unknown>,
    };
    calls.push(call);
    return respond(call);
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: "archon-remediation-test", version: "0.0.0" },
    { capabilities: {} }
  );
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    mutationClient: new LiveDataHubMutationClient(client, options.client),
    calls,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

function successful(message: string): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify({ success: true, message }) }],
  };
}

test("tag write adapter uses only the exact pinned add_tags/remove_tags arguments", async () => {
  const fixture = await connect(
    [mutationTool("add_tags"), mutationTool("remove_tags")],
    () => successful("tenant-private-success-message")
  );
  try {
    const request = {
      tagUrns: ["urn:li:tag:PII"],
      entityUrns: ["urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.users,PROD)"],
      columnPaths: ["customer_email"],
    } as const;

    const addReceipt = await fixture.mutationClient.addTags(request);
    const removeReceipt = await fixture.mutationClient.removeTags(request);

    assert.deepEqual(fixture.calls, [
      {
        name: "add_tags",
        arguments: {
          tag_urns: ["urn:li:tag:PII"],
          entity_urns: [...request.entityUrns],
          column_paths: ["customer_email"],
        },
      },
      {
        name: "remove_tags",
        arguments: {
          tag_urns: ["urn:li:tag:PII"],
          entity_urns: [...request.entityUrns],
          column_paths: ["customer_email"],
        },
      },
    ]);
    for (const receipt of [addReceipt, removeReceipt]) {
      assert.deepEqual(Object.keys(receipt).sort(), ["requestDigest", "responseDigest"]);
      assert.match(receipt.requestDigest, /^sha256:[a-f0-9]{64}$/u);
      assert.match(receipt.responseDigest, /^sha256:[a-f0-9]{64}$/u);
      assert.doesNotMatch(JSON.stringify(receipt), /tenant-private|prod\.users|customer_email/u);
    }
    assert.equal(addReceipt.requestDigest, digest(request));
    assert.equal(removeReceipt.requestDigest, digest(request));
    assert.equal(addReceipt.responseDigest, removeReceipt.responseDigest);
  } finally {
    await fixture.close();
  }
});

test("tag write adapter discovers both required tools before making any mutation", async () => {
  const fixture = await connect([mutationTool("add_tags")], () => successful("not reached"));
  try {
    await assert.rejects(
      fixture.mutationClient.addTags({
        tagUrns: ["urn:li:tag:PII"],
        entityUrns: ["urn:li:dataset:test"],
      }),
      (error: unknown) => {
        assert.ok(error instanceof DataHubMutationError);
        assert.equal(error.code, "REQUIRED_TOOLS_MISSING");
        assert.match(error.message, /remove_tags/u);
        return true;
      }
    );
    assert.equal(fixture.calls.length, 0);
  } finally {
    await fixture.close();
  }
});

test("a rejected MCP discovery is not cached and the next delivery can recover", async () => {
  const tools = [mutationTool("add_tags"), mutationTool("remove_tags")];
  let discoveryAttempts = 0;
  const fixture = await connect(
    tools,
    () => successful("recovered"),
    {
      discover: async () => {
        discoveryAttempts += 1;
        if (discoveryAttempts === 1) {
          throw new Error("transient discovery failure");
        }
        return { tools };
      },
    }
  );
  const request = {
    tagUrns: ["urn:li:tag:PII"],
    entityUrns: ["urn:li:dataset:test"],
  } as const;

  try {
    await assert.rejects(
      fixture.mutationClient.addTags(request),
      (error: unknown) => {
        assert.ok(error instanceof DataHubMutationError);
        assert.equal(error.code, "MCP_ERROR");
        return true;
      }
    );
    const receipt = await fixture.mutationClient.addTags(request);
    assert.match(receipt.responseDigest, /^sha256:[a-f0-9]{64}$/u);
    assert.equal(discoveryAttempts, 2);
    assert.equal(fixture.calls.length, 1);
  } finally {
    await fixture.close();
  }
});

test("aborted MCP discovery fails promptly without poisoning a later retry", async () => {
  const tools = [mutationTool("add_tags"), mutationTool("remove_tags")];
  let discoveryAttempts = 0;
  const fixture = await connect(
    tools,
    () => successful("recovered after abort"),
    {
      discover: async () => {
        discoveryAttempts += 1;
        return { tools };
      },
      client: { initializationTimeoutMs: 1_000 },
    }
  );
  const request = {
    tagUrns: ["urn:li:tag:PII"],
    entityUrns: ["urn:li:dataset:test"],
  } as const;
  const abort = new AbortController();
  abort.abort();

  try {
    await assert.rejects(
      fixture.mutationClient.addTags(request, { signal: abort.signal }),
      (error: unknown) => {
        assert.ok(error instanceof DataHubMutationError);
        assert.equal(error.code, "MCP_ERROR");
        return true;
      }
    );
    await fixture.mutationClient.addTags(request);
    assert.equal(discoveryAttempts, 1);
    assert.equal(fixture.calls.length, 1);
  } finally {
    await fixture.close();
  }
});

test("MCP errors and negative acknowledgements fail closed without leaking server text", async (t) => {
  await t.test("isError response", async () => {
    const secret = "SECRET-UPSTREAM-DIAGNOSTIC";
    const fixture = await connect(
      [mutationTool("add_tags"), mutationTool("remove_tags")],
      () => ({ isError: true, content: [{ type: "text", text: secret }] })
    );
    try {
      await assert.rejects(
        fixture.mutationClient.addTags({
          tagUrns: ["urn:li:tag:PII"],
          entityUrns: ["urn:li:dataset:test"],
        }),
        (error: unknown) => {
          assert.ok(error instanceof DataHubMutationError);
          assert.equal(error.code, "MCP_ERROR");
          assert.doesNotMatch(error.message, new RegExp(secret, "u"));
          return true;
        }
      );
    } finally {
      await fixture.close();
    }
  });

  await t.test("success false response", async () => {
    const secret = "SECRET-FAILURE-DETAIL";
    const fixture = await connect(
      [mutationTool("add_tags"), mutationTool("remove_tags")],
      () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify({ success: false, message: secret }),
          },
        ],
      })
    );
    try {
      await assert.rejects(
        fixture.mutationClient.removeTags({
          tagUrns: ["urn:li:tag:PII"],
          entityUrns: ["urn:li:dataset:test"],
        }),
        (error: unknown) => {
          assert.ok(error instanceof DataHubMutationError);
          assert.equal(error.code, "INVALID_MCP_RESPONSE");
          assert.doesNotMatch(error.message, new RegExp(secret, "u"));
          return true;
        }
      );
    } finally {
      await fixture.close();
    }
  });
});

test("live construction never falls back to read credentials and keeps the server pin exact", async () => {
  const saved = {
    readToken: process.env.DATAHUB_GMS_TOKEN,
    readMcp: process.env.DATAHUB_MCP_URL,
    writeToken: process.env.DATAHUB_WRITE_GMS_TOKEN,
    writeMcp: process.env.DATAHUB_WRITE_MCP_URL,
    writeGms: process.env.DATAHUB_WRITE_GMS_URL,
  };
  process.env.DATAHUB_GMS_TOKEN = "READ-TOKEN-MUST-NOT-BE-USED";
  process.env.DATAHUB_MCP_URL = "https://read-only.invalid/mcp";
  delete process.env.DATAHUB_WRITE_GMS_TOKEN;
  delete process.env.DATAHUB_WRITE_MCP_URL;
  delete process.env.DATAHUB_WRITE_GMS_URL;

  try {
    assert.equal(PINNED_DATAHUB_MUTATION_SERVER, "mcp-server-datahub@0.6.0");
    const client = new LiveDataHubMutationClient();
    await assert.rejects(
      client.addTags({
        tagUrns: ["urn:li:tag:PII"],
        entityUrns: ["urn:li:dataset:test"],
      }),
      (error: unknown) => {
        assert.ok(error instanceof DataHubMutationError);
        assert.equal(error.code, "WRITE_CONFIG_MISSING");
        assert.match(error.message, /DATAHUB_WRITE_GMS_TOKEN/u);
        assert.doesNotMatch(error.message, /READ-TOKEN-MUST-NOT-BE-USED/u);
        return true;
      }
    );
  } finally {
    const restore = (name: string, value: string | undefined): void => {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    };
    restore("DATAHUB_GMS_TOKEN", saved.readToken);
    restore("DATAHUB_MCP_URL", saved.readMcp);
    restore("DATAHUB_WRITE_GMS_TOKEN", saved.writeToken);
    restore("DATAHUB_WRITE_MCP_URL", saved.writeMcp);
    restore("DATAHUB_WRITE_GMS_URL", saved.writeGms);
  }
});

test("invalid column targeting is rejected before MCP discovery or mutation", async () => {
  const fixture = await connect(
    [mutationTool("add_tags"), mutationTool("remove_tags")],
    () => successful("not reached")
  );
  try {
    await assert.rejects(
      fixture.mutationClient.addTags({
        tagUrns: ["urn:li:tag:PII"],
        entityUrns: ["urn:li:dataset:first", "urn:li:dataset:second"],
        columnPaths: ["only-one-column"],
      }),
      (error: unknown) => {
        assert.ok(error instanceof DataHubMutationError);
        assert.equal(error.code, "INVALID_REQUEST");
        return true;
      }
    );
    assert.equal(fixture.calls.length, 0);
  } finally {
    await fixture.close();
  }
});
