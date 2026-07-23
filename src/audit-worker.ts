import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { S3Client } from "@aws-sdk/client-s3";
import { pathToFileURL } from "node:url";
import { createDataHubClient } from "./datahub/mcp-client.js";
import { DirectGmsTagProjectionReader } from "./datahub/tag-projection-reader-live.js";
import { canonicalize } from "./remediation/integrity.js";
import {
  AwsQueueWorker,
  DynamoAuditResultCheckpoint,
  S3ImmutableEvidenceStore,
} from "./worker/aws-adapters.js";
import {
  httpsUrl,
  rejectCapabilities,
  releaseSha,
  required,
} from "./worker/configuration.js";
import { AuditWorkerService } from "./worker/service.js";

interface AuditWorkerConfiguration {
  queueUrl: string;
  quarantineQueueUrl: string;
  idempotencyTable: string;
  evidenceBucket: string;
  releaseSha: string;
  readGmsUrl: string;
  readToken: string;
}

export function loadAuditWorkerConfiguration(): AuditWorkerConfiguration {
  rejectCapabilities([
    "ARCHON_APPROVAL_TABLE",
    "ARCHON_APPROVAL_QUEUE_URL",
    "ARCHON_APPROVAL_DLQ_URL",
    "ARCHON_REMEDIATION_QUEUE_URL",
    "ARCHON_REMEDIATION_DLQ_URL",
    "DATAHUB_WRITE_GMS_TOKEN",
    "DATAHUB_WRITE_GMS_URL",
    "DATAHUB_WRITE_MCP_URL",
  ]);
  const readGmsUrl = httpsUrl("DATAHUB_GMS_URL");
  httpsUrl("DATAHUB_MCP_URL");
  httpsUrl("LLM_BASE_URL");
  required("LLM_API_KEY", 16_384);
  return {
    queueUrl: httpsUrl("ARCHON_AUDIT_QUEUE_URL"),
    quarantineQueueUrl: httpsUrl("ARCHON_AUDIT_DLQ_URL"),
    idempotencyTable: required("ARCHON_IDEMPOTENCY_TABLE", 255),
    evidenceBucket: required("ARCHON_EVIDENCE_BUCKET", 255),
    releaseSha: releaseSha(),
    readGmsUrl,
    readToken: required("DATAHUB_GMS_TOKEN", 16_384),
  };
}

export async function main(): Promise<void> {
  const configuration = loadAuditWorkerConfiguration();
  const evidence = new S3ImmutableEvidenceStore(
    new S3Client({}),
    configuration.evidenceBucket
  );
  const service = new AuditWorkerService({
    dataHub: await createDataHubClient(),
    tagReader: new DirectGmsTagProjectionReader({
      gmsUrl: configuration.readGmsUrl,
      token: configuration.readToken,
    }),
    evidence,
    auditCheckpoint: new DynamoAuditResultCheckpoint(
      new DynamoDBClient({}),
      configuration.idempotencyTable
    ),
    releaseSha: configuration.releaseSha,
  });

  const stop = new AbortController();
  process.once("SIGTERM", () => stop.abort());
  process.once("SIGINT", () => stop.abort());
  console.log(
    canonicalize({
      event: "audit_worker_started",
      releaseSha: configuration.releaseSha,
    })
  );
  await new AwsQueueWorker({
    kind: "audit",
    queueUrl: configuration.queueUrl,
    quarantineQueueUrl: configuration.quarantineQueueUrl,
    service,
    signal: stop.signal,
  }).run();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    console.error(
      canonicalize({
        event: "audit_worker_fatal",
        error: error instanceof Error ? error.name : "UnknownError",
      })
    );
    process.exitCode = 1;
  });
}
