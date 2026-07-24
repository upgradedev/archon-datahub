import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { S3Client } from "@aws-sdk/client-s3";
import { pathToFileURL } from "node:url";
import { createDataHubMutationClient } from "./datahub/mutation-client.js";
import { DirectGmsTagProjectionReader } from "./datahub/tag-projection-reader-live.js";
import { canonicalize } from "./remediation/integrity.js";
import {
  AwsQueueWorker,
  DynamoExecutionJournal,
  S3ImmutableEvidenceStore,
} from "./worker/aws-adapters.js";
import {
  httpsUrl,
  rejectCapabilities,
  releaseSha,
  required,
} from "./worker/configuration.js";
import { RemediationWorkerService } from "./worker/service.js";

interface RemediationWorkerConfiguration {
  queueUrl: string;
  quarantineQueueUrl: string;
  idempotencyTable: string;
  evidenceBucket: string;
  releaseSha: string;
  writeGmsUrl: string;
  writeToken: string;
}

export function loadRemediationWorkerConfiguration(): RemediationWorkerConfiguration {
  rejectCapabilities([
    "ARCHON_APPROVAL_TABLE",
    "ARCHON_APPROVAL_QUEUE_URL",
    "ARCHON_APPROVAL_DLQ_URL",
    "ARCHON_AUDIT_QUEUE_URL",
    "ARCHON_AUDIT_DLQ_URL",
    "DATAHUB_GMS_TOKEN",
    "DATAHUB_GMS_URL",
    "DATAHUB_MCP_URL",
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
  ]);
  const writeGmsUrl = httpsUrl("DATAHUB_WRITE_GMS_URL");
  httpsUrl("DATAHUB_WRITE_MCP_URL");
  return {
    queueUrl: httpsUrl("ARCHON_REMEDIATION_QUEUE_URL"),
    quarantineQueueUrl: httpsUrl("ARCHON_REMEDIATION_DLQ_URL"),
    idempotencyTable: required("ARCHON_IDEMPOTENCY_TABLE", 255),
    evidenceBucket: required("ARCHON_EVIDENCE_BUCKET", 255),
    releaseSha: releaseSha(),
    writeGmsUrl,
    writeToken: required("DATAHUB_WRITE_GMS_TOKEN", 16_384),
  };
}

export async function main(): Promise<void> {
  const configuration = loadRemediationWorkerConfiguration();
  const service = new RemediationWorkerService({
    tagReader: new DirectGmsTagProjectionReader({
      gmsUrl: configuration.writeGmsUrl,
      token: configuration.writeToken,
    }),
    mutation: await createDataHubMutationClient(),
    journal: new DynamoExecutionJournal(
      new DynamoDBClient({}),
      configuration.idempotencyTable
    ),
    evidence: new S3ImmutableEvidenceStore(
      new S3Client({}),
      configuration.evidenceBucket
    ),
  });

  const stop = new AbortController();
  process.once("SIGTERM", () => stop.abort());
  process.once("SIGINT", () => stop.abort());
  console.log(
    canonicalize({
      event: "remediation_worker_started",
      releaseSha: configuration.releaseSha,
    })
  );
  await new AwsQueueWorker({
    kind: "remediation",
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
        event: "remediation_worker_fatal",
        error: error instanceof Error ? error.name : "UnknownError",
      })
    );
    process.exitCode = 1;
  });
}
