# Hosted demo: one-time configuration

The public demo at <https://archon-datahub.web.app> can run a **real** audit
against a **real** DataHub. This document is the complete list of things that
must exist outside this repository before the `Hosted demo deploy` workflow can
succeed. Everything inside the repository is already in place.

The workflow fails closed at every one of these: it refuses to start if a
variable is missing, and it refuses to finish unless `/readyz` reports
`datahubMode: "live"` bound to the exact release SHA it just deployed.

### GitHub Actions policy prerequisite

The repository uses `allowed_actions=selected`. Add only these two patterns to
the selected-action allowlist before dispatching this workflow:

- `google-github-actions/auth@*`
- `google-github-actions/setup-gcloud@*`

Keep `sha_pinning_required=true`. Do not enable all verified actions. Without
these two patterns GitHub rejects the workflow before creating a job, which is
reported as `startup_failure` with no job log.

## The shape of the deployment

```
browser ──► Firebase Hosting (archon-datahub)
                │  /api/**, /healthz, /readyz  (rewrite, so the browser stays same-origin)
                ▼
            Cloud Run  archon-datahub-api   europe-west1   upgradegr-challenges
                │  spawns mcp-server-datahub 0.6.0 over stdio, from the sealed lock
                │  Direct VPC egress, private ranges only
                ▼
            datahub-core  10.132.0.10:8080   europe-west1-b   (GMS, no public ingress)
```

Two properties are deliberate:

- **The API sends no CORS headers.** Firebase rewrites make the API same-origin,
  so no other site can drive it from a browser.
- **DataHub has no public ingress on 8080.** Cloud Run reaches it on a private
  address through Direct VPC egress, so nothing about the metadata service is
  exposed to the internet. `default-allow-internal` on the `default` network
  already permits this; no new firewall rule is needed, and none should be added.

The synthetic demo instance currently relies on network isolation: it contains
no private customer data, has no public GMS ingress, exposes one fixed read-only
query, and gives Cloud Run no write route. This is an explicit demo exception,
not the supported customer posture. Customer deployments require DataHub
metadata-service authentication and a distinct least-privilege read token.

## 1. Workload Identity Federation

The workflow authenticates with OIDC and holds no long-lived key.

```bash
PROJECT=upgradegr-challenges
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"

gcloud iam service-accounts create archon-datahub-deploy \
  --project "${PROJECT}" --display-name "Archon DataHub hosted demo deploy"

gcloud iam service-accounts create archon-datahub-runtime \
  --project "${PROJECT}" --display-name "Archon DataHub read-only runtime"

gcloud iam service-accounts create archon-datahub-proof \
  --project "${PROJECT}" --display-name "Archon DataHub governed proof tunnel"

gcloud iam workload-identity-pools create github \
  --project "${PROJECT}" --location global --display-name "GitHub Actions"

WIF_CONDITION="assertion.repository=='upgradedev/archon-datahub' && assertion.ref=='refs/heads/master'"
WIF_CONDITION+=" && (assertion.job_workflow_ref=='upgradedev/archon-datahub/.github/workflows/hosted-demo.yml@refs/heads/master'"
WIF_CONDITION+=" || assertion.job_workflow_ref=='upgradedev/archon-datahub/.github/workflows/live-governed-proof.yml@refs/heads/master')"

gcloud iam workload-identity-pools providers create-oidc github \
  --project "${PROJECT}" --location global --workload-identity-pool github \
  --display-name "GitHub" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "${WIF_CONDITION}"

SA="archon-datahub-deploy@${PROJECT}.iam.gserviceaccount.com"
RUNTIME_SA="archon-datahub-runtime@${PROJECT}.iam.gserviceaccount.com"
PROOF_SA="archon-datahub-proof@${PROJECT}.iam.gserviceaccount.com"
POOL="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github"

gcloud iam service-accounts add-iam-policy-binding "${SA}" \
  --project "${PROJECT}" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/${POOL}/attribute.repository/upgradedev/archon-datahub"

gcloud iam service-accounts add-iam-policy-binding "${PROOF_SA}" \
  --project "${PROJECT}" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/${POOL}/attribute.repository/upgradedev/archon-datahub"
```

For an existing provider, apply the same condition with `providers update-oidc` before either
workflow is enabled. The workflow-ref and `master` checks are essential: a repository-only
condition would also accept OIDC requests from PR-triggered CI jobs that execute untrusted
change-set code.

```bash
gcloud iam workload-identity-pools providers update-oidc github \
  --project "${PROJECT}" --location global --workload-identity-pool github \
  --attribute-condition "${WIF_CONDITION}"
```

Roles the deploy identity needs:

| Role | Why |
| --- | --- |
| `roles/artifactregistry.writer` | push the image |
| `roles/run.admin` | deploy the service |
| `roles/iam.serviceAccountUser` on `archon-datahub-runtime` | deploy only as the narrow runtime identity |
| `roles/compute.networkUser` on the `default` subnet in `europe-west1` | Direct VPC egress |
| `roles/firebasehosting.admin` | release the SPA |
| `roles/secretmanager.viewer` on the token secret | customer profile only; verify the configured secret version exists |

The runtime identity has no project-level role. Grant it only
`roles/secretmanager.secretAccessor` on the single DataHub read-token secret in the customer
profile. The synthetic demo profile needs no IAM role at all. Never run the container as the
default Compute Engine service account or as the deploy identity.

The governed proof uses a third, distinct identity. Grant `archon-datahub-proof` only
`compute.instances.get`, `compute.instances.list`, and
`iap.tunnelInstances.accessViaIAP`, scoped to the `datahub-core` VM wherever GCP supports
resource-level binding. Do not grant Artifact Registry, Cloud Run, Firebase Hosting,
service-account-user, Secret Manager, or VPC-administration roles. The workflow fails before
OIDC if the proof identity is empty or equals either the deploy or runtime identity.

## 2. The DataHub read token

For the customer/production profile, enable metadata-service authentication,
create a least-privilege read token, and store it without it ever passing
through GitHub or a chat window:

```bash
printf '%s' '<paste-the-token>' | gcloud secrets create datahub-gms-token \
  --project upgradegr-challenges --replication-policy automatic --data-file=-

gcloud secrets add-iam-policy-binding datahub-gms-token \
  --project upgradegr-challenges \
  --role roles/secretmanager.secretAccessor \
  --member "serviceAccount:archon-datahub-runtime@upgradegr-challenges.iam.gserviceaccount.com"
```

Set the non-secret repository variable `DATAHUB_GMS_TOKEN_SECRET` to the secret
name. The workflow verifies that the secret and an enabled `latest` version
exist, then mounts it. Do not create a repository secret or variable containing
the token value. Leave the name unset only for the synthetic, private-network
demo exception described above.

## 3. Repository variables

Settings → Secrets and variables → Actions → **Variables**. These are
non-secret; the token is not among them.

| Variable | Value |
| --- | --- |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/<number>/locations/global/workloadIdentityPools/github/providers/github` |
| `GCP_DEPLOY_SERVICE_ACCOUNT` | `archon-datahub-deploy@upgradegr-challenges.iam.gserviceaccount.com` |
| `GCP_RUNTIME_SERVICE_ACCOUNT` | `archon-datahub-runtime@upgradegr-challenges.iam.gserviceaccount.com` |
| `GCP_PROOF_SERVICE_ACCOUNT` | `archon-datahub-proof@upgradegr-challenges.iam.gserviceaccount.com` |
| `DATAHUB_GMS_URL` | `http://10.132.0.10:8080` |
| `ARCHON_DEMO_QUERY` | `urn:li:dataset:(urn:li:dataPlatform:snowflake,omega_ledger_audit_target,PROD)` |
| `DATAHUB_GMS_TOKEN_SECRET` | customer profile: Secret Manager resource name; synthetic demo: unset |

`ARCHON_DEMO_QUERY` pins the public endpoint to exactly one query. Any other
input is rejected with 400, so the unauthenticated surface is a single
read-only lookup rather than an open query interface.

## 4. Deploy

```bash
gh workflow run hosted-demo.yml --repo upgradedev/archon-datahub
```

Then confirm what a judge will see:

```bash
curl -s https://archon-datahub.web.app/readyz
# {"status":"ready","releaseSha":"<sha>","datahubMode":"live"}
```

When `datahubMode` is `live`, the dashboard shows a **Run live audit** control
that needs no sign-in. Running it replaces the fixture with the report the
agent actually produced, and the source badge changes from `fixture` to `live`.

## 5. Keep the instance up

`datahub-core` holds the seeded two-ingestion-source fixture that the flagship
cross-source contradiction depends on. It cannot be recreated quickly. It must
stay running for the whole judging window. At `e2-standard-4` that is roughly
`$0.14`/hour.

Its internal address `10.132.0.10` survives a stop/start, but reserving it
removes all doubt:

```bash
gcloud compute addresses create datahub-core-internal \
  --project upgradegr-challenges --region europe-west1 \
  --subnet default --addresses 10.132.0.10
```

## What stays behind a human gate

The governed write-back is not reachable from the public path: the hosted API exposes no
write route and holds no write credential. It runs only through
`.github/workflows/live-governed-proof.yml` on `master`. Before OIDC, the workflow revalidates
the exact solo-owner and master-only GitHub environment policy, then binds exactly one
approved run event (reviewer ID/login, environment ID, state, and content-bound comment) to
the plan. Write and rollback use separate protected environments and separate approval
comments printed in the prepare-job summary. Recovery remains independently approved even
when forward execution fails.
