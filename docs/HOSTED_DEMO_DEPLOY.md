# Hosted demo: one-time configuration

The public demo at <https://archon-datahub.web.app> can run a **real** audit
against a **real** DataHub. This document is the complete list of things that
must exist outside this repository before the `Hosted demo deploy` workflow can
succeed. Everything inside the repository is already in place.

The workflow fails closed at every one of these: it refuses to start if a
variable is missing, and it refuses to finish unless `/readyz` reports
`datahubMode: "live"` bound to the exact release SHA it just deployed.

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

That second property is what carries the authentication weight here. The
`datahub-core` instance runs the quickstart with
`METADATA_SERVICE_AUTH_ENABLED=false`, so it issues no personal access tokens and
accepts unauthenticated reads from anything that can route to it — which is only
this Cloud Run service, over a private address. If you point the workflow at a
DataHub that does enforce metadata service auth, set the optional
`DATAHUB_GMS_TOKEN_SECRET` variable (section 2) and the bearer token is mounted.

## 1. Workload Identity Federation

The workflow authenticates with OIDC and holds no long-lived key.

```bash
PROJECT=upgradegr-challenges
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"

gcloud iam service-accounts create archon-datahub-deploy \
  --project "${PROJECT}" --display-name "Archon DataHub hosted demo deploy"

gcloud iam workload-identity-pools create github \
  --project "${PROJECT}" --location global --display-name "GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github \
  --project "${PROJECT}" --location global --workload-identity-pool github \
  --display-name "GitHub" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "assertion.repository=='upgradedev/archon-datahub'"

SA="archon-datahub-deploy@${PROJECT}.iam.gserviceaccount.com"
POOL="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github"

gcloud iam service-accounts add-iam-policy-binding "${SA}" \
  --project "${PROJECT}" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/${POOL}/attribute.repository/upgradedev/archon-datahub"
```

The attribute condition is the part that matters: without it the provider would
mint tokens for any repository on GitHub.

Roles the deploy identity needs:

| Role | Why |
| --- | --- |
| `roles/artifactregistry.writer` | push the image |
| `roles/run.admin` | deploy the service |
| `roles/iam.serviceAccountUser` on the Cloud Run runtime service account | act as the runtime identity |
| `roles/compute.networkUser` on the `default` subnet in `europe-west1` | Direct VPC egress |
| `roles/firebasehosting.admin` | release the SPA |
| `roles/secretmanager.secretAccessor` on the token secret | only when section 2 applies |

## 2. The DataHub token — optional, and not used today

The demo instance has metadata service auth disabled, so there is no token to
create and the deploy binds none. Nothing further is required for the hosted
demo to run live.

Against a DataHub that *does* enforce auth, create a personal access token in its
UI (Settings → Access Tokens) and store it without it ever passing through
GitHub or a chat window:

```bash
printf '%s' '<paste-the-token>' | gcloud secrets create datahub-gms-token \
  --project upgradegr-challenges --replication-policy automatic --data-file=-

gcloud secrets add-iam-policy-binding datahub-gms-token \
  --project upgradegr-challenges \
  --role roles/secretmanager.secretAccessor \
  --member "serviceAccount:<project-number>-compute@developer.gserviceaccount.com"
```

Then set the repository variable `DATAHUB_GMS_TOKEN_SECRET` to
`datahub-gms-token`. Leaving that variable unset is what keeps the deploy from
demanding a secret that does not exist.

## 3. Repository variables

Settings → Secrets and variables → Actions → **Variables**. These are
non-secret; the token is not among them.

| Variable | Value |
| --- | --- |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/<number>/locations/global/workloadIdentityPools/github/providers/github` |
| `GCP_DEPLOY_SERVICE_ACCOUNT` | `archon-datahub-deploy@upgradegr-challenges.iam.gserviceaccount.com` |
| `DATAHUB_GMS_URL` | `http://10.132.0.10:8080` |
| `ARCHON_DEMO_QUERY` | `urn:li:dataset:(urn:li:dataPlatform:snowflake,omega_ledger_audit_target,PROD)` |
| `DATAHUB_GMS_TOKEN_SECRET` | optional; unset for this instance (see section 2) |

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

The governed write-back is unchanged. It still requires a Cognito session, a
runtime lease, and an explicit human approval, and it is not reachable from this
public path: the hosted API exposes no write route at all.
