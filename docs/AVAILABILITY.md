# Production availability evidence

`Production availability` is a scheduled and manually dispatchable, read-only synthetic
probe of the public production path. It runs every six hours at minute 17 and can also be
started from GitHub Actions when a release needs immediate verification.

The workflow deliberately uses the existing `production-observer` GitHub environment but
does not use AWS credentials, OIDC, or long-lived secrets. Its only credential is the
short-lived repository-scoped `GITHUB_TOKEN`, with `contents: read` and `actions: read`,
used to bind public observations to GitHub's release evidence.

## Configuration

Set these environment variables on `production-observer`:

| Variable | Contract |
| --- | --- |
| `ARCHON_APPLICATION_URL` | Exact public HTTPS origin, such as `https://archon.example.com`, with no trailing slash, path, query, fragment, user info, or non-default port. |
| `DATAHUB_DEMO_QUERY` | A trimmed 1–256 character query for a dedicated, public-safe demo dataset. It must contain no wildcard and must resolve exactly one entity. |

Manual dispatch accepts optional `application_url` and `query` inputs. Each input overrides
its environment variable for that run and is validated by the same fail-closed rules.
These values are not secrets; do not place production DataHub tokens, model credentials,
cookies, access tokens, or steward credentials in either field.

The environment should allow only the `master` branch. The workflow also reads the
repository and ref APIs and fails closed unless:

- the repository default branch is exactly `master`;
- the workflow ref and SHA are the current default-branch head at both the beginning and
  the final control-plane recheck;
- the release reported by the public audit response is the current `master` commit or an
  ancestor retained for an intentional rollback;
- the **newest successful** default-branch `deploy.yml` run, and no older historical run,
  owns one unexpired `deployment-evidence-<release>-<attempt>` artifact for that release;
- the artifact's immutable GitHub digest, compressed byte count, workflow-run ownership,
  name, and expiry state are exact;
- the sealed `rollbackSelector.ciRunId` identifies the successful, exact-release
  default-branch `ci.yml` run; and
- the deployment evidence binds the deployment control-plane SHA, public application URL,
  runtime-config digest, live-runtime-manifest digest, identical production image digest,
  and successful staging/production promotion.

GitHub may report a workflow path either as `.github/workflows/<name>.yml` or as that exact
path followed by `@master`. Those are the only accepted variants. The workflow repeats the
newest-deployment selection immediately before producing evidence and also re-reads the
exact deployment attempt, CI run, artifact metadata, repository default branch, and
default-branch ref. A deployment or control-plane change during the observation therefore
invalidates the run instead of producing a stale receipt.

## Probe contract

One run performs exactly three public requests:

1. `GET /` verifies a bounded HTML response, zero redirects, TLS 1.3, the application
   mount point, cache behavior, and the exact deployed browser-security headers.
2. `GET /runtime-config.json` verifies zero redirects, a bounded no-store JSON response,
   exact keys, PKCE/Cognito HTTPS endpoints on one auth origin, the application redirect
   and logout URIs, and the exact `openid`, `email`, `archon/approve` scope set. Its public
   bytes must be identical to `production-runtime-config.json` in deployment evidence.
3. `POST /api/audits` submits one canonical `{"query":"..."}` body. This endpoint is the
   synchronous read-only audit path. The probe enforces a 50-second request deadline, a
   4 MiB response limit, zero redirects, security headers, exact response/report shapes,
   exactly one classified entity, the four expected read-only agents, and the absence of
   secret-bearing keys or recognizable credential material. The single `X-Request-Id`
   response header must equal the JSON body `requestId`. It never calls an approval,
   remediation, or rollback route.

All three responses must contain exactly one copy of the production CSP, HSTS
(`max-age=63072000; includeSubDomains; preload`), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, and `X-XSS-Protection` contract. The CSP is matched
directive-for-directive, including the sole Cognito origin derived from the validated
runtime config. Header presence alone is not sufficient.

The public runtime config intentionally does not contain a release SHA. It is an
authentication bootstrap document, not a deployment ledger. The workflow therefore binds
its exact bytes and redirect URIs to the observed application origin, obtains the exact
release SHA from the same-origin read-only audit response, and corroborates that SHA
against `master` and the newest sealed deployment. The archived live-runtime manifest must
bind that release and production image and must contain exactly one `index.html` and one
`runtime-config.json` object whose SHA-256 and byte count match the public responses.

Before any file is extracted, the downloaded ZIP is checked against GitHub's digest and
compressed byte count. A bounded parser then rejects unsafe or duplicate paths,
non-regular entries, encryption, unsupported compression, oversized entries or totals,
excessive compression ratios, and missing/duplicate required files. It streams only
`deployment-evidence.json`, `production-runtime-config.json`, and
`live-runtime-manifest.json` into new runner-temporary files with per-file byte limits.

## Retained evidence

Successful runs upload
`production-availability-<release-sha>-<run-attempt>` for 90 days. The artifact contains
exactly:

- `availability.json` — a sanitized projection with source/run identifiers, hashes of the
  application origin and response bodies, classification counts, agent names, release
  SHA, live-runtime-manifest digest, the exact rollback-selector CI ID, newest-deployment
  identifiers, and explicit public-byte/final-recheck results;
- `manifest.json` — `archon.production-availability-manifest/v1`, binding the exact
  `availability.json` SHA-256 and byte count; and
- `SHA256SUMS` — checksums for both JSON files, verified before upload.

Raw HTML, runtime config, audit output, query text, request/scan IDs, and the downloaded
deployment archive remain under `runner.temp` and are not uploaded. Public client/auth
origins and IDs are represented only by hashes in the retained projection.

## Honest scope

This check demonstrates synthetic availability of one bounded public read journey and
provides tamper-evident release evidence. Its three public requests are sequential, so it
is an internally cross-bound, point-in-time observation rather than an atomic distributed
snapshot. It does not provide an SLA, browser rendering or login coverage, continuous
traffic monitoring, regional performance measurements, AWS stack/drift inspection, queue
or worker-depth inspection, notification delivery, or an authenticated governed-write
exercise.

Those concerns remain covered by their purpose-built pipelines: immutable deployment,
production posture, production supply-chain rescan, live DataHub proof, and the governed
canary/recovery workflows. GitHub marks a failed scheduled probe in Actions; external
paging requires a separately configured notification integration.
