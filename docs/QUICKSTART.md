# Customer quickstart

This is the supported local customer path: one read-only Archon API connected to one
authenticated HTTPS DataHub origin and restricted to one exact dataset query. It does not
start DataHub, accept write credentials, expose a public port, or enable remediation.

## Prerequisites

- Docker Engine with Docker Compose v2.20 or newer
- an HTTPS DataHub GMS origin reachable from Docker
- a least-privilege DataHub read token
- one narrow query that resolves to exactly one dataset

Copy `quickstart.env.example` to `.env`, then replace all three required values. `.env` is
gitignored. Keep the URL as an origin such as `https://datahub.example.com`, with no embedded
credential, path, query string, or fragment.

## Start and prove readiness

```bash
docker compose up --build --detach --wait api
```

This command fails unless the container starts and `/readyz` proves that the configured
query reaches exactly one live DataHub dataset. The API binds only to
`http://127.0.0.1:8080` by default.

## Execute the smoke audit

```bash
docker compose run --rm doctor
```

The doctor independently rejects plaintext or credential-bearing DataHub URLs, rechecks
live readiness, submits only `ARCHON_DEMO_QUERY`, and accepts only a bounded public audit
report from the same release. A clean dataset may correctly return zero findings.

Stop the local stack with `docker compose down`. For production, put the API behind your
authenticated ingress and secret manager; do not publish this local Compose binding or
copy the synthetic hosted-demo exception into a customer environment.
