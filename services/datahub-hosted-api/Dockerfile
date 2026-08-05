# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Hosted public demo runtime: the same Node audit server as the root image, plus the
# sealed mcp-server-datahub venv the stdio transport spawns. The root image is
# distroless and cannot host an interpreter, so the public demo builds from here.
ARG NODE_IMAGE=node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3
ARG UV_IMAGE=ghcr.io/astral-sh/uv@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437

FROM ${UV_IMAGE} AS uv

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=archon-npm-dev,target=/root/.npm,sharing=locked npm ci --ignore-scripts

FROM dependencies AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM ${NODE_IMAGE} AS production-dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=archon-npm-production,target=/root/.npm,sharing=locked npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

# uv resolves its own relocatable CPython into a pinned directory, so the runtime
# stage needs no system interpreter and no cross-distribution binary copying.
FROM ${NODE_IMAGE} AS mcp-builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_INSTALL_DIR=/opt/archon/python
COPY --from=uv /uv /uvx /bin/
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY .github/locks/datahub-mcp-v0.6.0.json .github/locks/datahub-mcp-v0.6.0.json
COPY .github/security/openvex/datahub-mcp-setuptools-81.0.0.openvex.json .github/security/openvex/datahub-mcp-setuptools-81.0.0.openvex.json
COPY scripts/materialize-datahub-mcp-lock.sh scripts/materialize-datahub-mcp-lock.sh
RUN ARCHON_DATAHUB_MCP_LOCK_CONTRACT=.github/locks/datahub-mcp-v0.6.0.json \
    bash scripts/materialize-datahub-mcp-lock.sh /opt/archon/mcp \
    && test -x /opt/archon/mcp/.venv/bin/mcp-server-datahub \
    && test "$(/opt/archon/mcp/.venv/bin/mcp-server-datahub --version)" = \
      "mcp-server-datahub, version 0.6.0"

FROM ${NODE_IMAGE} AS runtime
ARG ARCHON_RELEASE_SHA=dev
ENV NODE_ENV=production \
    PORT=8080 \
    HOME=/tmp \
    ARCHON_RELEASE_SHA=${ARCHON_RELEASE_SHA} \
    DATAHUB_TELEMETRY_ENABLED=false \
    DATAHUB_MCP_COMMAND=/opt/archon/mcp/.venv/bin/mcp-server-datahub \
    DATAHUB_MCP_ARGS=""
LABEL org.opencontainers.image.source="https://github.com/upgradedev/archon-datahub" \
      org.opencontainers.image.revision="${ARCHON_RELEASE_SHA}" \
      org.opencontainers.image.title="Archon DataHub Hosted Demo API" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=mcp-builder --chown=65532:65532 /opt/archon/python /opt/archon/python
COPY --from=mcp-builder --chown=65532:65532 /opt/archon/mcp /opt/archon/mcp
# Fails the build if the relocated interpreter cannot start the sealed server.
RUN test "$(/opt/archon/mcp/.venv/bin/mcp-server-datahub --version)" = \
      "mcp-server-datahub, version 0.6.0"
WORKDIR /app
COPY --from=production-dependencies --chown=65532:65532 /app/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /app/dist ./dist
COPY --chown=65532:65532 package.json LICENSE NOTICE.md ./
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "dist/http/server.js"]
