# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG PYTHON_IMAGE=python:3.11.15-slim-trixie@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
ARG UV_IMAGE=ghcr.io/astral-sh/uv@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS companion-builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /opt/archon/companion
COPY --from=uv /uv /uvx /bin/
COPY services/datahub-companion/pyproject.toml services/datahub-companion/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-build --no-install-project

FROM ${PYTHON_IMAGE} AS mcp-builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never
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

FROM ${PYTHON_IMAGE} AS runtime
ARG ARCHON_RELEASE_SHA=dev
ENV HOME=/tmp \
    PATH=/opt/archon/companion/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARCHON_AGENT_STACK_LOCK=/opt/archon/.github/locks/datahub-agent-stack.json \
    ARCHON_DATAHUB_MCP_LOCK=/opt/archon/.github/locks/datahub-mcp-v0.6.0.json \
    ARCHON_DATAHUB_SKILLS_DIR=/opt/archon/datahub-skills \
    ARCHON_CUSTOM_SKILLS_DIR=/opt/archon/contrib \
    ARCHON_DATAHUB_MCP_BIN=/opt/archon/mcp/.venv/bin/mcp-server-datahub \
    TOOLS_IS_MUTATION_ENABLED=false \
    TOOLS_IS_USER_ENABLED=false \
    DATA_QUALITY_TOOLS_ENABLED=false \
    DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=true \
    SEMANTIC_SEARCH_ENABLED=false \
    FASTMCP_HOST=0.0.0.0 \
    FASTMCP_PORT=8000 \
    FASTMCP_MASK_ERROR_DETAILS=true \
    FASTMCP_STRICT_INPUT_VALIDATION=true \
    FASTMCP_CHECK_FOR_UPDATES=off \
    FASTMCP_ENABLE_RICH_LOGGING=false \
    FASTMCP_HOME=/tmp/fastmcp
LABEL org.opencontainers.image.source="https://github.com/upgradedev/archon-datahub" \
      org.opencontainers.image.revision="${ARCHON_RELEASE_SHA}" \
      org.opencontainers.image.title="Archon DataHub Runtime" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /opt/archon/companion
RUN <<'PYTHON_RUNTIME'
set -eu
rm -rf /usr/local/lib/python3.11/site-packages
mkdir -p /usr/local/lib/python3.11/site-packages
rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11 /usr/local/bin/wheel
test -x /usr/local/bin/python3.11
/usr/local/bin/python3.11 --version
test -z "$(ls -A /usr/local/lib/python3.11/site-packages)"
/usr/local/bin/python3.11 -c 'import importlib.util; assert all(importlib.util.find_spec(name) is None for name in ("pip", "setuptools", "wheel"))'
test ! -e /usr/local/bin/pip
test ! -e /usr/local/bin/pip3
test ! -e /usr/local/bin/pip3.11
test ! -e /usr/local/bin/wheel
PYTHON_RUNTIME
COPY --from=companion-builder --chown=65532:65532 /opt/archon/companion/.venv ./.venv
COPY --from=mcp-builder --chown=65532:65532 /opt/archon/mcp/.venv /opt/archon/mcp/.venv
COPY --from=mcp-builder --chown=65532:65532 /opt/archon/mcp/.archon-evidence/resolved-lock-binding.json /opt/archon/mcp/.archon-evidence/resolved-lock-binding.json
COPY --from=mcp-builder --chown=65532:65532 /opt/archon/mcp/.archon-evidence/wheel-only-graph.json /opt/archon/mcp/.archon-evidence/wheel-only-graph.json
COPY --chown=65532:65532 services/datahub-companion/archon_companion.py ./
COPY --chown=65532:65532 .github/locks/datahub-agent-stack.json /opt/archon/.github/locks/datahub-agent-stack.json
COPY --chown=65532:65532 .github/locks/datahub-mcp-v0.6.0.json /opt/archon/.github/locks/datahub-mcp-v0.6.0.json
COPY --chown=65532:65532 contrib/datahub-audit/SKILL.md /opt/archon/contrib/datahub-audit/SKILL.md
COPY --from=datahub-skills --chown=65532:65532 /LICENSE /opt/archon/licenses/datahub-skills-LICENSE
COPY --from=datahub-skills --chown=65532:65532 /skills/datahub-search/SKILL.md /opt/archon/datahub-skills/skills/datahub-search/SKILL.md
COPY --from=datahub-skills --chown=65532:65532 /skills/datahub-lineage/SKILL.md /opt/archon/datahub-skills/skills/datahub-lineage/SKILL.md
COPY --from=datahub-skills --chown=65532:65532 /skills/datahub-quality/SKILL.md /opt/archon/datahub-skills/skills/datahub-quality/SKILL.md
COPY --from=datahub-skills --chown=65532:65532 /skills/datahub-enrich/SKILL.md /opt/archon/datahub-skills/skills/datahub-enrich/SKILL.md
COPY --from=datahub-skills --chown=65532:65532 /skills/using-datahub/SKILL.md /opt/archon/datahub-skills/skills/using-datahub/SKILL.md
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=4 \
  CMD ["/opt/archon/companion/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/livez', timeout=3).read(1024)"]
CMD ["/opt/archon/companion/.venv/bin/python", "-m", "uvicorn", "archon_companion:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
