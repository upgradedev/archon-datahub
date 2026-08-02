# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG LAMBDA_IMAGE=public.ecr.aws/lambda/python:3.12@sha256:182ce4c13bce31bc9fcff9a2705f2f946b59e2d32e10cdf7700883d8a59c25da
ARG UV_IMAGE=ghcr.io/astral-sh/uv@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437

FROM ${UV_IMAGE} AS uv

FROM ${LAMBDA_IMAGE} AS runtime-dependencies
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /build
COPY --from=uv /uv /uvx /bin/
COPY services/datahub-companion/pyproject.toml services/datahub-companion/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project \
      --python /var/lang/bin/python3.12

FROM runtime-dependencies AS test-dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --group test --no-install-project \
      --python /var/lang/bin/python3.12

FROM ${LAMBDA_IMAGE} AS runtime
ARG ARCHON_RELEASE_SHA=dev
ENV HOME=/tmp \
    PATH=/opt/archon/runtime/.venv/bin:${PATH} \
    PYTHONPATH=/var/task:/opt/archon/runtime/.venv/lib/python3.12/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_STS_REGIONAL_ENDPOINTS=regional \
    DATAHUB_TELEMETRY_ENABLED=false \
    OTEL_EXPORTER_OTLP_ENDPOINT="" \
    ARCHON_AGENT_STACK_LOCK=/opt/archon/.github/locks/datahub-agent-stack.json \
    ARCHON_DATAHUB_MCP_LOCK=/opt/archon/.github/locks/datahub-mcp-v0.6.0.json \
    ARCHON_DATAHUB_SKILLS_DIR=/opt/archon/datahub-skills \
    ARCHON_CUSTOM_SKILLS_DIR=/opt/archon/contrib \
    ARCHON_DEMO_QUERY="urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)" \
    ARCHON_ANALYTICS_QUESTION="Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?"
LABEL org.opencontainers.image.source="https://github.com/upgradedev/archon-datahub" \
      org.opencontainers.image.revision="${ARCHON_RELEASE_SHA}" \
      org.opencontainers.image.title="Archon DataHub Cloud Lambda Runtime v2" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=runtime-dependencies /build/.venv /opt/archon/runtime/.venv
COPY services/datahub-cloud-runtime/contracts.py /var/task/contracts.py
COPY services/datahub-cloud-runtime/managed_mcp.py /var/task/managed_mcp.py
COPY services/datahub-cloud-runtime/runtime_store.py /var/task/runtime_store.py
COPY services/datahub-cloud-runtime/analytics_runtime.py /var/task/analytics_runtime.py
COPY services/datahub-cloud-runtime/mutation_runtime.py /var/task/mutation_runtime.py
COPY services/datahub-cloud-runtime/fixture_reset.py /var/task/fixture_reset.py
COPY services/datahub-cloud-runtime/handlers.py /var/task/handlers.py
COPY services/datahub-companion/archon_companion.py /var/task/archon_companion.py
COPY services/datahub-companion/demo/archon_demo.sql /opt/archon/demo/archon_demo.sql
COPY contracts/datahub-core-mutation-authorization-golden.json /opt/archon/contracts/core-mutation-authorization-golden.json
COPY .github/locks/datahub-agent-stack.json /opt/archon/.github/locks/datahub-agent-stack.json
COPY .github/locks/datahub-mcp-v0.6.0.json /opt/archon/.github/locks/datahub-mcp-v0.6.0.json
COPY contrib/datahub-audit/SKILL.md /opt/archon/contrib/datahub-audit/SKILL.md
COPY --from=datahub-skills /LICENSE /opt/archon/licenses/datahub-skills-LICENSE
COPY --from=datahub-skills /skills/datahub-search/SKILL.md /opt/archon/datahub-skills/skills/datahub-search/SKILL.md
COPY --from=datahub-skills /skills/datahub-lineage/SKILL.md /opt/archon/datahub-skills/skills/datahub-lineage/SKILL.md
COPY --from=datahub-skills /skills/datahub-quality/SKILL.md /opt/archon/datahub-skills/skills/datahub-quality/SKILL.md
COPY --from=datahub-skills /skills/datahub-enrich/SKILL.md /opt/archon/datahub-skills/skills/datahub-enrich/SKILL.md
COPY --from=datahub-skills /skills/using-datahub/SKILL.md /opt/archon/datahub-skills/skills/using-datahub/SKILL.md
RUN test -x /opt/archon/runtime/.venv/bin/python \
    && test -f /var/task/handlers.py \
    && test -f /opt/archon/demo/archon_demo.sql \
    && test -f /opt/archon/contracts/core-mutation-authorization-golden.json \
    && chmod 0555 /var/task/*.py \
    && chmod 0444 /opt/archon/demo/archon_demo.sql \
      /opt/archon/contracts/core-mutation-authorization-golden.json \
      /opt/archon/.github/locks/*.json \
    && chmod 0444 \
      /opt/archon/licenses/datahub-skills-LICENSE \
      /opt/archon/datahub-skills/skills/datahub-search/SKILL.md \
      /opt/archon/datahub-skills/skills/datahub-lineage/SKILL.md \
      /opt/archon/datahub-skills/skills/datahub-quality/SKILL.md \
      /opt/archon/datahub-skills/skills/datahub-enrich/SKILL.md \
      /opt/archon/datahub-skills/skills/using-datahub/SKILL.md \
      /opt/archon/contrib/datahub-audit/SKILL.md
CMD ["handlers.read_handler"]

FROM runtime AS test
ENV PYTHONPATH=/var/task:/opt/archon/test/.venv/lib/python3.12/site-packages
COPY --from=test-dependencies /build/.venv /opt/archon/test/.venv
COPY services/datahub-cloud-runtime/tests /opt/archon/cloud-runtime-tests
COPY tests/pipeline/datahub_cloud_runtime_image_contracts_test.py /opt/archon/repo/tests/pipeline/datahub_cloud_runtime_image_contracts_test.py
COPY .github/workflows/datahub-cloud-runtime-image.yml /opt/archon/repo/.github/workflows/datahub-cloud-runtime-image.yml
COPY .github/locks/datahub-cloud-runtime-image.json /opt/archon/repo/.github/locks/datahub-cloud-runtime-image.json
COPY services/datahub-cloud-runtime/Dockerfile /opt/archon/repo/services/datahub-cloud-runtime/Dockerfile
ENTRYPOINT ["/opt/archon/test/.venv/bin/python", "-m", "pytest"]
CMD ["-q", "/opt/archon/cloud-runtime-tests", "/opt/archon/repo/tests/pipeline/datahub_cloud_runtime_image_contracts_test.py"]
