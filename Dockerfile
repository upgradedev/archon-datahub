# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts

FROM dependencies AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM ${NODE_IMAGE} AS production-dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

FROM ${NODE_IMAGE} AS runtime
ARG ARCHON_RELEASE_SHA=dev
ENV NODE_ENV=production
ENV PORT=8080
ENV ARCHON_RELEASE_SHA=${ARCHON_RELEASE_SHA}
LABEL org.opencontainers.image.source="https://github.com/upgradedev/archon-datahub"
LABEL org.opencontainers.image.revision="${ARCHON_RELEASE_SHA}"
WORKDIR /app
COPY --from=production-dependencies --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json LICENSE NOTICE.md ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/http/server.js"]
