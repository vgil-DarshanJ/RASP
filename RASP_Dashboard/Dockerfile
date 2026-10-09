# Dashboard for production: static export (NEXT_OUTPUT=export) served by
# Caddy, which also terminates HTTPS and proxies /v1/* and /healthz to the
# backend (BE/deploy/Caddyfile, mounted by BE/deploy/docker-compose.prod.yml).
# PUBLIC_ORIGIN is the https:// origin users open (the API is on the same one).
FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG PUBLIC_ORIGIN
ENV NEXT_PUBLIC_API_BASE_URL=${PUBLIC_ORIGIN} NEXT_OUTPUT=export NEXT_TELEMETRY_DISABLED=1
RUN test -n "$PUBLIC_ORIGIN" || (echo "PUBLIC_ORIGIN build argument is required" && exit 1)
RUN npx next build

FROM caddy:2-alpine
COPY --from=build /app/out /srv
