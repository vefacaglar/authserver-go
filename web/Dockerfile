# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src
RUN pnpm run build

FROM caddy:2-alpine
# Port 8080 needs no privileged-port capability. Remove the file capability
# inherited from Caddy so it can run with Compose's cap_drop: [ALL].
RUN setcap -r /usr/bin/caddy \
    && addgroup -S -g 10001 web \
    && adduser -S -D -H -u 10001 -G web web
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
# Caddy's state (autosave, storage) goes under /tmp, the only writable
# path in the read-only production container.
ENV XDG_CONFIG_HOME=/tmp/caddy/config XDG_DATA_HOME=/tmp/caddy/data
USER 10001:10001
EXPOSE 8080
