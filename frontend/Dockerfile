# syntax=docker/dockerfile:1.7

FROM node:25.9.0-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=optional

COPY . .
RUN npm run build

FROM caddy:2-alpine
RUN apk add --no-cache wget ca-certificates

COPY --from=build /app/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --timeout=2 -O /dev/null http://127.0.0.1:80/health || exit 1

EXPOSE 80 443
