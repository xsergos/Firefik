# Firefik — Operations Runbook

## Deployment

Required environment:

- **`FIREFIK_API_TOKEN`** — bearer token for the HTTP API. 32+ random bytes.
  Set via `FIREFIK_API_TOKEN_FILE` for Docker secrets / Vault Agent. Both
  the backend and frontend containers must see the same value.
- **`FIREFIK_METRICS_TOKEN`** — optional; dedicated scrape scope.
- **`FIREFIK_ALLOWED_ORIGINS`** — comma-separated list for the WS check
  and CORS (when the UI is served from a different hostname).
- **`FIREFIK_ENABLE_IPV6`** — set `true` only when the host has a working
  IPv6 stack. Firefik fails-closed on IPv6 errors if enabled.
- **`FIREFIK_USE_GEOIP_DB`** / **`FIREFIK_GEOIP_DB_PATH`** — GeoIP
  features. When on, any `geoblock`/`geoallow` label with an unresolvable
  DB state causes the rule-set to refuse to apply (fail-closed).
- **`FIREFIK_GEOIP_SOURCE`** — download source for the auto-updater.
  Default `p3terx` mirrors the MaxMind GeoLite2-Country database via the
  [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) GitHub
  release — no registration, no license key. Use `maxmind` (requires
  `FIREFIK_GEOIP_LICENSE_KEY_FILE`) or `url` (+ `FIREFIK_GEOIP_DOWNLOAD_URL`)
  for the official endpoint or a self-hosted mirror.
- **`FIREFIK_SOCKET_GROUP`** — numeric GID or name. Recommended for
  deployments where Caddy runs as a non-root user.

Compose bring-up:

```bash
export FIREFIK_API_TOKEN=$(openssl rand -hex 32)
docker compose up -d
```

For blue/green or multi-instance deploys, set `STACK_PREFIX=firefik-v2`.

## Health endpoints

| Endpoint  | Auth | Intended probe                                             |
|-----------|------|------------------------------------------------------------|
| `/health` | none | Legacy alias, always 200 if process is alive.              |
| `/live`   | none | Liveness — identical to /health; used by compose.          |
| `/ready`  | none | Readiness — 200 only if Docker daemon responds within 2s.  |

Docker Compose healthchecks are bundled. If deploying to Kubernetes, map
`/live` → livenessProbe and `/ready` → readinessProbe.

## Metrics

Prometheus endpoint is `/metrics`. All labels are low-cardinality
(bounded by rule-set names and container short IDs). Required
authentication via `Authorization: Bearer $FIREFIK_METRICS_TOKEN`
(or API token if the metrics token is unset).

Key metrics:

- `firefik_engine_reconcile_total`
- `firefik_engine_reconcile_errors_total`
- `firefik_engine_reconcile_duration_seconds`
- `firefik_engine_apply_duration_seconds{result}`
- `firefik_engine_apply_errors_total{phase}`
- `firefik_engine_orphans_cleaned_total`
- `firefik_engine_rehydrated_chains`
- `firefik_logstream_dropped_total`

## Tracing

OpenTelemetry is disabled by default. Enable by exporting:

| Env | Default | Meaning |
|---|---|---|
| `FIREFIK_OTEL_ENABLED` | `false` | Master switch |
| `FIREFIK_OTEL_ENDPOINT` | `localhost:4317` (grpc) / `localhost:4318` (http) | OTLP collector |
| `FIREFIK_OTEL_PROTOCOL` | `grpc` | `grpc` or `http/protobuf` |
| `FIREFIK_OTEL_SAMPLE_RATIO` | `1.0` | `[0.0, 1.0]` |
| `FIREFIK_OTEL_SERVICE_NAME` | `firefik` | Service name for spans |

Recommended sampling by environment:

- **dev / staging**: `1.0` (capture everything — volumes are low).
- **small prod (<100 containers)**: `0.5`.
- **large prod**: `0.05`–`0.1`, let the collector tail-sample errors via
  `firefik_engine_apply_errors_total` as trigger.

Spans emitted today: `engine.Reconcile`, `engine.ApplyContainer`, and HTTP
routes via `otelgin.Middleware`. Trace context propagates through the
`X-Request-ID` header set by the request-logger middleware.

### Troubleshooting spans not arriving

If `FIREFIK_OTEL_ENABLED=true` but the collector shows no firefik spans:

1. **Confirm init succeeded.** Startup logs an `opentelemetry enabled`
   line with endpoint, protocol, and sample_ratio. No such line →
   `FIREFIK_OTEL_ENABLED` did not evaluate true (accepted values are
   `true`, `1`, `yes` — case sensitive).
2. **Validate the sample ratio.** A `Warn("invalid FIREFIK_OTEL_SAMPLE_RATIO …")`
   means the env value was rejected and firefik is sampling 1.0 even if
   you asked for less. Set the env to a value in `[0.0, 1.0]`.
3. **Check the endpoint.** Defaults are `localhost:4317` for gRPC,
   `localhost:4318` for `http/protobuf`. Flipping protocol without a
   matching endpoint override is the most common misconfig. Explicit
   override: `FIREFIK_OTEL_ENDPOINT=otel-collector.observability:4317`.
4. **Reachability.** From the firefik container:
   `curl -v telnet://$FIREFIK_OTEL_ENDPOINT` (or `grpcurl`). A blocked
   NetworkPolicy is the #2 cause.
5. **Parent context.** The request-logger middleware sets
   `X-Request-ID`; if your collector groups by trace, confirm your
   ingress doesn't strip it. Absence doesn't drop spans, but hides the
   HTTP → engine correlation.
6. **Downsampled into oblivion.** Large-prod deployments with
   `FIREFIK_OTEL_SAMPLE_RATIO=0.05` can exhibit "nothing arrived in
   5 minutes" even when healthy. Send a synthetic apply
   (`curl -X POST /api/containers/$ID/apply`) with
   `X-Request-ID: probe-$(date +%s)` and check the collector for that
   exact ID — if it's absent, the pipeline is broken; if present, you
   are merely below the sampling floor.

## Audit log forwarding

`audit.Logger` always writes structured JSON to stdout via slog. When
`FIREFIK_AUDIT_SINK` is set, events are **additionally** forwarded to an
external sink for SIEM ingestion:

| Sink | Env |
|---|---|
| `json-file` | `FIREFIK_AUDIT_SINK=json-file FIREFIK_AUDIT_SINK_PATH=/var/log/firefik/audit.jsonl` |
| `cef-file`  | `FIREFIK_AUDIT_SINK=cef-file  FIREFIK_AUDIT_SINK_PATH=/var/log/firefik/audit.cef`   |

Both sinks open at mode `0640`. Path of `-` or empty means stdout
(useful when shipping via `docker logs` to a log aggregator).

### Rotation

By default firefik rotates audit files itself. You do **not** need
`logrotate` for a working deployment:

| Env | Default | Purpose |
|---|---|---|
| `FIREFIK_AUDIT_SINK_MAX_SIZE_MB`  | `100`  | Rotate when the active file reaches this size. `0` disables built-in rotation entirely (legacy append-only mode — use when an external rotator owns the path). |
| `FIREFIK_AUDIT_SINK_MAX_BACKUPS`  | `5`    | Keep at most this many rotated files. |
| `FIREFIK_AUDIT_SINK_MAX_AGE_DAYS` | `30`   | Drop rotated files older than this. `0` = unlimited. |
| `FIREFIK_AUDIT_SINK_COMPRESS`     | `true` | gzip rotated backups. |

Rotated files are named `<path>-<timestamp>.gz` next to the live file.
The same rotation policy is applied to every file sink when
`FIREFIK_AUDIT_SINK` is a comma-list (e.g. `json-file,cef-file`).

To disable built-in rotation and rely on an external `logrotate
copytruncate` instead, set `FIREFIK_AUDIT_SINK_MAX_SIZE_MB=0`.

Event shape (JSON): see `backend/internal/audit/sink.go#Event`. CEF
extension fields: `src` (container IPs), `cs1` (source), `cs2` (container
ID), `cs3` (container name), `cs4` (default policy), `cn1` (rule-set
count), `rt` (ISO-8601 timestamp).

## GeoIP maintenance

When `FIREFIK_USE_GEOIP_DB=true` and `FIREFIK_GEOIP_DB_AUTOUPDATE=true`,
firefik downloads the GeoLite2-Country database on startup (if missing)
and refreshes it on the configured cron.

| `FIREFIK_GEOIP_SOURCE` | Endpoint | Auth | Payload |
|---|---|---|---|
| `p3terx` **(default)** | `github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb` | none | raw `.mmdb` |
| `maxmind` | `download.maxmind.com/app/geoip_download` | license key (`FIREFIK_GEOIP_LICENSE_KEY_FILE`) | `.tar.gz` |
| `url` | `$FIREFIK_GEOIP_DOWNLOAD_URL` | operator-defined | `.tar.gz`/`.tgz` → extracted, anything else → treated as raw `.mmdb` |

The updater caches the upstream `ETag` alongside the database
(`${GEOIP_DB_PATH}.etag`) and sends `If-None-Match` on every subsequent
fetch, so scheduled runs only rewrite the file when the upstream release
actually rotated.

**Troubleshooting:**

- `GeoIP auto-update disabled` in logs → `validate()` rejected the
  configuration. `maxmind` missing key, `url` missing
  `FIREFIK_GEOIP_DOWNLOAD_URL`, or unknown source value.
- `download GeoIP: HTTP 403` → GitHub rate-limit (anonymous UA blocked)
  or license key revoked. Retry with a different source, or set
  `FIREFIK_GEOIP_DOWNLOAD_URL` to an internal mirror.
- Air-gapped environments: host `GeoLite2-Country.mmdb` on an internal
  HTTPS endpoint and set `FIREFIK_GEOIP_SOURCE=url`
  `FIREFIK_GEOIP_DOWNLOAD_URL=https://internal.example.com/.../GeoLite2-Country.mmdb`.

## Alerts

See `alerts/firefik.yml` for the reference rule bundle. Tune severity
labels to your pager.

## Incident response

1. **API returns 503 / readiness failing** — Docker daemon is
   unreachable. `docker info` from the host. Restart `firefik-back`
   only if the daemon is healthy; firefik will auto-reconnect events
   via exponential backoff.
2. **Rules not applied after deploy** — check
   `firefik_engine_apply_errors_total`. Investigate the audit log;
   search for `"action":"apply"` and `"error"`. If IPv6 rules are the
   cause, the whole container is now unprotected (fail-closed) —
   intentional.
3. **Kernel counters climbing but firefik has no history** — inspect
   live state with the admin CLI:

   ```bash
   firefik-admin inventory --backend auto
   firefik-admin status --backend auto
   firefik-admin check --backend auto --output json | jq .
   ```

   `check` returns exit code 2 if it detects drift (missing base chain,
   missing parent jump) — wire it into your monitoring cron:

   ```bash
   firefik-admin check --backend auto || alert-oncall "firefik drift"
   ```

   If orphan chains remain after a cutover, drain or reap them. Use
   `drain` for an ordered wind-down with progress output:

   ```bash
   firefik-admin drain --chain FIREFIK-v1 --confirm
   # or, for a blue/green rollback where the parent jump must stay:
   firefik-admin drain --chain FIREFIK-v1 --keep-parent-jump --confirm
   ```

   Use `reap` for scoped blue/green removal by suffix (works on both
   iptables and nftables; honours `--dry-run`):

   ```bash
   firefik-admin reap --chain FIREFIK --suffix v1 --dry-run
   firefik-admin reap --chain FIREFIK --suffix v1
   ```

   The same effect runs automatically on next firefik startup if you
   set `FIREFIK_CLEANUP_OLD_SUFFIXES=v1` — now wired on nftables as
   well (previously iptables-only).

   Use `force-reset` for the nuclear option (removes container chains
   only; does not tear down the base chain or parent jump):

   ```bash
   firefik-admin force-reset --backend nftables --chain FIREFIK-v1 --confirm
   ```

   When the main service is down but the Docker daemon is up and you
   need rules applied urgently, run a local Reconcile:

   ```bash
   firefik-admin reconcile --backend auto
   ```

   `firefik-admin` is shipped as a separate binary so it works when the
   main service is down.
4. **Socket permission denied** — check `ls -la /run/firefik/api.sock`.
   Mode must be `0660`, group must include the Caddy user. Set
   `FIREFIK_SOCKET_GROUP` if rebuilding.
5. **Sudden drop in audit events** — check
   `firefik_logstream_dropped_total` and WS client control messages.
   A slow consumer is dropping packets; the hub also emits a
   `{"event":"dropped"}` message to clients.

## Grafana dashboard

A ready-to-import overview dashboard lives in
[docs/dashboards/firefik-overview.json](dashboards/firefik-overview.json).

```
Grafana → + → Import → Upload JSON file → choose your Prometheus data source
```

Panels cover: reconcile rate & duration, apply errors by phase,
apply-duration p95/p99 by result, drift events by type, orphan counter,
rehydrated-chains gauge, legacy cleanup errors, and log-stream drop
rate. Use alongside the
Prometheus alert rules in [alerts/firefik.yml](../alerts/firefik.yml):
an alert fires → operator opens the dashboard to see the surrounding
context.

## Running integration tests

The integration suite in `backend/tests/integration/` exercises the
real kernel (iptables-nft and nftables) instead of mocks. It is
gated behind the `integration` build tag and requires `CAP_NET_ADMIN`.

Prerequisites:

- Linux host (kernel with nf_tables). Ubuntu 22.04+ or Debian 12+
  works out of the box.
- `iptables` and `nftables` userland installed.
- Root or `sudo`.

Run locally:

```bash
cd backend
sudo -E go test -tags=integration -timeout=5m ./tests/integration/...
```

Each test runs under a unique chain prefix (`FIREFIKT<ns><n>`) so
parallel invocations don't collide with each other or with a live
firefik. Every test registers a `t.Cleanup` that tears down its own
kernel state even on failure.

Windows / macOS developers: the package is tagged `//go:build
integration`, so normal `go test ./...` runs skip it. CI runs it on
`ubuntu-24.04` (see the `integration` job in
[.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Rollback

Routine rollback flow:

```bash
git revert <commit-or-tag>
docker compose build
docker compose up -d backend frontend
```

Before rolling back any change that touches the firewall engine
(`backend/internal/rules/`), snapshot the current kernel state so a
re-apply or manual surgery is possible:

```bash
iptables-save > /tmp/pre-rollback-iptables.rules
nft list ruleset > /tmp/pre-rollback-nft.rules
```

If a revert leaves orphan chains (unlikely — rehydrate covers this),
manual cleanup:

```bash
iptables -S | awk '/-N FIREFIK-/ {print $2}' | xargs -r -n1 iptables -X
```

## Capacity planning

- `firefik_engine_reconcile_duration_seconds` p95 should stay under
  500ms for hosts with <50 containers. Beyond 500ms, enable the
  `dockerproxy` profile to reduce Docker API overhead.
- Log stream hub has a 256-message global broadcast buffer and a
  64-message per-client buffer. Consumers that can't keep up see
  `{"event":"dropped","count":N}` control messages.
