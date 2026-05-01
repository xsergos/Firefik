# Firefik — Upgrade guide

How to move between 0.x releases without dropping packets or
corrupting kernel state.

> Firefik is pre-release (0.x). Breaking env-var renames, chain-name
> changes, and control-plane schema migrations are allowed between
> minors. **Read the release notes before upgrading.** Once v1.0
> ships, standard SemVer rules apply.

---

## Pre-flight (any upgrade)

1. **Back up kernel chains** (in case of rollback):
   ```bash
   iptables-save > /tmp/iptables.pre-upgrade.dump
   nft list ruleset > /tmp/nftables.pre-upgrade.dump
   ```

2. **Snapshot control-plane state** (if running firefik-server):
   ```bash
   firefik-server backup --out /tmp/cp-pre-upgrade.tar   # v0.11+
   # Before v0.11:
   systemctl stop firefik-server
   tar czf /tmp/cp-pre-upgrade.tar.gz /var/lib/firefik-server/
   systemctl start firefik-server
   ```

3. **Verify no drift** before upgrading:
   ```bash
   firefik-admin check --output json | jq .drift
   # Expect: false
   ```

4. **Read the release notes** for the target version on the
   GitHub Releases page.

---

## Zero-downtime upgrade pattern (blue/green)

Use `FIREFIK_CHAIN_SUFFIX` to run old + new in parallel, then reap.

```bash
# Current production runs with suffix='' (empty).
# Start new version with suffix=v2:
docker run -d --name firefik-v2 \
  -e FIREFIK_CHAIN_SUFFIX=v2 \
  -e FIREFIK_CLEANUP_OLD_SUFFIXES= \
  ghcr.io/.../firefik-back:v0.NEW

# Verify v2 is installing its chains (suffix FIREFIK-v2):
iptables -S | grep FIREFIK-v2 | head

# Swap parent-chain jump atomically:
iptables -D DOCKER-USER -j FIREFIK       # point away from old
iptables -I DOCKER-USER 1 -j FIREFIK-v2  # point at new

# Remove old version after 5-min soak:
docker stop firefik && docker rm firefik
firefik-admin reap --suffix=""   # removes old FIREFIK chain-tree
```

Roll back: reverse the `iptables -D` / `-I` swap, then `docker start
firefik`. No packet loss.

---

## Per-version migration notes

### v0.12.0 → v0.13.0

**Breaking:** _(none — v0.13 is additive.)_

**Additive env-vars:**

- `FIREFIK_OTEL_LOGS_ENABLED`, `FIREFIK_OTEL_LOGS_ENDPOINT`,
  `FIREFIK_OTEL_LOGS_PROTOCOL`, `FIREFIK_OTEL_LOGS_TIMEOUT` — OTLP
  logs export. When enabled, audit events fan out as OTel log records
  alongside existing sinks. Off by default.
- `FIREFIK_WEBHOOK_*` (existing on agent) is now read by **firefik-
  server** as well. When set, server-side audit events (initially
  the three `policy_approval_*` actions) are forwarded to the
  configured webhook with optional HMAC signing.

**New audit events** (emitted by control-plane, NOT a breaking change
for existing webhook consumers since they're only forwarded when the
URL is configured):

- `policy_approval_requested` — operator A creates a pending approval.
- `policy_approval_approved` — operator B (different fingerprint) approves.
- `policy_approval_rejected` — operator B rejects.

Each event metadata: `approval_id`, `policy_name`, `requester` /
`approver`, fingerprints. Reject also carries `comment`.

**CI gate change:** backend `make cover-gate` threshold raised from
75% to 76%. No action needed unless you fork CI; coverage rose from
76.8% to 78.4%.

**Upgrade steps:**

1. Pre-flight (above).
2. Pull `ghcr.io/.../firefik-back:v0.13.0` and
   `ghcr.io/.../firefik-server:v0.13.0`.
3. Blue/green agent upgrade with `FIREFIK_CHAIN_SUFFIX=v013`.
4. Upgrade firefik-server (no schema migration needed in v0.13).
5. (Optional) Set `FIREFIK_WEBHOOK_URL` on firefik-server to receive
   approval events; verify with a manual approve flow.
6. (Optional) Set `FIREFIK_OTEL_LOGS_ENABLED=true` to push audit
   events as OTel logs.

### v0.11.0 → v0.12.0

**Breaking:** _(none — v0.12 is additive.)_

**Additive env-vars:**

- `FIREFIK_OTEL_METRICS_ENABLED`, `FIREFIK_OTEL_METRICS_ENDPOINT`,
  `FIREFIK_OTEL_METRICS_PROTOCOL`, `FIREFIK_OTEL_METRICS_INTERVAL` —
  OTLP metrics push via Prometheus bridge. Off by default.
- `FIREFIK_CONTROL_PLANE_HTTP` — required (on agents) for the new
  Templates / Approvals UI pages to work. Empty = pages return empty.
- `FIREFIK_TEMPLATE_SYNC_INTERVAL` (default 60s) and
  `FIREFIK_TEMPLATE_CACHE_DIR` (default `/var/lib/firefik/templates`)
  — fleet-wide template syncer.

**New control-plane endpoints:**

- `GET/POST /v1/templates`, `GET /v1/templates/{name}` — fleet-wide
  policy templates.
- `GET/POST /v1/approvals`, `GET /v1/approvals/{id}`,
  `POST /v1/approvals/{id}/approve|reject` — 4-eyes policy gate. Self-
  approve is rejected at the store level using `requester_fingerprint`
  (sha256 of bearer token).

**Schema:** new sqlite migration `0002_templates_approvals.sql` (tables
`policy_templates` and `pending_approvals`). Runs on first start.
Forward-only.

**New images:** `linux/arm64` is now published alongside `linux/amd64`.
No action required; pull works the same. Verify with
`docker manifest inspect ghcr.io/.../firefik-back:v0.12.0`.

**CI gates:** `make cover-gate` (backend ≥ 80%) and vitest thresholds
(frontend ≥ 80%) are now CI-required. Fork builds may need to update
their PR template.

**Upgrade steps:**

1. Pre-flight (above).
2. Pull `ghcr.io/.../firefik-back:v0.12.0` and
   `ghcr.io/.../firefik-server:v0.12.0`.
3. Blue/green agent upgrade with `FIREFIK_CHAIN_SUFFIX=v012`.
4. Upgrade firefik-server (sqlite migration runs automatically).
5. Verify control-plane HTTP routes:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://firefik-server:8443/v1/templates
   ```
6. (Optional) Set `FIREFIK_CONTROL_PLANE_HTTP=https://firefik-server:8443`
   on agents to enable the Templates / Approvals UI pages.

### v0.10.0 → v0.11.0

**Breaking:** _(none planned — this release is quality-focused.)_

**Additive env-vars:**

- `FIREFIK_WEBHOOK_URL`, `FIREFIK_WEBHOOK_EVENTS`,
  `FIREFIK_WEBHOOK_SECRET` — new webhook sink (F1). Default off.

**New metrics:**

- `firefik_controlplane_agent_cert_days_until_expiry{agent_id,
  spiffe_id}` — add dashboard panel before wide rollout.

**New subcommands:**

- `firefik-server backup` / `restore` — add to your DR runbook.
- `firefik-admin metrics-audit` — optional weekly check.

**Schema:** control-plane sqlite migration runs on first start.
Forward-only. Restore from v0.10.0 backup is supported; restore from
v0.11.0 backup to a v0.10.0 server is **not**.

**Upgrade steps:**

1. Pre-flight (above).
2. Pull `ghcr.io/.../firefik-back:v0.11.0` and
   `firefik-server:v0.11.0`.
3. Blue/green agent upgrade with `FIREFIK_CHAIN_SUFFIX=v011`.
4. Upgrade `firefik-server` in place (short downtime OK; agents
   reconnect with exponential backoff).
5. Verify all agents reconnected:
   ```bash
   curl https://firefik-server:8443/metrics | grep firefik_controlplane_grpc_agents_connected
   ```

### Pre-v0.10.0 → v0.10.0

v0.10.0 is the first shipped release. Installations before this point
were pre-release snapshots; upgrade path is not supported. Start fresh.

---

## What carries over, what doesn't

**Carries over across versions:**

- Container labels (`firefik.*`). The label schema is stable-forward;
  new fields are additive.
- Kernel chains (with matching `FIREFIK_CHAIN_SUFFIX` on both sides).
- Policy DSL files in `FIREFIK_POLICIES_DIR` (v0.10.0 onwards).
- Audit sink paths + rotated-file archive.
- Control-plane sqlite (forward-only migrations since v0.10.0).

**Resets on upgrade:**

- In-memory rate-limiter state (token buckets restart).
- WebSocket log-stream subscribers (clients reconnect).
- Metrics counters (they always reset on process restart — this is
  standard Prometheus behaviour).

**Can diverge and require manual action:**

- Env-var renames (version-specific; see notes above).
- mTLS cert validity — renew with `firefik-admin enroll --renew`
  before upgrade if expiry < 72h.

---

## Rolling back

If upgrade goes wrong:

1. **Agent**: redeploy previous image with the same `CHAIN_SUFFIX` as
   before; old chains still in kernel if you haven't reaped yet.
2. **Control-plane**: stop new server, restore from pre-upgrade
   snapshot, start old version. Agents auto-reconnect.
3. **Kernel state**: only if chains are corrupted,
   `firefik-admin drain --keep-parent-jump --confirm` then reapply
   from labels at old version.
4. **Never** run `iptables-restore` from the pre-upgrade dump
   directly — it can race with firefik's reconciler. Dump is a
   human-readable reference for what *was* installed, not an
   executable rollback artifact.

---

## Post-upgrade verification

```bash
firefik-admin doctor --output json
firefik-admin check --output json | jq .drift        # false
firefik-admin diff --api http://127.0.0.1/api/rules  # empty

# Control-plane:
curl -s https://firefik-server:8443/healthz
# Expect 200.

# Fleet health:
curl -s .../metrics | grep firefik_controlplane_grpc_agents_connected
# Expect: equal to your fleet size.
```

All four green = upgrade done. File anything else.
