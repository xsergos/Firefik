# Firefik — Troubleshooting

Decision-tree for incident response. Start with the symptom headline,
follow branches until you reach **→ FIX**.

For background, cross-references:

- [runbook.md](runbook.md) — standard runbooks (not incident).
- [operations.md](operations.md) — ops narrative.
- [metrics-guide.md](metrics-guide.md) — what each metric means.

---

## Symptom: API returns 503 / times out

```
Does `firefik-admin doctor --output json` pass all checks?
├── No → Check which check failed:
│   ├── docker-socket → Docker daemon dead / socket permissions.
│   │   → FIX: `systemctl status docker` and verify socket perms.
│   ├── kernel-module → ip_tables / nf_tables not loaded.
│   │   → FIX: `modprobe ip_tables nf_tables`; add to modules-load.d.
│   ├── capabilities → container missing NET_ADMIN / NET_RAW.
│   │   → FIX: redeploy with `--cap-add NET_ADMIN --cap-add NET_RAW`.
│   ├── audit-path → FIREFIK_AUDIT_SINK_PATH not writable.
│   │   → FIX: chmod / chown the target directory.
│   └── geoip-db-age → mmdb older than max-age.
│       → FIX: trigger updater; run `firefik-admin doctor` again.
│
└── Yes → Check `journalctl -u firefik-back -n 200` for panics.
    ├── Panic in handler → File issue with stack trace.
    └── Healthy logs, still 503 → Rate-limit exhaustion?
        → Check `/metrics` for high 429 count; raise
          FIREFIK_RATE_LIMIT_RPS or investigate client.
```

---

## Symptom: rules are not applied to a container

```
Does the container have `firefik.enable=true` label?
├── No → FIX: add label, redeploy container.
└── Yes → Does `firefik-admin inventory` show the container's chain?
    ├── No → Docker event missed.
    │   → FIX: `firefik-admin reconcile` (force full reconcile).
    │   → If recurring: check `firefik_docker_events_total` — if
    │     zero rate, Docker socket broken.
    └── Yes → But no kernel rules? Check drift:
        `firefik-admin diff`
        ├── Shows missing rules → apply-error during last reconcile.
        │   → Check audit sink for `rule_apply_failed` event; look
        │     at `phase` label — determines root cause (labels /
        │     backend / geoip / kernel_emit).
        └── Shows extra rules → manual kernel edit?
            → FIX: `firefik-admin reconcile` will remove extras.
```

---

## Symptom: socket permission denied

```
curl --unix-socket /run/firefik/api.sock http://localhost/api/containers
Returns: curl: (7) Couldn't connect to server

Is the socket file present?
├── No → firefik-back not running or LISTEN_ADDR wrong.
│   → FIX: `systemctl status firefik-back`;
│          verify FIREFIK_LISTEN_ADDR.
└── Yes → Check ownership:
    ls -la /run/firefik/api.sock
    ├── Wrong owner/group → FIREFIK_SOCKET_GROUP mismatch.
    │   → FIX: set env to a group your user belongs to, restart.
    ├── Correct owner, still 403 → peer-cred UID allowlist.
    │   → Check FIREFIK_ALLOWED_UIDS; add your UID or unset for
    │     token-only auth.
    └── Correct, 401 → Token mismatch.
        → Verify FIREFIK_API_TOKEN_FILE content.
```

---

## Symptom: control-plane agent won't connect

```
Agent logs `controlplane: mtls handshake failed`
├── Check `firefik_controlplane_mtls_rejected_total{reason=...}` on
│   server side:
│   ├── reason=trust_domain → Wrong SPIFFE trust domain.
│   │   → FIX: re-enroll with correct
│   │     FIREFIK_CP_TRUST_DOMAIN on server, pass --trust-domain
│   │     in `firefik-admin enroll`.
│   ├── reason=expired → Client cert past expiry.
│   │   → FIX: `firefik-admin enroll --renew`.
│   ├── reason=unknown_ca → Server-side trust bundle wrong.
│   │   → FIX: verify server --client-ca points at the issuing CA.
│   └── reason=no_uri_san → Cert lacks SPIFFE URI SAN.
│       → Probably issued by non-firefik CA; re-enroll.
│
└── If no mtls_rejected growth → networking issue.
    → Test: `openssl s_client -connect firefik-server:8444 -tls1_3`
    → Expect: successful handshake or "certificate verify failed".
    → "connection refused" → firefik-server not listening or
      firewall blocks port.
```

---

## Symptom: kernel drift detected

```
firefik-admin check reports drift: true

What does `firefik-admin diff` show?
├── Missing chains → someone (or a reboot) flushed iptables.
│   → FIX: `firefik-admin reconcile`
│     Re-applies everything from labels.
├── Extra rules → manual kernel edit or different firefik instance.
│   → INVESTIGATE first (shell history, audit log) before removing.
│   → FIX: if confirmed stray, `firefik-admin reconcile`
│     removes un-owned rules within firefik chains.
└── Wrong parent-chain jump → iptables-save / restore from wrong time.
    → FIX: manually re-add parent jump, then reconcile.
```

**Never** just `iptables -F FIREFIK-<id>` — that creates drift without
fixing root cause. Reconcile via firefik.

---

## Symptom: high memory / OOM on agent

```
Is `firefik_logstream_dropped_total` rate climbing?
├── Yes → Slow WebSocket subscriber.
│   → FIX: identify subscribers via active connections; lower
│     FIREFIK_WS_MAX_SUBSCRIBERS or cut slow client.
│
Else: is container count extreme (500+)?
├── Yes → Known scale limit.
│   → FIX: shard by host, or wait for scale improvements.
│
Else: check `firefik_rules_active` cardinality:
├── Container-label explosion (e.g. per-request container creation) →
│   → Address at orchestrator level; firefik isn't the right place
│     to filter this.
```

---

## Symptom: audit events disappearing

```
Is `FIREFIK_AUDIT_SINK` set?
├── No → stdout-only; events go to agent stderr only.
│   → FIX: set to `file` or `remote` for durability.
└── Yes → Check the sink:
    ├── file → Does FIREFIK_AUDIT_SINK_PATH exist and grow?
    │   ├── No growth → sink not configured in code path.
    │   │   → Check agent logs for "audit sink: ..." warnings.
    │   └── Grew but was rotated → check
    │       FIREFIK_AUDIT_SINK_MAX_* values; lumberjack archives
    │       are `<path>.1.gz` / `.2.gz` etc.
    │       → If retention truncated too aggressively, raise
    │         MAX_AGE_DAYS.
    ├── remote → Is endpoint reachable?
    │   → `curl -v $FIREFIK_AUDIT_SINK_ENDPOINT`
    │   → On 4xx/5xx: fix endpoint side; firefik drops events
    │     after retry-exhaustion (bounded queue).
    └── cef → Same as file; verify path + mode.
```

---

## Symptom: GeoIP rule says "CN" but traffic from Russia matches

```
Check GeoIP DB age:
firefik-admin doctor | grep geoip
├── DB is old → Auto-updater didn't run.
│   → FIX: check FIREFIK_GEOIP_DB_AUTOUPDATE=true and cron schedule;
│     trigger manually: delete DB file and restart (updater refetches).
└── DB fresh → MaxMind attribution error (edge case on border IPs).
    → Not a firefik bug. Add IP to policy allow/deny list directly.
```

---

## Still stuck?

Capture:

```bash
firefik-admin doctor --output json > /tmp/firefik-doctor.json
firefik-admin check --output json > /tmp/firefik-check.json
firefik-admin diff > /tmp/firefik-diff.txt
iptables-save > /tmp/iptables.dump
nft list ruleset > /tmp/nftables.dump 2>/dev/null
journalctl -u firefik-back -n 500 > /tmp/firefik.log
```

Open a GitHub issue with all five attached and a one-paragraph
description of the symptom.
