# Control plane (gRPC protocol reference)

Firefik's central control plane is a **gRPC-only** service.

## Topology

```
  ┌──────────────────┐       gRPC bidi stream (TLS 1.3 + mTLS)
  │   firefik-back   │ ───────────────────────────────────────▶  ┌────────────────┐
  │     (agent)      │                                           │ firefik-server │
  └──────────────────┘       HTTP (/healthz + /v1/enroll)        │ (control plane)│
                      ───────────────────────────────────────▶  └────────────────┘
```

- gRPC listener (default `:8444`) — all operational traffic (register,
  stream events, commands, acks).
- HTTP listener (default `:8443`) — bootstrap only. Serves `/healthz`
  and `/v1/enroll` (cert issuance).

## TLS posture

- TLS 1.3, mutual auth. Agents present a client cert signed by the
  control-plane CA.
- The embedded mini-CA (`firefik-server mini-ca`) issues short-lived
  SPIFFE-compatible certs. External CAs (cert-manager, step-ca) are also
  supported via `--client-ca` on the server + `FIREFIK_CONTROL_PLANE_CLIENT_CERT`
  / `_CLIENT_KEY` on the agent.
- Optional: set `FIREFIK_CP_TRUST_DOMAIN=spiffe://<domain>/` on the
  server to reject any peer cert whose URI SAN is not under that trust
  domain. Metric: `firefik_controlplane_mtls_rejected_total{reason}`.

## Bootstrap (mini-CA flow)

1. On the control-plane host:
   ```
   firefik-server mini-ca init --state-dir /var/lib/firefik-server/ca \
                               --trust-domain spiffe://prod.corp/
   ```
   Generates a root + issuing CA under the state dir. Idempotent.
2. Start `firefik-server` — the CA is picked up automatically and the
   `/v1/enroll` endpoint becomes available.
3. On each agent:
   ```
   firefik-admin enroll --control-plane=https://cp.example:8443 \
                        --token=$CP_BOOTSTRAP_TOKEN \
                        --agent-id=host-a \
                        --out=/var/lib/firefik/control-plane
   ```
   Drops `client.crt`, `client.key`, `ca-bundle.pem`. Agent-side env:
   - `FIREFIK_CONTROL_PLANE_GRPC=cp.example:8444`
   - `FIREFIK_CONTROL_PLANE_CA_CERT=/var/lib/firefik/control-plane/ca-bundle.pem`
   - `FIREFIK_CONTROL_PLANE_CLIENT_CERT=/var/lib/firefik/control-plane/client.crt`
   - `FIREFIK_CONTROL_PLANE_CLIENT_KEY=/var/lib/firefik/control-plane/client.key`
4. Rotate near expiry:
   ```
   firefik-admin enroll --renew --renew-window=72h ...
   ```

## Edge enrollment (one-time token)

For Portainer-edge-style self-enrollment without distributing the static
bearer to every host, the panel issues a single-use enrollment token and
the new host exchanges it for a short-lived mTLS cert.

1. Operator opens **Add agent** in the panel (or POSTs
   `/v1/enrollment-tokens` directly):
   ```bash
   curl -fsSL -H "Authorization: Bearer $CP_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"agent_id":"host-prod-01","ttl_seconds":900}' \
        https://cp.example:8443/v1/enrollment-tokens
   # → {"token":"f5a9…","agent_id":"host-prod-01","expires_at":"…","issued_at":"…"}
   ```
2. The panel renders a bash one-liner with the freshly issued token. The
   operator copies it and runs it as root on the new host:
   ```bash
   curl -fsSL "https://cp.example:8443/v1/enroll" \
        -X POST -H 'Content-Type: application/json' \
        -d '{"agent_id":"host-prod-01","enrollment_token":"f5a9…"}' \
        > /tmp/firefik-enroll.json && \
   mkdir -p /etc/firefik && \
   jq -r .cert_pem   /tmp/firefik-enroll.json > /etc/firefik/cert.pem && \
   jq -r .key_pem    /tmp/firefik-enroll.json > /etc/firefik/key.pem  && \
   jq -r .bundle_pem /tmp/firefik-enroll.json > /etc/firefik/bundle.pem && \
   chmod 600 /etc/firefik/key.pem && rm /tmp/firefik-enroll.json
   ```
3. Operator brings up the agent container — env vars point at the freshly
   minted cert/key/bundle. Within ~30s the agent appears in `/v1/agents`
   with status `healthy`.

Token semantics:
- Single-use — the `consumed_at` column is set in the same SQLite tx that
  reads it; concurrent attempts get `409 enrollment token already used`.
- TTL-bounded — expired tokens are rejected with `401 enrollment token
  expired`; expired rows stay in the table for audit.
- `agent_id` is bound at issue time. If the consumer sends a different
  `agent_id` in the enroll body, the request is rejected with `403
  agent_id does not match enrollment token`.
- Issuance and consumption (with consumer IP) are audited
  (`enrollment_token_created`). The `issued_by` column reflects the
  actual operator: SSO-proxy headers (`X-Auth-Subject`,
  `X-Forwarded-User`, `X-Auth-Request-User`, `X-Forwarded-Email`) win,
  otherwise it falls back to `bearerFingerprint(token)@client_ip`
  (first hop of `X-Forwarded-For` or `RemoteAddr`).
- The store has a `RevokeEnrollmentToken` method (sets `consumed_at` so the
  token can no longer be exchanged); no public HTTP endpoint yet — let the
  TTL expire or delete the row out-of-band.

## Self-renewal flow (mTLS-only)

Agent-driven cert rotation that does **not** require an operator bearer
token — the agent presents its current cert via mTLS, generates a CSR
with its existing private key, and the server signs a fresh cert.

```
agent (CertRenewer)                     firefik-server
─────────────────────                   ──────────────
  loop every CERT_RENEW_INTERVAL
    if remaining < CERT_RENEW_BEFORE
      load existing private key
      build CSR  (CN = agent_id, key = existing)
      POST /v1/renew  ── mTLS handshake ──▶
        body = { agent_id, ttl_seconds, csr_pem }
                                              verify peer.SPIFFE → trust_domain
                                              extract agent_id from peer SAN
                                              reject if revoked.json contains serial
                                              reject if remaining > 24h (renewal window)
                                              parse CSR; require pubkey == peer pubkey
                                              ca.IssueFromCSR(csr, agent_id, ttl)
                                              audit "cert_renewed"
      ◀── 200 { cert_pem, bundle_pem, serial, not_after_unix }
      atomic write CertPath (key untouched)
      gRPC client picks up rotated cert at next handshake
      via tls.Config.GetClientCertificate (mtime-cached loader)
```

Key properties:

- **No operator bearer involved.** Privilege-escalation surface (`enroll
  any agent_id`) eliminated — peer cert SAN is the binding identity.
- **Private key never rotates.** Agent reuses its enroll-time ECDSA-P256
  key for every CSR. Less file movement, fewer chances for partial
  rotations to wedge mTLS.
- **Revocation closes the loop.** `firefik-server mini-ca revoke
  --serial <hex>` writes to `<state-dir>/revoked.json`; subsequent
  `/v1/renew` from that cert returns 403 + `cert_renew_rejected`
  audit event. Operators can bind a stolen cert without touching CA keys.
- **Hot-reload, no agent restart.** gRPC client TLS config uses
  `GetClientCertificate` callback that re-reads the cert file when its
  mtime changes; the active gRPC stream stays up, the next handshake
  picks the new cert.
- **`firefik-admin enroll --renew`** remains as an operator-driven
  break-glass path (e.g. when the agent's cert is past expiry and self-
  renewal can no longer authenticate).

## Endpoints (HTTP, bootstrap-only and self-service)

In addition to the operator REST surface below, two unauthenticated-but-
auth-different bootstrap routes:

- `POST /v1/enroll` — bearer or one-time enrollment token; issues both
  cert and key (server keygen).
- `POST /v1/renew` — mTLS only; CSR-based, key stays on agent;
  rejects revoked serials.

## gRPC service surface

Defined in [controlplane.proto](../backend/proto/controlplane/v1/controlplane.proto).

```proto
service ControlPlane {
  rpc Register(RegisterRequest) returns (RegisterAck);
  rpc Stream(stream AgentEvent) returns (stream ServerCommand);
  rpc Ack(CommandAck) returns (AckReply);

  rpc ListTemplates(ListTemplatesRequest) returns (ListTemplatesResponse);
  rpc GetTemplate(GetTemplateRequest) returns (PolicyTemplate);
  rpc PublishTemplate(PublishTemplateRequest) returns (PublishTemplateResponse);
}
```

- **Register** — one-shot on agent startup. Returns heartbeat cadence.
- **Stream** — bidirectional. Agent sends `AgentEvent` (Snapshot /
  Audit / Heartbeat); server pushes `ServerCommand` within
  single-digit ms of enqueue.
- **Ack** — out-of-band ack after stream drop; safe idempotent.
- **ListTemplates / GetTemplate / PublishTemplate** (v0.12+) — fleet-
  wide policy template library. Agent's `TemplateSyncer` pulls every
  `FIREFIK_TEMPLATE_SYNC_INTERVAL` (default 60s).

## HTTP REST surface (operator UI / approval flow)

In addition to the bootstrap `GET /healthz` + `POST /v1/enroll`, the
HTTP listener serves an operator-side REST API once a control-plane
token is set (`--token-file` or `FIREFIK_SERVER_TOKEN`):

| Method + Path | Purpose |
|---|---|
| `GET /v1/templates` | List published templates. |
| `POST /v1/templates` | Publish (insert or version-bump). Body fields auto-fill `publisher = sha256(bearer)[:8]`. |
| `GET /v1/templates/{name}` | Single template, latest version. |
| `GET /v1/approvals?status=pending|approved|rejected` | List pending-approval rows. Empty status = all. |
| `POST /v1/approvals` | Open a pending approval. `requester_fingerprint` always derived from caller's bearer; body field is ignored. |
| `GET /v1/approvals/{id}` | Single approval. |
| `POST /v1/approvals/{id}/approve` | 4-eyes approve. Returns `403 self-approve forbidden` if `approver_fingerprint == requester_fingerprint`; `409 not pending` if status changed. Atomic via `RowsAffected`. |
| `POST /v1/approvals/{id}/reject` | Same guards as approve; body `comment` optional. |
| `GET /v1/agents` | List enrolled agents. Returns `agent_dto[]` with `status: healthy\|stale\|dead\|unknown` based on `last_seen` (thresholds: 90s healthy, 5m stale, dead beyond). |
| `GET /v1/agents/{id}` | Single agent record. |
| `GET /v1/agents/{id}/snapshot` | Latest reported snapshot (containers, firewall_status, default_policy, sources, rule_set_count). Empty `snapshot` field if the agent has not pushed yet. |
| `POST /v1/agents/{id}/commands` | Enqueue a command. Body `{"action": "apply\|disable\|reconcile\|token_rotate", "container_id": "..."}`. `apply`/`disable` require `container_id`; `reconcile`/`token_rotate` are agent-wide. Returns `202 {"id","agent_id","action"}`. Audited as `agent_command`. |
| `GET /v1/agents/{id}/logs` | **WebSocket** — live tail of nflog forwarded by the agent. `Authorization: Bearer …` required on the upgrade request. Server sends `LogLine` JSON (`agent`, `at`, `level`, `source`, `line`, `fields`) and PINGs every 30s. |
| `GET /v1/enrollment-tokens` | List active (unconsumed) enrollment tokens. `?include_used=1` includes consumed/revoked. |
| `POST /v1/enrollment-tokens` | Issue a one-time enrollment token. Body `{"agent_id": "host-prod-01", "ttl_seconds": 900}`. `agent_id` must match `[a-z0-9-]{3,63}`; TTL defaults to 15 min, capped at 24 h. Returns `201 {"token","agent_id","expires_at","issued_at"}`. The token is single-use — `POST /v1/enroll` consumes it atomically. |

All routes require `Authorization: Bearer <token>`. The agent-side
firefik-back exposes proxy endpoints under `/api/templates*` and
`/api/approvals*` — UI talks to firefik-back, which forwards
operator's bearer onto firefik-server.

### Approval audit fan-out

Every successful create / approve / reject is recorded via
`store.RecordAudit` AND fanned out through the configured
`SinkFanOut`. Default sinks:

- `WebhookSink` if `FIREFIK_WEBHOOK_URL` is set. HMAC-SHA256 over
  `action\ntimestamp\nbody`; `X-Firefik-Timestamp` header for replay
  protection.
- `OTelSink` if `FIREFIK_OTEL_LOGS_ENABLED=true`. Severity by action
  (`*_rejected` → WARN, default INFO).

## Metrics (server-side)

| Metric | Type | Labels |
|--------|------|--------|
| `firefik_controlplane_grpc_agents_connected` | gauge | — |
| `firefik_controlplane_transport_requests_total` | counter | `transport` |
| `firefik_controlplane_audit_events_total` | counter | — |
| `firefik_controlplane_db_bytes` | gauge | — |
| `firefik_controlplane_commands_enqueued_total` | counter | `kind` |
| `firefik_controlplane_mtls_rejected_total` | counter | `reason` |
| `firefik_controlplane_ca_certs_issued_total` | counter | — |

## SPIRE compatibility

Agents deployed under SPIRE can skip the embedded mini-CA. Point
`FIREFIK_CONTROL_PLANE_CLIENT_CERT` / `_CLIENT_KEY` at the SPIRE-rotated
SVID paths (typically `/run/spire/agent/svid.pem` + `svid.key`), and
make sure the trust bundle is wired via `FIREFIK_CONTROL_PLANE_CA_CERT`.
Server-side `FIREFIK_CP_TRUST_DOMAIN` must match the SPIRE trust domain.
