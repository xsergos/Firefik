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
