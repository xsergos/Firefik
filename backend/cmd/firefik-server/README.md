# firefik-server (control plane)

The central control plane for a firefik fleet. Accepts agent
registrations, collects per-host snapshots + audit events, and
dispatches commands (apply / disable / reconcile / token-rotate) back
via bidirectional gRPC streams.

## Transport

gRPC bidirectional streams over TLS 1.3 with mutual auth. The
`.proto` contract lives at [backend/proto/controlplane/v1/controlplane.proto](../../proto/controlplane/v1/controlplane.proto)
and is the sole supported protocol.

See [docs/control-plane.md](../../../docs/control-plane.md) for the
full protocol reference.

## Run

```bash
firefik-server --grpc-listen :8444 \
  --listen :8443 \
  --cert /etc/firefik-server/tls.crt \
  --key /etc/firefik-server/tls.key \
  --client-ca /etc/firefik-server/agents-ca.pem \
  --ca-state-dir /var/lib/firefik-server/ca \
  --trust-domain spiffe://prod.corp/ \
  --db /var/lib/firefik-server/firefik.db
```

- `--grpc-listen` — operational traffic. Mutual TLS is mandatory.
- `--listen` — bootstrap only: `GET /healthz`, `POST /v1/enroll`.
- `--client-ca` enables mTLS (`RequireAndVerifyClientCert`) for the
  gRPC listener. Agents must present certs signed by this CA.
- `--ca-state-dir` — directory with the embedded mini-CA state
  (created by `firefik-server mini-ca init`). Enables `/v1/enroll`.
- `--trust-domain` (or `FIREFIK_CP_TRUST_DOMAIN`) — rejects peer
  certs whose URI SAN is not under the given SPIFFE domain.
- `--db` — sqlite path for persistent agent / snapshot / audit /
  command / policy-version rows. `":memory:"` or empty disables
  persistence (tests only).

## Bootstrap CA

```bash
firefik-server mini-ca init --state-dir /var/lib/firefik-server/ca \
                            --trust-domain spiffe://prod.corp/
firefik-server mini-ca issue --state-dir /var/lib/firefik-server/ca \
                             --agent-id host-a --ttl 720h --out /tmp/host-a
```

Agents call `firefik-admin enroll` to pull short-lived certs via the
HTTP `/v1/enroll` endpoint.

## Endpoints (HTTP, bootstrap-only)

| Method | Path | Caller | Purpose |
|--------|------|--------|---------|
| GET  | `/healthz` | anyone | Liveness probe (unauthenticated). |
| POST | `/v1/enroll` | agent | Request/renew mTLS client cert from embedded mini-CA. |

## Agent integration

Agents (firefik-back) opt in by setting:

- `FIREFIK_CONTROL_PLANE_GRPC=cp.example:8444`
- `FIREFIK_CONTROL_PLANE_CA_CERT=/etc/firefik/ca-bundle.pem`
- `FIREFIK_CONTROL_PLANE_CLIENT_CERT=/etc/firefik/client.crt`
- `FIREFIK_CONTROL_PLANE_CLIENT_KEY=/etc/firefik/client.key`
- `FIREFIK_CONTROL_PLANE_TOKEN=…` (optional; supplementary to mTLS)

On connection loss the agent degrades to local-only operation — the
control plane is an observer, not a master.

## Features

- Embedded mini-CA subcommand (`firefik-server mini-ca init|issue`)
  + `/v1/enroll` endpoint + `firefik-admin enroll [--renew]`.
- SPIFFE SVID trust-domain enforcement via
  `FIREFIK_CP_TRUST_DOMAIN` / `--trust-domain`.
- gRPC-only transport.

## Out of scope

- HA / multi-replica control plane — single-host by design.
- Postgres / MySQL backend — sqlite-only persistence.
- Multi-token RBAC — one operator = one bearer token.
