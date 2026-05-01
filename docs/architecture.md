# Firefik — Architecture

High-level flow diagrams for the key paths. Paired with narrative in
[operations.md](operations.md).

---

## 1 — High-level components

```mermaid
flowchart LR
  subgraph Host[Host / Docker daemon]
    DOCKER[Docker API]
    KERNEL[iptables / nftables kernel state]
  end

  subgraph Agent[firefik-back]
    EVENTS[Docker event loop]
    ENGINE[Rule engine<br/>reconcile + apply]
    LABELS[Label + policy compiler]
    API[HTTP API + WS]
    AUDIT[Audit sinks]
    METRICS[Prometheus /metrics]
  end

  subgraph Operator[Operators + integrations]
    UI[firefik-front UI]
    ADMIN[firefik-admin CLI]
    PROM[Prometheus]
    SIEM[SIEM / remote sink]
  end

  subgraph ControlPlane[firefik-server optional]
    GRPC[gRPC stream :8444]
    ENROLL[HTTP /v1/enroll :8443]
    CA[mini-CA]
    STORE[SQLite store]
  end

  DOCKER -->|container events| EVENTS
  EVENTS --> ENGINE
  LABELS --> ENGINE
  ENGINE -->|apply| KERNEL
  ENGINE --> AUDIT
  ENGINE --> METRICS
  API --> UI
  API --> ADMIN
  METRICS --> PROM
  AUDIT --> SIEM

  Agent <-.mTLS bidi stream.-> GRPC
  Agent -.enroll + renew.-> ENROLL
  ENROLL --> CA
  GRPC --> STORE
```

Key points:

- Kernel is source of truth; firefik derives memory state from kernel
  on startup (`Rehydrate`), not the other way around.
- Control plane is optional. Agents work autonomously without
  firefik-server; no fleet feature (policy push, audit aggregation)
  depends on server uptime for agent-local firewall state.

---

## 2 — Agent event loop (per-container path)

```mermaid
sequenceDiagram
  actor User as Container owner
  participant Docker
  participant Events as Event loop
  participant Labels as Label compiler
  participant Engine
  participant Kernel as iptables/nftables
  participant Audit as Audit sinks

  User->>Docker: docker run --label firefik.enable=true ...
  Docker-->>Events: container.start event
  Events->>Docker: inspect(containerID)
  Docker-->>Events: labels + IPs
  Events->>Labels: parse(labels)
  Labels-->>Events: RuleSet
  Events->>Engine: ApplyContainer(ruleSet)
  Engine->>Kernel: iptables -N FIREFIK-<id>;<br/>iptables -A ...
  Kernel-->>Engine: ok
  Engine->>Audit: rule_applied{id, rules=N}
  Engine-->>Events: done

  Note over Events,Engine: Reconciler also runs every N seconds<br/>and on drift detection
```

---

## 3 — Control plane: enrollment

```mermaid
sequenceDiagram
  participant Operator
  participant Agent as firefik-admin
  participant Server as firefik-server<br/>(HTTP :8443)
  participant CA as mini-CA
  participant Store as SQLite

  Operator->>Server: 1. firefik-server mini-ca init<br/>(creates root + issuing CA)
  Operator->>Agent: 2. firefik-admin enroll<br/>--control-plane server:8443<br/>--token <bootstrap>
  Agent->>Server: POST /v1/enroll<br/>{agent_id, ttl, trust_domain}
  Server->>Server: verify bearer token
  Server->>CA: issue(agent_id, ttl)
  CA-->>Server: cert + key + bundle<br/>(SPIFFE URI SAN)
  Server->>Store: record enroll event
  Server-->>Agent: cert + key + bundle (PEM)
  Agent->>Agent: write to --out path

  Note over Agent,Server: Renewal: same flow with --renew<br/>when cert ≤ --renew-window.
```

---

## 4 — Control plane: bi-directional stream

```mermaid
sequenceDiagram
  participant Agent as firefik-back
  participant Server as firefik-server<br/>(gRPC :8444)
  participant CA_Bundle as trust bundle<br/>+ SPIFFE domain

  Agent->>Server: Stream RPC open (mTLS)
  Server->>CA_Bundle: verify peer cert
  CA_Bundle-->>Server: check URI SAN = spiffe://your.tld/...
  alt trust domain mismatch
    Server-->>Agent: reject (metrics: mtls_rejected_total)
  else authorised
    Server-->>Agent: stream open
  end

  loop each snapshot_interval
    Agent->>Server: Snapshot{containers, rules, kernel_state}
    Server->>Server: persist snapshot (with rotation)
  end

  loop each audit event
    Agent->>Server: Audit{event, container_id, ts}
    Server->>Server: persist audit row
  end

  loop on operator action
    Server->>Agent: Command{kind, payload}
    Agent->>Agent: dispatch (apply, drain, reload)
    Agent->>Server: Ack{command_id, result}
  end
```

Reconnect: agent uses exponential backoff (1s → 60s cap) on
disconnect. `firefik_controlplane_connection_state` reports live
value. All local firewall enforcement continues during disconnect.

---

## 5 — Audit fan-out

```mermaid
flowchart LR
  EVENT[Audit event produced]
  EVENT --> FORK{fan-out}

  FORK --> SLOG[slog<br/>(stderr)]
  FORK --> FILE[JSON file sink<br/>+ lumberjack rotation]
  FORK --> CEF[CEF file sink]
  FORK --> REMOTE[remote NDJSON HTTP POST]

  FILE --> ROT[rotated archives<br/>size / backups / age / gzip]
  CEF --> ROT
  REMOTE --> SIEM[SIEM<br/>(Splunk / ArcSight / ELK)]
```

- Sinks are configured via `FIREFIK_AUDIT_SINK` (comma-separated list).
- Each sink writes independently; one failing doesn't block the others.
- Write path is non-blocking (bounded channel); full channel ⇒
  drop + increment internal counter.

---

## 6 — Label → kernel rule compile pipeline

```mermaid
flowchart TD
  RAW[Raw container labels]
  RAW --> PARSE[ParseLabels]
  PARSE --> VALIDATE[ValidateSuffix + port/IP validation]
  VALIDATE --> TEMPL[Expand firefik.template=...]
  TEMPL --> POLICY[Expand firefik.policy=...]
  POLICY --> COMPILE[Policy DSL compile]
  COMPILE --> GEOIP[Resolve GeoIP CIDRs]
  GEOIP --> SETS[Emit rule-sets<br/>inbound + outbound]
  SETS --> BACKEND{Backend}
  BACKEND -- iptables --> IPT[iptables -A ...]
  BACKEND -- nftables --> NFT[nft add rule ...]
```

Every transform is pure — given the same labels + policy files +
GeoIP DB version, output is deterministic. This makes `firefik-admin
explain --packet` behaviour reproducible.

---

## 7 — Blue/green chain swap

```mermaid
flowchart LR
  subgraph Before
    P1[DOCKER-USER -j FIREFIK]
    P1 --> OLD[FIREFIK<br/>(old rules)]
  end

  subgraph Stage
    NEW[FIREFIK-v2<br/>(new rules, installed but unreachable)]
    P2[DOCKER-USER -j FIREFIK]
    P2 --> OLD2[FIREFIK]
    NEW -.dry.-> NEW
  end

  subgraph Swap
    P3[DOCKER-USER -j FIREFIK-v2]
    P3 --> NEW3[FIREFIK-v2]
    OLD3[FIREFIK<br/>(orphan)] -.reap.-> X(( ))
  end

  Before --> Stage
  Stage --> Swap
```

`firefik-admin reap --suffix=""` removes the old chain-tree after the
soak window. Parent-chain jump is swapped atomically with a single
`iptables -R` (replace rule).

---

## 8 — Policy approval gate (4-eyes, v0.12+)

```mermaid
sequenceDiagram
  autonumber
  actor Alice as Operator A
  actor Bob as Operator B
  participant UI as firefik-front
  participant BACK as firefik-back
  participant CP as firefik-server
  participant DB as sqlite

  Alice->>UI: Edit policy P (with requires_approval=true)
  UI->>BACK: POST /api/approvals (proxied)
  BACK->>CP: POST /v1/approvals
  CP->>CP: derive requester_fingerprint = sha256(bearer)
  CP->>DB: INSERT pending_approvals (status=pending)
  Note over Bob: Reviews pending list
  Bob->>UI: Click Approve
  UI->>BACK: POST /api/approvals/{id}/approve (proxied)
  BACK->>CP: POST /v1/approvals/{id}/approve
  CP->>CP: derive approver_fingerprint = sha256(bearer)
  alt fingerprints differ
    CP->>DB: UPDATE status=approved
    CP-->>BACK: 200 OK
  else same fingerprint
    CP-->>BACK: 403 self-approve forbidden
  end
```

The fingerprint is `sha256(bearer_token)[:16]`. Two operators must
hold distinct tokens (typically distinct named tokens via
`FIREFIK_API_TOKEN_FILE` rotation across hosts). Same-token approval
returns `ErrSelfApprove → 403 Forbidden`.

---

## 9 — OTel metrics bridge (v0.12+)

```mermaid
flowchart LR
  A[promauto-registered<br/>collectors] -->|gather every<br/>FIREFIK_OTEL_METRICS_INTERVAL| BR[prometheusBridge<br/>Producer]
  BR -->|metricdata.ScopeMetrics| RD[PeriodicReader]
  RD --> EX[OTLP gRPC/HTTP exporter]
  EX -->|push| COLL[OpenTelemetry collector]
  A -->|same registry| PROM[Prometheus pull /metrics]
```

The bridge keeps a **single source of truth** in Prometheus collectors;
the OTel side is a fan-out, not a parallel registry. Counters → Sum
(monotonic, cumulative). Gauges → Gauge. Histograms → Histogram with
preserved bucket boundaries. Summaries are skipped (OTLP has no native
mapping for Prometheus quantile summaries).

---

## 10 — OTel logs bridge + approval webhook fan-out (v0.13+)

```mermaid
flowchart LR
  subgraph Server[firefik-server]
    HTTP[HTTP handlers<br/>POST /v1/approvals/*]
    FAN[SinkFanOut]
    HTTP -->|emit action+metadata| FAN
    FAN --> WS[Webhook sink<br/>HMAC signed]
    FAN --> OS[OTel sink<br/>BatchProcessor]
  end
  WS -->|POST + X-Firefik-Signature| HOOK[(External webhook<br/>Slack / Teams / SIEM)]
  OS --> OTLP[OTLP logs<br/>gRPC/HTTP exporter]
  OTLP -->|push| COLL[(OpenTelemetry collector)]
```

`policy_approval_requested`, `policy_approval_approved`,
`policy_approval_rejected` events are emitted from the HTTP handlers
inside firefik-server (not the agent). The fan-out is opt-in: a
configured `FIREFIK_WEBHOOK_URL` activates the webhook sink, and a
`FIREFIK_OTEL_LOGS_ENABLED=true` activates the OTel sink. With no
config, events are silently dropped at the fan-out (the store still
records them).

The OTel sink writes log records with severity by action: ERROR for
`rule_apply_failed`, WARN for `rule_drift_detected` and
`policy_approval_rejected`, INFO otherwise. Body is the JSON-serialised
`audit.Event`; attributes carry `audit.action`, `audit.source`,
`audit.container_id`, etc.

---

## Invariants (enforced by code; see design-notes for motivation)

- **Rule-set deterministic**: same inputs → same output chain, byte-
  for-byte. Tested against `testdata/golden/`.
- **Never partial apply**: a container's rule-set applies either
  fully or not at all (apply → swap-in via temporary chain on
  iptables, atomic table swap on nftables).
- **Audit-before-kernel**: audit write happens on the *success* path
  of the kernel apply, but the kernel side is the source of truth —
  re-apply from labels is always safe.
- **No kernel state outside FIREFIK chain-tree**: firefik never
  modifies `INPUT` / `FORWARD` / `OUTPUT` / `DOCKER-USER` rules except
  the one parent-chain jump.

---

## See also

- [operations.md](operations.md) — narrative ops.
- [control-plane.md](control-plane.md) — gRPC + enrollment detail.
