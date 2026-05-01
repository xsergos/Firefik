CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    version     TEXT,
    backend     TEXT,
    chain       TEXT,
    labels_json TEXT,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    at            TIMESTAMP NOT NULL,
    payload_json  TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS snapshots_agent_at ON snapshots(agent_id, at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT,
    at            TIMESTAMP NOT NULL,
    kind          TEXT,
    payload_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_at ON audit_events(at);
CREATE INDEX IF NOT EXISTS audit_events_agent_at ON audit_events(agent_id, at);

CREATE TABLE IF NOT EXISTS commands (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    kind          TEXT NOT NULL,
    container_id  TEXT,
    payload_json  TEXT,
    issued_at     TIMESTAMP NOT NULL,
    delivered_at  TIMESTAMP,
    acked_at      TIMESTAMP,
    success       INTEGER,
    error         TEXT,
    expired       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS commands_agent_pending
    ON commands(agent_id)
    WHERE delivered_at IS NULL AND expired = 0;

CREATE TABLE IF NOT EXISTS policy_versions (
    sha           TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    dsl           TEXT NOT NULL,
    author        TEXT,
    comment       TEXT,
    committed_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_versions_name
    ON policy_versions(name, committed_at DESC);
