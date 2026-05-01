CREATE TABLE IF NOT EXISTS autogen_schema_version (
    version INTEGER NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS observations (
    container_id TEXT NOT NULL,
    proto        TEXT NOT NULL,
    port         INTEGER NOT NULL,
    peer_ip      TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    first_at     TIMESTAMP NOT NULL,
    last_at      TIMESTAMP NOT NULL,
    PRIMARY KEY (container_id, proto, port, peer_ip)
);
CREATE INDEX IF NOT EXISTS observations_last_at ON observations(last_at);
CREATE INDEX IF NOT EXISTS observations_container ON observations(container_id);

CREATE TABLE IF NOT EXISTS proposals (
    container_id TEXT PRIMARY KEY,
    ports_json   TEXT NOT NULL,
    peers_json   TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    observed_for TEXT,
    generated_at TIMESTAMP NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_at   TIMESTAMP,
    decided_by   TEXT,
    reason       TEXT
);
CREATE INDEX IF NOT EXISTS proposals_status ON proposals(status);
