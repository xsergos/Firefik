CREATE TABLE agent_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    issued_by    TEXT NOT NULL,
    issued_at    TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    last_used_ip TEXT,
    revoked_at   TIMESTAMP
);

CREATE INDEX idx_agent_tokens_active ON agent_tokens(revoked_at);
CREATE INDEX idx_agent_tokens_issued ON agent_tokens(issued_at DESC);
