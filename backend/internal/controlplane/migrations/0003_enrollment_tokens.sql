CREATE TABLE enrollment_tokens (
    token        TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    issued_by    TEXT NOT NULL,
    issued_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consumed_at  TIMESTAMP,
    consumer_ip  TEXT
);

CREATE INDEX idx_enrollment_tokens_agent ON enrollment_tokens(agent_id, issued_at DESC);
CREATE INDEX idx_enrollment_tokens_expires ON enrollment_tokens(expires_at) WHERE consumed_at IS NULL;
