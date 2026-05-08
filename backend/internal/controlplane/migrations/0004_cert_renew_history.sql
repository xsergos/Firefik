CREATE TABLE cert_renew_history (
    serial         TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    last_renew_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cert_renew_history_agent ON cert_renew_history(agent_id, last_renew_at DESC);
