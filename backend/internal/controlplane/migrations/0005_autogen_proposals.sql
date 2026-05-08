CREATE TABLE IF NOT EXISTS autogen_proposals (
    agent_id     TEXT NOT NULL,
    container_id TEXT NOT NULL,
    ports_json   TEXT NOT NULL,
    peers_json   TEXT NOT NULL,
    observed_for TEXT NOT NULL DEFAULT '',
    confidence   TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (agent_id, container_id)
);

CREATE INDEX IF NOT EXISTS idx_autogen_proposals_agent ON autogen_proposals(agent_id);
