CREATE TABLE policy_templates (
    name        TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    body        TEXT NOT NULL,
    labels_json TEXT,
    publisher   TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_approvals (
    id                   TEXT PRIMARY KEY,
    policy_name          TEXT NOT NULL,
    proposed_body        TEXT NOT NULL,
    requester            TEXT NOT NULL,
    requester_fingerprint TEXT NOT NULL,
    requested_at         TIMESTAMP NOT NULL,
    approver             TEXT,
    approver_fingerprint TEXT,
    approved_at          TIMESTAMP,
    status               TEXT NOT NULL DEFAULT 'pending',
    rejection_comment    TEXT
);

CREATE INDEX idx_pending_approvals_status ON pending_approvals(status, requested_at DESC);
CREATE INDEX idx_pending_approvals_policy ON pending_approvals(policy_name, requested_at DESC);
