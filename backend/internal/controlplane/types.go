package controlplane

import "time"

type AgentIdentity struct {
	InstanceID string            `json:"instance_id"`
	Hostname   string            `json:"hostname"`
	Version    string            `json:"version"`
	Backend    string            `json:"backend"`
	Chain      string            `json:"chain"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type TrafficBucket struct {
	Timestamp string `json:"ts"`
	Accepted  int64  `json:"accepted"`
	Dropped   int64  `json:"dropped"`
}

type AgentSnapshot struct {
	Agent      AgentIdentity    `json:"agent"`
	Containers []ContainerState `json:"containers"`
	At         time.Time        `json:"at"`
	Traffic    []TrafficBucket  `json:"traffic,omitempty"`
}

type ContainerState struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Status         string            `json:"status"`
	FirewallStatus string            `json:"firewall_status"`
	DefaultPolicy  string            `json:"default_policy"`
	Labels         map[string]string `json:"labels,omitempty"`
	RuleSetCount   int               `json:"rule_set_count"`
	Sources        []string          `json:"sources,omitempty"`
}

type AuditEventEnvelope struct {
	Agent AgentIdentity  `json:"agent"`
	Event map[string]any `json:"event"`
}

type EnrollmentToken struct {
	Token      string     `json:"token"`
	AgentID    string     `json:"agent_id"`
	TTLSeconds int        `json:"ttl_seconds"`
	ExpiresAt  time.Time  `json:"expires_at"`
	IssuedBy   string     `json:"issued_by"`
	IssuedAt   time.Time  `json:"issued_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	ConsumerIP string     `json:"consumer_ip,omitempty"`
}

type LogLine struct {
	Agent  AgentIdentity     `json:"agent"`
	At     time.Time         `json:"at"`
	Level  string            `json:"level,omitempty"`
	Source string            `json:"source,omitempty"`
	Line   string            `json:"line"`
	Fields map[string]string `json:"fields,omitempty"`
}

type AutogenProposal struct {
	AgentID     string   `json:"agent_id"`
	ContainerID string   `json:"container_id"`
	Ports       []uint32 `json:"ports"`
	Peers       []string `json:"peers"`
	ObservedFor string   `json:"observed_for,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CommandKind string

const (
	CommandApply          CommandKind = "apply"
	CommandDisable        CommandKind = "disable"
	CommandReconcile      CommandKind = "reconcile"
	CommandTokenRotate    CommandKind = "token_rotate"
	CommandStatsCollect   CommandKind = "stats_collect"
	CommandAutogenApprove CommandKind = "autogen_approve"
	CommandAutogenReject  CommandKind = "autogen_reject"
)

type Command struct {
	ID          string         `json:"id"`
	Kind        CommandKind    `json:"kind"`
	ContainerID string         `json:"container_id,omitempty"`
	Payload     map[string]any `json:"payload,omitempty"`
	IssuedAt    time.Time      `json:"issued_at"`
}

type CommandAck struct {
	ID            string         `json:"id"`
	AgentID       string         `json:"agent_id"`
	Success       bool           `json:"success"`
	Error         string         `json:"error,omitempty"`
	CompletedAt   time.Time      `json:"completed_at"`
	ResultPayload map[string]any `json:"result_payload,omitempty"`
}

type PolicyTemplate struct {
	Name      string            `json:"name"`
	Version   int64             `json:"version"`
	Body      string            `json:"body"`
	Labels    map[string]string `json:"labels,omitempty"`
	Publisher string            `json:"publisher,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

type PendingApproval struct {
	ID               string         `json:"id"`
	PolicyName       string         `json:"policy_name"`
	ProposedBody     string         `json:"proposed_body"`
	Requester        string         `json:"requester"`
	RequesterFinger  string         `json:"requester_fingerprint"`
	RequestedAt      time.Time      `json:"requested_at"`
	Approver         string         `json:"approver,omitempty"`
	ApproverFinger   string         `json:"approver_fingerprint,omitempty"`
	ApprovedAt       *time.Time     `json:"approved_at,omitempty"`
	Status           ApprovalStatus `json:"status"`
	RejectionComment string         `json:"rejection_comment,omitempty"`
}
