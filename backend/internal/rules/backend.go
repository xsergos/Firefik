package rules

import (
	"net"

	"firefik/internal/docker"
)

type HealthReport struct {
	Backend             string
	ParentJumpPresent   bool
	BaseChainPresent    bool
	ContainerChainCount int
	Notes               []string
}

type Backend interface {
	SetupChains() error

	Cleanup() error

	ApplyContainerRules(
		containerID string,
		containerName string,
		containerIPs []net.IP,
		ruleSets []docker.FirewallRuleSet,
		defaultPolicy string,
		autoAllowlist []net.IPNet,
	) error

	RemoveContainerChains(containerID string) error

	ApplyHostRules(rules []HostRule, defaultPolicy string) error

	RemoveHostChain() error

	ListAppliedContainerIDs() ([]string, error)

	Healthy() (HealthReport, error)
}
