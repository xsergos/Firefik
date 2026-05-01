package api

type StatusResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ContainerCounts struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Enabled int `json:"enabled"`
}

type StatsResponse struct {
	Containers ContainerCounts `json:"containers"`
	Traffic    []TrafficBucket `json:"traffic"`
}

type ProfileEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RuleEntry struct {
	ContainerID   string               `json:"containerID"`
	ContainerName string               `json:"containerName"`
	Status        string               `json:"status"`
	DefaultPolicy string               `json:"defaultPolicy"`
	RuleSets      []FirewallRuleSetDTO `json:"ruleSets"`
}
