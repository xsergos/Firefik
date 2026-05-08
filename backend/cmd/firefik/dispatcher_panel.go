package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"firefik/internal/audit"
	"firefik/internal/autogen"
	"firefik/internal/config"
	"firefik/internal/controlplane"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

const proposalLookupMinAge = 15 * time.Minute

func (d *engineDispatcher) collectStats(ctx context.Context) (map[string]any, error) {
	if d.docker == nil {
		return nil, errors.New("docker client unavailable")
	}
	containers, err := d.docker.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	var fileRules config.RulesFile
	if d.cfg != nil {
		fileRules, _ = config.LoadRulesFile(d.cfg.ConfigFile)
	}
	total, running, enabled := 0, 0, 0
	for _, ctr := range containers {
		total++
		if ctr.Status == "running" {
			running++
		}
		cfg, _ := docker.ParseLabels(ctr.Labels)
		cfg = rules.MergeFileRules(cfg, ctr.Name, fileRules)
		if cfg.Enable {
			enabled++
		}
	}
	out := map[string]any{
		"containers": map[string]any{
			"total":   total,
			"running": running,
			"enabled": enabled,
		},
	}
	if d.traffic != nil {
		buckets := d.traffic.Last(60)
		traffic := make([]map[string]any, 0, len(buckets))
		for _, b := range buckets {
			traffic = append(traffic, map[string]any{
				"ts":       b.Timestamp,
				"accepted": b.Accepted,
				"dropped":  b.Dropped,
			})
		}
		out["traffic"] = traffic
	}
	if d.engine != nil {
		applied := d.engine.GetApplied()
		out["rules_active_containers"] = len(applied)
	}
	out["at"] = time.Now().UTC().Format(time.RFC3339)
	return out, nil
}

func (d *engineDispatcher) autogenApprove(ctx context.Context, cmd controlplane.Command) (map[string]any, error) {
	if d.observer == nil {
		return nil, errors.New("autogen disabled on agent")
	}
	containerID := cmd.ContainerID
	if containerID == "" {
		return nil, errors.New("container_id required")
	}
	mode, _ := cmd.Payload["mode"].(string)
	if mode == "" {
		mode = "labels"
	}
	if mode != "labels" && mode != "policy" {
		return nil, fmt.Errorf("invalid mode %q (expected labels or policy)", mode)
	}
	target := d.findProposal(ctx, containerID)
	if target == nil {
		return nil, errors.New("no pending proposal for this container")
	}
	snippet := autogenLabelsSnippet(*target)
	if mode == "policy" {
		snippet = autogenPolicySnippet(*target)
	}
	if store := d.observer.StoreHandle(); store != nil {
		if err := store.MarkProposal(ctx, target.ContainerID, autogen.StatusApproved, "control-plane", ""); err != nil {
			return nil, fmt.Errorf("mark approved: %w", err)
		}
	}
	if d.auditLog != nil {
		d.auditLog.AutogenApproved(target.ContainerID, "", target.Ports, target.Peers, mode, "control-plane")
	}
	return map[string]any{
		"mode":         mode,
		"snippet":      snippet,
		"container_id": target.ContainerID,
		"ports":        target.Ports,
		"peers":        target.Peers,
	}, nil
}

func (d *engineDispatcher) autogenReject(ctx context.Context, cmd controlplane.Command) (map[string]any, error) {
	if d.observer == nil {
		return nil, errors.New("autogen disabled on agent")
	}
	containerID := cmd.ContainerID
	if containerID == "" {
		return nil, errors.New("container_id required")
	}
	reason, _ := cmd.Payload["reason"].(string)
	if store := d.observer.StoreHandle(); store != nil {
		if err := store.MarkProposal(ctx, containerID, autogen.StatusRejected, "control-plane", reason); err != nil {
			return nil, fmt.Errorf("mark rejected: %w", err)
		}
	}
	if d.auditLog != nil {
		d.auditLog.AutogenRejected(containerID, "", reason, "control-plane")
	}
	return map[string]any{
		"container_id": containerID,
		"reason":       reason,
	}, nil
}

func (d *engineDispatcher) findProposal(ctx context.Context, containerID string) *autogen.Proposal {
	minSamples := 0
	if d.cfg != nil {
		minSamples = d.cfg.AutogenMinSamples
	}
	for _, p := range d.observer.Propose(minSamples, proposalLookupMinAge) {
		if p.ContainerID == containerID || strings.HasPrefix(p.ContainerID, containerID) {
			out := p
			return &out
		}
	}
	if store := d.observer.StoreHandle(); store != nil {
		records, _ := store.ListProposals(ctx, autogen.StatusPending)
		for _, rec := range records {
			if rec.ContainerID == containerID || strings.HasPrefix(rec.ContainerID, containerID) {
				return &autogen.Proposal{
					ContainerID: rec.ContainerID,
					Ports:       rec.Ports,
					Peers:       rec.Peers,
					Confidence:  rec.Confidence,
				}
			}
		}
	}
	return nil
}

func autogenLabelsSnippet(p autogen.Proposal) string {
	var b strings.Builder
	b.WriteString("labels:\n")
	b.WriteString("  firefik.enable: \"true\"\n")
	if len(p.Ports) > 0 {
		ports := make([]string, 0, len(p.Ports))
		for _, port := range p.Ports {
			ports = append(ports, fmt.Sprintf("%d", port))
		}
		b.WriteString(fmt.Sprintf("  firefik.firewall.auto.ports: %q\n", strings.Join(ports, ",")))
	}
	if len(p.Peers) > 0 {
		b.WriteString(fmt.Sprintf("  firefik.firewall.auto.allowlist: %q\n", strings.Join(p.Peers, ",")))
	}
	b.WriteString("  firefik.defaultpolicy: \"DROP\"\n")
	return b.String()
}

func autogenPolicySnippet(p autogen.Proposal) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("policy %q {\n", p.ContainerID))
	b.WriteString("  default deny\n")
	for _, port := range p.Ports {
		b.WriteString(fmt.Sprintf("  allow tcp dport %d\n", port))
	}
	for _, peer := range p.Peers {
		b.WriteString(fmt.Sprintf("  allow from %s\n", peer))
	}
	b.WriteString("}\n")
	return b.String()
}

var _ = audit.SourceAPI

type autogenProposalAdapter struct {
	observer *autogen.Observer
	cfg      *config.Config
}

func (a *autogenProposalAdapter) Proposals(_ context.Context) []controlplane.AutogenProposal {
	if a.observer == nil {
		return nil
	}
	min := 0
	if a.cfg != nil {
		min = a.cfg.AutogenMinSamples
	}
	props := a.observer.Propose(min, proposalLookupMinAge)
	out := make([]controlplane.AutogenProposal, 0, len(props))
	for _, p := range props {
		ports := make([]uint32, 0, len(p.Ports))
		for _, port := range p.Ports {
			ports = append(ports, uint32(port))
		}
		out = append(out, controlplane.AutogenProposal{
			ContainerID: p.ContainerID,
			Ports:       ports,
			Peers:       append([]string(nil), p.Peers...),
			ObservedFor: p.ObservedFor,
			Confidence:  p.Confidence,
		})
	}
	return out
}

var _ = rules.NflogGroup

