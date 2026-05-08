package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRemotePullTimeout = 5 * time.Second
	defaultAuditHistoryLimit = 100
	maxAuditHistoryLimit     = 1000
)

type fleetStatsAgentCounts struct {
	Total   int `json:"total"`
	Healthy int `json:"healthy"`
	Stale   int `json:"stale"`
	Dead    int `json:"dead"`
	Unknown int `json:"unknown"`
}

type fleetStatsContainerCounts struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Enabled int `json:"enabled"`
}

type fleetStatsResponse struct {
	Agents     fleetStatsAgentCounts     `json:"agents"`
	Containers fleetStatsContainerCounts `json:"containers"`
}

func (s *HTTPServer) handleFleetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records, err := s.Registry.store.ListAgents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	resp := fleetStatsResponse{}
	for _, rec := range records {
		resp.Agents.Total++
		switch agentStatus(rec.LastSeen, now) {
		case "healthy":
			resp.Agents.Healthy++
		case "stale":
			resp.Agents.Stale++
		case "dead":
			resp.Agents.Dead++
		default:
			resp.Agents.Unknown++
		}
		snap, err := s.Registry.store.LatestSnapshot(r.Context(), rec.Identity.InstanceID)
		if err != nil || snap == nil {
			continue
		}
		for _, c := range snap.Containers {
			resp.Containers.Total++
			if strings.EqualFold(c.Status, "running") {
				resp.Containers.Running++
			}
			if c.FirewallStatus == "active" {
				resp.Containers.Enabled++
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type fleetContainerDTO struct {
	AgentID        string            `json:"agent_id"`
	AgentHostname  string            `json:"agent_hostname"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Status         string            `json:"status"`
	FirewallStatus string            `json:"firewall_status"`
	DefaultPolicy  string            `json:"default_policy"`
	Labels         map[string]string `json:"labels,omitempty"`
	RuleSetCount   int               `json:"rule_set_count"`
	Sources        []string          `json:"sources,omitempty"`
}

func (s *HTTPServer) handleFleetContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records, err := s.Registry.store.ListAgents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]fleetContainerDTO, 0, 32)
	for _, rec := range records {
		snap, err := s.Registry.store.LatestSnapshot(r.Context(), rec.Identity.InstanceID)
		if err != nil || snap == nil {
			continue
		}
		for _, c := range snap.Containers {
			out = append(out, fleetContainerDTO{
				AgentID:        rec.Identity.InstanceID,
				AgentHostname:  rec.Identity.Hostname,
				ID:             c.ID,
				Name:           c.Name,
				Status:         c.Status,
				FirewallStatus: c.FirewallStatus,
				DefaultPolicy:  c.DefaultPolicy,
				Labels:         c.Labels,
				RuleSetCount:   c.RuleSetCount,
				Sources:        c.Sources,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, http.StatusOK, out)
}

type fleetRuleDTO struct {
	AgentID        string `json:"agent_id"`
	AgentHostname  string `json:"agent_hostname"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	Status         string `json:"status"`
	FirewallStatus string `json:"firewall_status"`
	DefaultPolicy  string `json:"default_policy"`
	RuleSetCount   int    `json:"rule_set_count"`
}

func (s *HTTPServer) handleFleetRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records, err := s.Registry.store.ListAgents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]fleetRuleDTO, 0, 32)
	for _, rec := range records {
		snap, err := s.Registry.store.LatestSnapshot(r.Context(), rec.Identity.InstanceID)
		if err != nil || snap == nil {
			continue
		}
		for _, c := range snap.Containers {
			if c.RuleSetCount == 0 && c.FirewallStatus != "active" {
				continue
			}
			out = append(out, fleetRuleDTO{
				AgentID:        rec.Identity.InstanceID,
				AgentHostname:  rec.Identity.Hostname,
				ContainerID:    c.ID,
				ContainerName:  c.Name,
				Status:         c.Status,
				FirewallStatus: c.FirewallStatus,
				DefaultPolicy:  c.DefaultPolicy,
				RuleSetCount:   c.RuleSetCount,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].ContainerName < out[j].ContainerName
	})
	writeJSON(w, http.StatusOK, out)
}

type auditEventDTO struct {
	AgentID string         `json:"agent_id"`
	Kind    string         `json:"kind"`
	Payload map[string]any `json:"payload,omitempty"`
	At      time.Time      `json:"at"`
}

func (s *HTTPServer) handleFleetAuditHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := defaultAuditHistoryLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > maxAuditHistoryLimit {
				limit = maxAuditHistoryLimit
			}
		}
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	events, err := s.Registry.store.ListAuditEvents(r.Context(), agentID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]auditEventDTO, 0, len(events))
	for _, ev := range events {
		out = append(out, auditEventDTO{
			AgentID: ev.AgentID,
			Kind:    ev.Kind,
			Payload: ev.Payload,
			At:      ev.At,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type policySummaryDTO struct {
	Name        string    `json:"name"`
	Author      string    `json:"author,omitempty"`
	Comment     string    `json:"comment,omitempty"`
	SHA         string    `json:"sha"`
	CommittedAt time.Time `json:"committedAt"`
}

type policyDetailDTO struct {
	Name        string    `json:"name"`
	DSL         string    `json:"dsl"`
	Author      string    `json:"author,omitempty"`
	Comment     string    `json:"comment,omitempty"`
	SHA         string    `json:"sha"`
	CommittedAt time.Time `json:"committedAt"`
}

type policyValidateRequest struct {
	DSL string `json:"dsl"`
}

type policySaveRequest struct {
	DSL     string `json:"dsl"`
	Comment string `json:"comment,omitempty"`
	Author  string `json:"author,omitempty"`
}

func (s *HTTPServer) handlePoliciesIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	versions, err := s.Registry.store.ListPolicyVersions(r.Context(), "", 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	latest := map[string]PolicyVersion{}
	for _, v := range versions {
		if cur, ok := latest[v.Name]; !ok || v.CommittedAt.After(cur.CommittedAt) {
			latest[v.Name] = v
		}
	}
	out := make([]policySummaryDTO, 0, len(latest))
	for _, v := range latest {
		out = append(out, policySummaryDTO{
			Name:        v.Name,
			Author:      v.Author,
			Comment:     v.Comment,
			SHA:         v.SHA,
			CommittedAt: v.CommittedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *HTTPServer) handlePolicy(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "policy name required", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch {
	case sub == "validate" && r.Method == http.MethodPost:
		s.handlePolicyValidate(w, r, name)
	case sub == "" && r.Method == http.MethodGet:
		s.handlePolicyGet(w, r, name)
	case sub == "" && r.Method == http.MethodPut:
		s.handlePolicySave(w, r, name)
	default:
		http.Error(w, "method or subresource not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) handlePolicyGet(w http.ResponseWriter, r *http.Request, name string) {
	v, err := s.Registry.store.GetPolicyVersion(r.Context(), name)
	if err != nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, policyDetailDTO{
		Name: v.Name, DSL: v.DSL, Author: v.Author, Comment: v.Comment,
		SHA: v.SHA, CommittedAt: v.CommittedAt,
	})
}

func (s *HTTPServer) handlePolicySave(w http.ResponseWriter, r *http.Request, name string) {
	var req policySaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DSL) == "" {
		http.Error(w, "dsl required", http.StatusBadRequest)
		return
	}
	author := req.Author
	if author == "" {
		author = "panel"
	}
	v, err := s.Registry.store.SetPolicyVersion(r.Context(), name, req.DSL, author, req.Comment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policySummaryDTO{
		Name:        v.Name,
		Author:      v.Author,
		Comment:     v.Comment,
		SHA:         v.SHA,
		CommittedAt: v.CommittedAt,
	})
}

func (s *HTTPServer) handlePolicyValidate(w http.ResponseWriter, r *http.Request, _ string) {
	var req policyValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp := map[string]any{"ok": strings.TrimSpace(req.DSL) != ""}
	if !resp["ok"].(bool) {
		resp["errors"] = []string{"empty dsl"}
	}
	writeJSON(w, http.StatusOK, resp)
}

type autogenProposalDTO struct {
	AgentID       string    `json:"agent_id"`
	AgentHostname string    `json:"agent_hostname"`
	ContainerID   string    `json:"container_id"`
	Ports         []uint32  `json:"ports"`
	Peers         []string  `json:"peers"`
	ObservedFor   string    `json:"observed_for,omitempty"`
	Confidence    string    `json:"confidence,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *HTTPServer) handleAutogenProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := s.Registry.store.ListProposals(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hosts := s.hostnamesByAgent(r.Context())
	out := make([]autogenProposalDTO, 0, len(items))
	for _, p := range items {
		out = append(out, autogenProposalDTO{
			AgentID:       p.AgentID,
			AgentHostname: hosts[p.AgentID],
			ContainerID:   p.ContainerID,
			Ports:         p.Ports,
			Peers:         p.Peers,
			ObservedFor:   p.ObservedFor,
			Confidence:    p.Confidence,
			UpdatedAt:     p.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type autogenActionRequest struct {
	AgentID string `json:"agent_id"`
	Mode    string `json:"mode,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (s *HTTPServer) handleAutogenAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/autogen/proposals/")
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "container id and action required", http.StatusBadRequest)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		http.Error(w, "container id and action required", http.StatusBadRequest)
		return
	}
	containerID := parts[0]
	action := parts[1]
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req autogenActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "agent_id required in body", http.StatusBadRequest)
		return
	}

	var kind CommandKind
	payload := map[string]any{"container_id": containerID}
	switch action {
	case "approve":
		kind = CommandAutogenApprove
		mode := req.Mode
		if mode == "" {
			mode = "labels"
		}
		payload["mode"] = mode
	case "reject":
		kind = CommandAutogenReject
		payload["reason"] = req.Reason
	default:
		http.Error(w, "unsupported action: "+action, http.StatusBadRequest)
		return
	}

	cmd := Command{
		ID:          newCommandID(),
		Kind:        kind,
		ContainerID: containerID,
		Payload:     payload,
		IssuedAt:    time.Now().UTC(),
	}
	s.Registry.Enqueue(req.AgentID, cmd)

	ctx, cancel := context.WithTimeout(r.Context(), defaultRemotePullTimeout)
	defer cancel()
	ack, err := s.Registry.WaitForAck(ctx, cmd.ID, defaultRemotePullTimeout)
	if err != nil {
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"id": cmd.ID, "error": "timeout waiting for agent ack"})
		return
	}
	if !ack.Success {
		writeJSON(w, http.StatusBadGateway, map[string]any{"id": cmd.ID, "error": ack.Error})
		return
	}
	if ack.Success && action == "approve" {
		_ = s.Registry.store.DeleteProposal(r.Context(), req.AgentID, containerID)
	}
	if ack.Success && action == "reject" {
		_ = s.Registry.store.DeleteProposal(r.Context(), req.AgentID, containerID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      cmd.ID,
		"agent":   req.AgentID,
		"action":  action,
		"result":  ack.ResultPayload,
		"success": true,
	})
}

func (s *HTTPServer) hostnamesByAgent(ctx context.Context) map[string]string {
	out := map[string]string{}
	records, err := s.Registry.store.ListAgents(ctx)
	if err != nil {
		return out
	}
	for _, rec := range records {
		out[rec.Identity.InstanceID] = rec.Identity.Hostname
	}
	return out
}

func (s *HTTPServer) handleAgentStatsPull(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cmd := Command{
		ID:       newCommandID(),
		Kind:     CommandStatsCollect,
		IssuedAt: time.Now().UTC(),
	}
	s.Registry.Enqueue(agentID, cmd)

	ctx, cancel := context.WithTimeout(r.Context(), defaultRemotePullTimeout)
	defer cancel()
	ack, err := s.Registry.WaitForAck(ctx, cmd.ID, defaultRemotePullTimeout)
	if err != nil {
		http.Error(w, "timeout waiting for agent ack", http.StatusGatewayTimeout)
		return
	}
	if !ack.Success {
		errMsg := ack.Error
		if errMsg == "" {
			errMsg = "agent reported failure"
		}
		http.Error(w, errMsg, http.StatusBadGateway)
		return
	}
	if ack.ResultPayload == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, ack.ResultPayload)
}

var _ = errors.New
