package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"firefik/internal/policy"
)

type ruleSetView struct {
	Name      string   `json:"name"`
	Ports     []uint16 `json:"ports"`
	Allowlist []string `json:"allowlist"`
	Blocklist []string `json:"blocklist"`
	Protocol  string   `json:"protocol,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Log       bool     `json:"log,omitempty"`
	LogPrefix string   `json:"logPrefix,omitempty"`
	GeoBlock  []string `json:"geoBlock,omitempty"`
	GeoAllow  []string `json:"geoAllow,omitempty"`
}

func cidrsToStrings(in []net.IPNet) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, n.String())
	}
	return out
}

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

type fleetStatsTrafficBucket struct {
	Timestamp string `json:"ts"`
	Accepted  int64  `json:"accepted"`
	Dropped   int64  `json:"dropped"`
}

type fleetStatsResponse struct {
	Agents     fleetStatsAgentCounts     `json:"agents"`
	Containers fleetStatsContainerCounts `json:"containers"`
	Traffic    []fleetStatsTrafficBucket `json:"traffic"`
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
	resp := fleetStatsResponse{Traffic: []fleetStatsTrafficBucket{}}
	traffic := map[string]*fleetStatsTrafficBucket{}
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
		for _, b := range snap.Traffic {
			cur, ok := traffic[b.Timestamp]
			if !ok {
				cur = &fleetStatsTrafficBucket{Timestamp: b.Timestamp}
				traffic[b.Timestamp] = cur
			}
			cur.Accepted += b.Accepted
			cur.Dropped += b.Dropped
		}
	}
	keys := make([]string, 0, len(traffic))
	for k := range traffic {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		resp.Traffic = append(resp.Traffic, *traffic[k])
	}
	writeJSON(w, http.StatusOK, resp)
}

type fleetContainerDTO struct {
	AgentID        string            `json:"agent_id"`
	AgentHostname  string            `json:"agent_hostname"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Status         string            `json:"status"`
	Enabled        bool              `json:"enabled"`
	FirewallStatus string            `json:"firewallStatus"`
	DefaultPolicy  string            `json:"defaultPolicy,omitempty"`
	Labels         map[string]string `json:"labels"`
	RuleSets       []any             `json:"ruleSets"`
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
			labels := c.Labels
			if labels == nil {
				labels = map[string]string{}
			}
			fwStatus := normaliseFirewallStatus(c.FirewallStatus)
			out = append(out, fleetContainerDTO{
				AgentID:        rec.Identity.InstanceID,
				AgentHostname:  rec.Identity.Hostname,
				ID:             c.ID,
				Name:           c.Name,
				Status:         c.Status,
				Enabled:        fwStatus == "active",
				FirewallStatus: fwStatus,
				DefaultPolicy:  c.DefaultPolicy,
				Labels:         labels,
				RuleSets:       []any{},
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

func normaliseFirewallStatus(s string) string {
	switch s {
	case "active", "inactive", "disabled":
		return s
	case "":
		return "disabled"
	default:
		return s
	}
}

type fleetRuleDTO struct {
	AgentID       string `json:"agent_id"`
	AgentHostname string `json:"agent_hostname"`
	ContainerID   string `json:"containerID"`
	ContainerName string `json:"containerName"`
	Status        string `json:"status"`
	DefaultPolicy string `json:"defaultPolicy"`
	RuleSets      []any  `json:"ruleSets"`
	RuleSetCount  int    `json:"rule_set_count"`
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
			defPol := c.DefaultPolicy
			if defPol == "" {
				defPol = "ACCEPT"
			}
			out = append(out, fleetRuleDTO{
				AgentID:       rec.Identity.InstanceID,
				AgentHostname: rec.Identity.Hostname,
				ContainerID:   c.ID,
				ContainerName: c.Name,
				Status:        c.Status,
				DefaultPolicy: defPol,
				RuleSets:      []any{},
				RuleSetCount:  c.RuleSetCount,
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
	AgentID       string            `json:"agent_id"`
	AgentHostname string            `json:"agent_hostname,omitempty"`
	Action        string            `json:"action"`
	Source        string            `json:"source"`
	ContainerID   string            `json:"container_id,omitempty"`
	ContainerName string            `json:"container_name,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Timestamp     string            `json:"ts"`
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
	hosts := s.hostnamesByAgent(r.Context())
	out := make([]auditEventDTO, 0, len(events))
	for _, ev := range events {
		dto := auditEventDTO{
			AgentID:       ev.AgentID,
			AgentHostname: hosts[ev.AgentID],
			Action:        nonEmptyOr(ev.Kind, "unknown"),
			Source:        "control-plane",
			Timestamp:     ev.At.UTC().Format(time.RFC3339Nano),
		}
		if ev.Payload != nil {
			if v, ok := ev.Payload["container_id"].(string); ok {
				dto.ContainerID = v
			}
			if v, ok := ev.Payload["container_name"].(string); ok {
				dto.ContainerName = v
			}
			if v, ok := ev.Payload["source"].(string); ok && v != "" {
				dto.Source = v
			}
			meta := map[string]string{}
			for k, v := range ev.Payload {
				if k == "container_id" || k == "container_name" || k == "source" || k == "action" {
					continue
				}
				if s, ok := v.(string); ok {
					meta[k] = s
				}
			}
			if len(meta) > 0 {
				dto.Metadata = meta
			}
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

type policySummaryDTO struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Source      string    `json:"source,omitempty"`
	Rules       int       `json:"rules"`
	Author      string    `json:"author,omitempty"`
	Comment     string    `json:"comment,omitempty"`
	SHA         string    `json:"sha"`
	CommittedAt time.Time `json:"committedAt"`
}

type policyDetailDTO struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Source      string        `json:"source,omitempty"`
	DSL         string        `json:"dsl"`
	RuleSets    []ruleSetView `json:"ruleSets"`
	Author      string        `json:"author,omitempty"`
	Comment     string        `json:"comment,omitempty"`
	SHA         string        `json:"sha"`
	CommittedAt time.Time     `json:"committedAt"`
}

type policyValidateRequest struct {
	DSL string `json:"dsl"`
}

type policyValidateResponse struct {
	OK       bool     `json:"ok"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type policySaveRequest struct {
	DSL     string `json:"dsl"`
	Comment string `json:"comment,omitempty"`
	Author  string `json:"author,omitempty"`
}

type policySimulateRequest struct {
	ContainerID string            `json:"containerID,omitempty"`
	DSL         string            `json:"dsl,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type policySimulateResponse struct {
	Policy        string            `json:"policy"`
	Container     string            `json:"container,omitempty"`
	DefaultPolicy string            `json:"defaultPolicy,omitempty"`
	RuleSets      []ruleSetView     `json:"ruleSets"`
	Warnings      []string          `json:"warnings,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
	LabelsSeen    map[string]string `json:"labelsSeen,omitempty"`
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
			Version:     shortSHA(v.SHA),
			Source:      "control-plane",
			Rules:       countRulesInDSL(v.DSL),
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
		s.handlePolicyValidate(w, r)
	case sub == "simulate" && r.Method == http.MethodPost:
		s.handlePolicySimulate(w, r, name)
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
	rules := evaluatePolicyRules(v.DSL)
	writeJSON(w, http.StatusOK, policyDetailDTO{
		Name: v.Name, Version: shortSHA(v.SHA), Source: "control-plane",
		DSL: v.DSL, RuleSets: rules, Author: v.Author, Comment: v.Comment,
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
	if _, err := policy.Parse(req.DSL); err != nil {
		http.Error(w, "policy parse: "+err.Error(), http.StatusBadRequest)
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
		Version:     shortSHA(v.SHA),
		Source:      "control-plane",
		Rules:       countRulesInDSL(v.DSL),
		Author:      v.Author,
		Comment:     v.Comment,
		SHA:         v.SHA,
		CommittedAt: v.CommittedAt,
	})
}

func (s *HTTPServer) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	var req policyValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp := policyValidateResponse{OK: true}
	if strings.TrimSpace(req.DSL) == "" {
		resp.OK = false
		resp.Errors = []string{"empty dsl"}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if _, err := policy.Parse(req.DSL); err != nil {
		resp.OK = false
		resp.Errors = []string{err.Error()}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *HTTPServer) handlePolicySimulate(w http.ResponseWriter, r *http.Request, name string) {
	var req policySimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	dsl := req.DSL
	if strings.TrimSpace(dsl) == "" {
		v, err := s.Registry.store.GetPolicyVersion(r.Context(), name)
		if err != nil {
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}
		dsl = v.DSL
	}
	resp := policySimulateResponse{
		Policy:    name,
		Container: req.ContainerID,
		RuleSets:  []ruleSetView{},
	}
	if req.Labels != nil {
		resp.LabelsSeen = req.Labels
	}
	parsed, err := policy.Parse(dsl)
	if err != nil {
		resp.Errors = []string{err.Error()}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	views, warns, _ := renderPolicyViews(parsed)
	resp.RuleSets = views
	resp.Warnings = warns
	resp.DefaultPolicy = "DROP"
	writeJSON(w, http.StatusOK, resp)
}

func evaluatePolicyRules(dsl string) []ruleSetView {
	if strings.TrimSpace(dsl) == "" {
		return []ruleSetView{}
	}
	parsed, err := policy.Parse(dsl)
	if err != nil {
		return []ruleSetView{}
	}
	views, _, _ := renderPolicyViews(parsed)
	return views
}

func renderPolicyViews(parsed []*policy.Policy) ([]ruleSetView, []string, error) {
	views := []ruleSetView{}
	var warnings []string
	for _, pol := range parsed {
		compiled, err := policy.Compile(pol)
		if err != nil {
			return nil, warnings, err
		}
		warnings = append(warnings, compiled.Warnings...)
		for _, rs := range compiled.RuleSets {
			views = append(views, ruleSetView{
				Name:      rs.Name,
				Ports:     append([]uint16(nil), rs.Ports...),
				Allowlist: cidrsToStrings(rs.Allowlist),
				Blocklist: cidrsToStrings(rs.Blocklist),
				Protocol:  rs.Protocol,
				Profile:   rs.Profile,
				Log:       rs.Log,
				LogPrefix: rs.LogPrefix,
				GeoBlock:  append([]string(nil), rs.GeoBlock...),
				GeoAllow:  append([]string(nil), rs.GeoAllow...),
			})
		}
	}
	return views, warnings, nil
}

func countRulesInDSL(dsl string) int {
	views := evaluatePolicyRules(dsl)
	total := 0
	for _, v := range views {
		total += len(v.Ports) + len(v.Allowlist) + len(v.Blocklist)
	}
	return total
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

type autogenProposalDTO struct {
	AgentID       string   `json:"agent_id"`
	AgentHostname string   `json:"agent_hostname,omitempty"`
	ContainerID   string   `json:"container_id"`
	Ports         []uint32 `json:"ports"`
	Peers         []string `json:"peers"`
	ObservedFor   string   `json:"observed_for,omitempty"`
	Confidence    string   `json:"confidence,omitempty"`
	Status        string   `json:"status,omitempty"`
	UpdatedAt     string   `json:"updated_at"`
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
			Status:        "pending",
			UpdatedAt:     p.UpdatedAt.UTC().Format(time.RFC3339Nano),
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
	agentID := req.AgentID
	if agentID == "" {
		agentID = s.resolveProposalAgent(r.Context(), containerID)
	}
	if agentID == "" {
		http.Error(w, "agent_id required (no proposal found for this container)", http.StatusBadRequest)
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
	s.Registry.Enqueue(agentID, cmd)

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
	_ = s.Registry.store.DeleteProposal(r.Context(), agentID, containerID)
	resp := map[string]any{
		"id":      cmd.ID,
		"agent":   agentID,
		"action":  action,
		"success": true,
	}
	if ack.ResultPayload != nil {
		for k, v := range ack.ResultPayload {
			resp[k] = v
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *HTTPServer) resolveProposalAgent(ctx context.Context, containerID string) string {
	items, err := s.Registry.store.ListProposals(ctx, "")
	if err != nil {
		return ""
	}
	for _, p := range items {
		if p.ContainerID == containerID || strings.HasPrefix(p.ContainerID, containerID) {
			return p.AgentID
		}
	}
	return ""
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

type fleetContainerActionResult struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type fleetContainerBulkResponse struct {
	Results []fleetContainerActionResult `json:"results"`
	Summary struct {
		Total    int `json:"total"`
		Applied  int `json:"applied"`
		Disabled int `json:"disabled"`
		Failed   int `json:"failed"`
	} `json:"summary"`
}

type fleetContainerActionRequest struct {
	AgentID string `json:"agent_id,omitempty"`
}

type fleetContainerBulkRequest struct {
	Actions []struct {
		ID      string `json:"id"`
		Action  string `json:"action"`
		AgentID string `json:"agent_id,omitempty"`
	} `json:"actions"`
}

func (s *HTTPServer) handleFleetContainerAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/containers/")
	if rest == r.URL.Path || rest == "" {
		http.Error(w, "container id required", http.StatusBadRequest)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 1 && parts[0] == "bulk" {
		s.handleFleetContainerBulk(w, r)
		return
	}
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
	var req fleetContainerActionRequest
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	agentID := req.AgentID
	if agentID == "" {
		agentID = s.resolveContainerAgent(r.Context(), containerID)
	}
	if agentID == "" {
		http.Error(w, "agent_id required (no agent owns this container)", http.StatusBadRequest)
		return
	}
	kind, err := containerCommandKind(action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.runContainerCommand(r.Context(), agentID, containerID, kind); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": containerID, "action": action, "status": "ok"})
}

func (s *HTTPServer) handleFleetContainerBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req fleetContainerBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp := fleetContainerBulkResponse{Results: []fleetContainerActionResult{}}
	for _, a := range req.Actions {
		res := fleetContainerActionResult{ID: a.ID, Action: a.Action}
		agentID := a.AgentID
		if agentID == "" {
			agentID = s.resolveContainerAgent(r.Context(), a.ID)
		}
		if agentID == "" {
			res.Status = "error"
			res.Error = "agent not found"
			resp.Results = append(resp.Results, res)
			resp.Summary.Failed++
			continue
		}
		kind, err := containerCommandKind(a.Action)
		if err != nil {
			res.Status = "error"
			res.Error = err.Error()
			resp.Results = append(resp.Results, res)
			resp.Summary.Failed++
			continue
		}
		if err := s.runContainerCommand(r.Context(), agentID, a.ID, kind); err != nil {
			res.Status = "error"
			res.Error = err.Error()
			resp.Summary.Failed++
		} else {
			res.Status = "ok"
			if a.Action == "apply" {
				resp.Summary.Applied++
			} else {
				resp.Summary.Disabled++
			}
		}
		resp.Results = append(resp.Results, res)
	}
	resp.Summary.Total = len(resp.Results)
	writeJSON(w, http.StatusOK, resp)
}

func (s *HTTPServer) runContainerCommand(ctx context.Context, agentID, containerID string, kind CommandKind) error {
	cmd := Command{
		ID:          newCommandID(),
		Kind:        kind,
		ContainerID: containerID,
		IssuedAt:    time.Now().UTC(),
	}
	s.Registry.Enqueue(agentID, cmd)
	waitCtx, cancel := context.WithTimeout(ctx, defaultRemotePullTimeout)
	defer cancel()
	ack, err := s.Registry.WaitForAck(waitCtx, cmd.ID, defaultRemotePullTimeout)
	if err != nil {
		return errors.New("timeout waiting for agent ack")
	}
	if !ack.Success {
		if ack.Error != "" {
			return errors.New(ack.Error)
		}
		return errors.New("agent reported failure")
	}
	return nil
}

func (s *HTTPServer) resolveContainerAgent(ctx context.Context, containerID string) string {
	records, err := s.Registry.store.ListAgents(ctx)
	if err != nil {
		return ""
	}
	for _, rec := range records {
		snap, err := s.Registry.store.LatestSnapshot(ctx, rec.Identity.InstanceID)
		if err != nil || snap == nil {
			continue
		}
		for _, c := range snap.Containers {
			if c.ID == containerID || strings.HasPrefix(c.ID, containerID) {
				return rec.Identity.InstanceID
			}
		}
	}
	return ""
}

func containerCommandKind(action string) (CommandKind, error) {
	switch action {
	case "apply":
		return CommandApply, nil
	case "disable":
		return CommandDisable, nil
	}
	return "", errors.New("unsupported action: " + action)
}
