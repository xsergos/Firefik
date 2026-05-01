package api

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"firefik/internal/audit"
	"firefik/internal/docker"
	"firefik/internal/policy"
	"firefik/internal/rules"
)

type PolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*policy.Policy
}

var policyNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{policies: make(map[string]*policy.Policy)}
}

func (s *PolicyStore) Set(policies map[string]*policy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = make(map[string]*policy.Policy, len(policies))
	for k, v := range policies {
		s.policies[k] = v
	}
}

func (s *PolicyStore) Upsert(p *policy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.Name] = p
}

func (s *PolicyStore) Snapshot() map[string]*policy.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*policy.Policy, len(s.policies))
	for k, v := range s.policies {
		out[k] = v
	}
	return out
}

func (s *PolicyStore) Get(name string) (*policy.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[name]
	return p, ok
}

func (s *PolicyStore) List() []PolicySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PolicySummary, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, PolicySummary{
			Name:    p.Name,
			Version: p.Version,
			Source:  p.Source,
			Rules:   len(p.Rules),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type PolicySummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source,omitempty"`
	Rules   int    `json:"rules"`
}

// @Summary List policies
// @Description Returns the set of compiled policies keyed by name.
// @Tags policies
// @Produce json
// @Security BearerAuth
// @Success 200 {array} PolicySummary
// @Router /api/policies [get]
func (s *Server) handleGetPolicies(c *gin.Context) {
	c.JSON(http.StatusOK, s.policies.List())
}

// @Summary Validate a policy snippet
// @Description Parses + compiles `dsl` in the request body and returns `{ok, errors, warnings}` without touching state.
// @Tags policies
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body policyValidateRequest true "DSL source"
// @Success 200 {object} policyValidateResponse
// @Failure 400 {object} APIError
// @Router /api/policies/validate [post]
func (s *Server) handleValidatePolicy(c *gin.Context) {
	var req policyValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	resp := policyValidateResponse{OK: true}
	pols, err := policy.Parse(req.DSL)
	if err != nil {
		resp.OK = false
		resp.Errors = append(resp.Errors, err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	for _, p := range pols {
		comp, err := policy.Compile(p)
		if err != nil {
			resp.OK = false
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		resp.Warnings = append(resp.Warnings, comp.Warnings...)
	}
	c.JSON(http.StatusOK, resp)
}

type policyValidateRequest struct {
	DSL string `json:"dsl" binding:"required"`
}

type policyValidateResponse struct {
	OK       bool     `json:"ok"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type PolicyDetail struct {
	Name     string               `json:"name"`
	Version  string               `json:"version"`
	Source   string               `json:"source,omitempty"`
	DSL      string               `json:"dsl"`
	RuleSets []FirewallRuleSetDTO `json:"ruleSets"`
}

// @Summary Get a policy
// @Description Returns the compiled rule-sets and original DSL source for a single policy.
// @Tags policies
// @Produce json
// @Security BearerAuth
// @Param name path string true "policy name"
// @Success 200 {object} PolicyDetail
// @Failure 404 {object} APIError
// @Failure 500 {object} APIError
// @Router /api/policies/{name} [get]
func (s *Server) handleGetPolicy(c *gin.Context) {
	name := c.Param("name")
	p, ok := s.policies.Get(name)
	if !ok {
		respondError(c, http.StatusNotFound, "policy_not_found", "policy "+name+" not found")
		return
	}
	comp, err := policy.Compile(p)
	if err != nil {
		respondInternalError(c, "policy_compile_failed", "failed to compile policy", err)
		return
	}
	detail := PolicyDetail{
		Name:    p.Name,
		Version: p.Version,
		Source:  p.Source,
		DSL:     string(p.SourceBytes),
	}
	for _, rs := range comp.RuleSets {
		detail.RuleSets = append(detail.RuleSets, ruleSetToDTO(rs))
	}
	c.JSON(http.StatusOK, detail)
}

type policySimulateRequest struct {
	ContainerID string            `json:"containerID,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	DSL         string            `json:"dsl,omitempty"`
}

type PolicySimulateResponse struct {
	Policy        string               `json:"policy"`
	Container     string               `json:"container,omitempty"`
	RuleSets      []FirewallRuleSetDTO `json:"ruleSets"`
	Warnings      []string             `json:"warnings,omitempty"`
	Errors        []string             `json:"errors,omitempty"`
	LabelsSeen    map[string]string    `json:"labelsSeen,omitempty"`
	DefaultPolicy string               `json:"defaultPolicy,omitempty"`
}

// @Summary Simulate a policy
// @Description Compiles a policy (existing or supplied via `dsl`) and previews the resulting rule-sets, optionally against a container's labels.
// @Tags policies
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "policy name"
// @Param body body policySimulateRequest false "simulation request"
// @Success 200 {object} PolicySimulateResponse
// @Failure 404 {object} APIError
// @Router /api/policies/{name}/simulate [post]
func (s *Server) handleSimulatePolicy(c *gin.Context) {
	name := c.Param("name")
	var req policySimulateRequest
	_ = c.ShouldBindJSON(&req)

	resp := PolicySimulateResponse{Policy: name}
	var pol *policy.Policy
	if strings.TrimSpace(req.DSL) != "" {
		pols, err := policy.Parse(req.DSL)
		if err != nil {
			resp.Errors = append(resp.Errors, err.Error())
			c.JSON(http.StatusOK, resp)
			return
		}
		for _, p := range pols {
			if p.Name == name || name == "" {
				pol = p
				break
			}
		}
		if pol == nil && len(pols) > 0 {
			pol = pols[0]
			resp.Policy = pol.Name
		}
	} else {
		existing, ok := s.policies.Get(name)
		if !ok {
			respondError(c, http.StatusNotFound, "policy_not_found", "policy "+name+" not found")
			return
		}
		pol = existing
	}

	comp, err := policy.Compile(pol)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp.Warnings = append(resp.Warnings, comp.Warnings...)

	labels := req.Labels
	if req.ContainerID != "" {
		if ctr, ok := s.resolveContainerSilent(c, req.ContainerID); ok {
			resp.Container = ctr.ID
			if labels == nil {
				labels = ctr.Labels
			}
			cfg, _ := docker.ParseLabels(ctr.Labels)

			if labels[rules.PolicyLabel] == "" {
				if labels == nil {
					labels = map[string]string{}
				}
				labels[rules.PolicyLabel] = pol.Name
			}
			cfg = rules.ApplyPolicies(cfg, labels, map[string]*policy.Policy{pol.Name: pol})
			for _, rs := range cfg.RuleSets {
				resp.RuleSets = append(resp.RuleSets, ruleSetToDTO(rs))
			}
			resp.DefaultPolicy = cfg.DefaultPolicy
			resp.LabelsSeen = labels
			c.JSON(http.StatusOK, resp)
			return
		}
	}

	for _, rs := range comp.RuleSets {
		resp.RuleSets = append(resp.RuleSets, ruleSetToDTO(rs))
	}
	resp.LabelsSeen = labels
	c.JSON(http.StatusOK, resp)
}

type policyWriteRequest struct {
	DSL     string `json:"dsl" binding:"required"`
	Comment string `json:"comment,omitempty"`
}

// @Summary Write a policy
// @Description Upserts a single policy by name. Fails when `FIREFIK_POLICIES_READONLY=true`.
// @Tags policies
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "policy name"
// @Param body body policyWriteRequest true "policy DSL + optional comment"
// @Success 200 {object} PolicySummary
// @Failure 400 {object} APIError
// @Failure 403 {object} APIError
// @Router /api/policies/{name} [put]
func (s *Server) handleWritePolicy(c *gin.Context) {
	if s.cfg.PoliciesReadOnly {
		respondError(c, http.StatusForbidden, "policies_readonly",
			"policy write rejected: FIREFIK_POLICIES_READONLY=true (GitOps mode)")
		return
	}
	name := c.Param("name")
	if !policyNameRe.MatchString(name) {
		respondError(c, http.StatusBadRequest, "invalid_name",
			"policy name must match ^[A-Za-z0-9_.-]{1,64}$")
		return
	}
	var req policyWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, ErrCodeInvalidBody, err.Error())
		return
	}
	pols, err := policy.Parse(req.DSL)
	if err != nil {
		respondErrorDetails(c, http.StatusBadRequest, "policy_parse_failed", "DSL parse failed", err.Error())
		return
	}
	var chosen *policy.Policy
	for _, p := range pols {
		if p.Name == name {
			chosen = p
			break
		}
	}
	if chosen == nil {
		if len(pols) == 1 {
			chosen = pols[0]
		} else {
			respondError(c, http.StatusBadRequest, "policy_name_mismatch",
				"DSL does not contain policy \""+name+"\"")
			return
		}
	}
	if _, err := policy.Compile(chosen); err != nil {
		respondErrorDetails(c, http.StatusBadRequest, "policy_compile_failed", "policy compile failed", err.Error())
		return
	}
	chosen.Source = "api"

	s.policies.Upsert(chosen)
	if s.engine != nil {
		s.engine.SetPolicies(s.policies.Snapshot())
		if err := s.engine.Reconcile(c.Request.Context(), audit.SourceAPI); err != nil {
			s.logger.Warn("reconcile after policy write failed", "policy", chosen.Name, "error", err)
		}
	}
	if s.auditLog != nil {
		s.auditLog.PolicyUpdated(chosen.Name, chosen.Version, req.Comment, string(audit.SourceAPI))
	}

	c.JSON(http.StatusOK, PolicySummary{
		Name:    chosen.Name,
		Version: chosen.Version,
		Source:  chosen.Source,
		Rules:   len(chosen.Rules),
	})
}
