package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

type ContainerDTO struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Status         string               `json:"status"`
	Enabled        bool                 `json:"enabled"`
	FirewallStatus string               `json:"firewallStatus"`
	DefaultPolicy  string               `json:"defaultPolicy"`
	Labels         map[string]string    `json:"labels"`
	RuleSets       []FirewallRuleSetDTO `json:"ruleSets"`
}

type RateLimitDTO struct {
	Rate  uint `json:"rate"`
	Burst uint `json:"burst"`
}

type FirewallRuleSetDTO struct {
	Name      string        `json:"name"`
	Ports     []uint16      `json:"ports"`
	Allowlist []string      `json:"allowlist"`
	Blocklist []string      `json:"blocklist"`
	Profile   string        `json:"profile,omitempty"`
	Protocol  string        `json:"protocol,omitempty"`
	Log       bool          `json:"log,omitempty"`
	LogPrefix string        `json:"logPrefix,omitempty"`
	RateLimit *RateLimitDTO `json:"rateLimit,omitempty"`
	GeoBlock  []string      `json:"geoBlock,omitempty"`
	GeoAllow  []string      `json:"geoAllow,omitempty"`
}

// @Summary List containers
// @Description Returns every container visible to the Docker daemon with its parsed firewall configuration and live apply status.
// @Tags containers
// @Produce json
// @Security BearerAuth
// @Success 200 {array} ContainerDTO
// @Failure 500 {object} APIError
// @Router /api/containers [get]
func (s *Server) handleGetContainers(c *gin.Context) {
	containers, err := s.docker.ListContainers(c.Request.Context())
	if err != nil {
		respondInternalError(c, ErrCodeDockerUnavailable, "failed to list containers", err)
		return
	}

	fileRules, _ := config.LoadRulesFile(s.cfg.ConfigFile)
	applied := s.engine.GetApplied()

	resp := make([]ContainerDTO, 0, len(containers))
	for _, ctr := range containers {
		cfg, parseErrs := docker.ParseLabels(ctr.Labels)
		for _, pe := range parseErrs {
			s.logger.Warn("label parse error", "container", ctr.Name, "error", pe)
		}
		cfg = rules.MergeFileRules(cfg, ctr.Name, fileRules)
		_, isApplied := applied[rules.ShortID(ctr.ID)]
		resp = append(resp, containerToDTO(ctr, cfg, isApplied))
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) resolveContainerSilent(c *gin.Context, id string) (docker.ContainerInfo, bool) {
	if !isValidContainerID(id) {
		return docker.ContainerInfo{}, false
	}
	containers, err := s.docker.ListContainers(c.Request.Context())
	if err != nil {
		return docker.ContainerInfo{}, false
	}
	var match docker.ContainerInfo
	found := 0
	for _, ctr := range containers {
		if ctr.ID == id || (len(id) < 64 && strings.HasPrefix(ctr.ID, id)) {
			match = ctr
			found++
		}
	}
	if found != 1 {
		return docker.ContainerInfo{}, false
	}
	return match, true
}

func (s *Server) resolveContainer(c *gin.Context, id string) (docker.ContainerInfo, bool) {
	if !isValidContainerID(id) {
		respondErrorDetails(c, http.StatusBadRequest, ErrCodeInvalidID, "invalid container id", "expected 12-64 hex chars")
		return docker.ContainerInfo{}, false
	}
	containers, err := s.docker.ListContainers(c.Request.Context())
	if err != nil {
		respondInternalError(c, ErrCodeDockerUnavailable, "failed to list containers", err)
		return docker.ContainerInfo{}, false
	}
	var matches []docker.ContainerInfo
	for _, ctr := range containers {
		if ctr.ID == id || (len(id) < 64 && strings.HasPrefix(ctr.ID, id)) {
			matches = append(matches, ctr)
		}
	}
	switch len(matches) {
	case 0:
		respondError(c, http.StatusNotFound, ErrCodeContainerMissing, "container not found")
		return docker.ContainerInfo{}, false
	case 1:
		return matches[0], true
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name)
		}
		respondErrorDetails(c, http.StatusConflict, ErrCodeAmbiguousPrefix,
			"container prefix matches multiple containers", strings.Join(names, ","))
		return docker.ContainerInfo{}, false
	}
}

// @Summary Get a container
// @Description Resolves by full container ID or unambiguous prefix. Returns the parsed label-based config merged with the file-rules overlay.
// @Tags containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "container ID or unambiguous prefix (12-64 hex chars)"
// @Success 200 {object} ContainerDTO
// @Failure 400 {object} APIError
// @Failure 404 {object} APIError
// @Failure 409 {object} APIError "ambiguous prefix"
// @Failure 500 {object} APIError
// @Router /api/containers/{id} [get]
func (s *Server) handleGetContainer(c *gin.Context) {
	id := c.Param("id")
	ctr, ok := s.resolveContainer(c, id)
	if !ok {
		return
	}
	fileRules, _ := config.LoadRulesFile(s.cfg.ConfigFile)
	applied := s.engine.GetApplied()
	cfg, parseErrs := docker.ParseLabels(ctr.Labels)
	for _, pe := range parseErrs {
		s.logger.Warn("label parse error", "container", ctr.Name, "error", pe)
	}
	cfg = rules.MergeFileRules(cfg, ctr.Name, fileRules)
	_, isApplied := applied[rules.ShortID(ctr.ID)]
	c.JSON(http.StatusOK, containerToDTO(ctr, cfg, isApplied))
}

// @Summary List applied rule-sets
// @Description Snapshot of what firefik currently has applied in the kernel, keyed by container. Each entry includes container name, status, default policy, and per-rule-set details.
// @Tags rules
// @Produce json
// @Security BearerAuth
// @Success 200 {array} RuleEntry
// @Failure 500 {object} APIError
// @Router /api/rules [get]
func (s *Server) handleGetRules(c *gin.Context) {
	applied := s.engine.GetApplied()

	containers, err := s.docker.ListContainers(c.Request.Context())
	if err != nil {
		respondInternalError(c, ErrCodeDockerUnavailable, "failed to list containers", err)
		return
	}

	names := make(map[string]string, len(containers))
	statuses := make(map[string]string, len(containers))
	for _, ctr := range containers {
		sid := rules.ShortID(ctr.ID)
		names[sid] = ctr.Name
		statuses[sid] = ctr.Status
	}

	result := make([]RuleEntry, 0, len(applied))
	for id, cfg := range applied {
		entry := RuleEntry{
			ContainerID:   id,
			ContainerName: names[id],
			Status:        statuses[id],
			DefaultPolicy: cfg.DefaultPolicy,
			RuleSets:      make([]FirewallRuleSetDTO, 0),
		}
		for _, rs := range cfg.RuleSets {
			rsDTO := ruleSetToDTO(rs)
			entry.RuleSets = append(entry.RuleSets, rsDTO)
		}
		result = append(result, entry)
	}
	c.JSON(http.StatusOK, result)
}

func containerToDTO(ctr docker.ContainerInfo, cfg docker.ContainerConfig, isApplied bool) ContainerDTO {
	policy := cfg.DefaultPolicy
	if policy == "" {
		policy = "RETURN"
	}
	var fwStatus string
	switch {
	case !cfg.Enable:
		fwStatus = "disabled"
	case isApplied:
		fwStatus = "active"
	default:
		fwStatus = "inactive"
	}
	dto := ContainerDTO{
		ID:             ctr.ID,
		Name:           ctr.Name,
		Status:         ctr.Status,
		Enabled:        cfg.Enable,
		FirewallStatus: fwStatus,
		DefaultPolicy:  policy,
		Labels:         ctr.Labels,
		RuleSets:       make([]FirewallRuleSetDTO, 0),
	}
	for _, rs := range cfg.RuleSets {
		dto.RuleSets = append(dto.RuleSets, ruleSetToDTO(rs))
	}
	return dto
}

func ruleSetToDTO(rs docker.FirewallRuleSet) FirewallRuleSetDTO {
	protocol := rs.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	dto := FirewallRuleSetDTO{
		Name:      rs.Name,
		Ports:     rs.Ports,
		Profile:   rs.Profile,
		Protocol:  protocol,
		Log:       rs.Log,
		LogPrefix: rs.LogPrefix,
		GeoBlock:  rs.GeoBlock,
		GeoAllow:  rs.GeoAllow,
	}
	if rs.RateLimit != nil {
		dto.RateLimit = &RateLimitDTO{Rate: rs.RateLimit.Rate, Burst: rs.RateLimit.Burst}
	}
	for _, ip := range rs.Allowlist {
		if ip.IP != nil {
			dto.Allowlist = append(dto.Allowlist, ip.String())
		}
	}
	for _, ip := range rs.Blocklist {
		if ip.IP != nil {
			dto.Blocklist = append(dto.Blocklist, ip.String())
		}
	}
	return dto
}

// @Summary Apply firewall rules to a container
// @Description Re-reads labels + file-rules and installs the merged rule-sets. Audit source = `api`.
// @Tags containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "container ID or unambiguous prefix"
// @Success 200 {object} StatusResponse
// @Failure 400 {object} APIError
// @Failure 404 {object} APIError
// @Failure 409 {object} APIError
// @Failure 500 {object} APIError
// @Router /api/containers/{id}/apply [post]
func (s *Server) handleApplyContainer(c *gin.Context) {
	id := c.Param("id")
	ctr, ok := s.resolveContainer(c, id)
	if !ok {
		return
	}
	if err := s.engine.ApplyContainer(c.Request.Context(), ctr.ID, audit.SourceAPI); err != nil {
		respondInternalError(c, ErrCodeApplyFailed, "failed to apply rules", err)
		return
	}
	c.JSON(http.StatusOK, StatusResponse{Status: "applied"})
}

// @Summary Disable firewall rules for a container
// @Description Removes kernel chains + any associated audit entries for the container. Audit source = `api`.
// @Tags containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "container ID (12-64 hex chars)"
// @Success 200 {object} StatusResponse
// @Failure 400 {object} APIError
// @Failure 500 {object} APIError
// @Router /api/containers/{id}/disable [post]
func (s *Server) handleDisableContainer(c *gin.Context) {
	id := c.Param("id")
	if !isValidContainerID(id) {
		respondErrorDetails(c, http.StatusBadRequest, ErrCodeInvalidID, "invalid container id", "expected 12-64 hex chars")
		return
	}
	if err := s.engine.RemoveContainer(id, audit.SourceAPI); err != nil {
		respondInternalError(c, ErrCodeDisableFailed, "failed to disable container rules", err)
		return
	}
	c.JSON(http.StatusOK, StatusResponse{Status: "disabled"})
}
