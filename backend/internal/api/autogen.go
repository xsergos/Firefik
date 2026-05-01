package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"firefik/internal/autogen"
)

// @Summary Auto-generated rule proposals
// @Description Returns observe-mode proposals per container. Populated only when `FIREFIK_AUTOGEN_MODE=observe`.
// @Tags autogen
// @Produce json
// @Security BearerAuth
// @Success 200 {array} object
// @Router /api/autogen/proposals [get]
func (s *Server) handleGetAutogenProposals(c *gin.Context) {
	if s.autogen == nil {
		c.JSON(http.StatusOK, []autogen.Proposal{})
		return
	}
	proposals := s.autogen.Propose(s.cfg.AutogenMinSamples, 15*time.Minute)

	if store := s.autogen.StoreHandle(); store != nil {
		for _, p := range proposals {
			_ = store.UpsertProposal(c.Request.Context(), p)
		}
	}

	if store := s.autogen.StoreHandle(); store != nil {
		records, err := store.ListProposals(c.Request.Context())
		if err == nil {
			c.JSON(http.StatusOK, recordsToDTO(proposals, records))
			return
		}
	}
	c.JSON(http.StatusOK, proposals)
}

type autogenProposalDTO struct {
	ContainerID string   `json:"container_id"`
	Ports       []uint16 `json:"ports"`
	Peers       []string `json:"peers"`
	ObservedFor string   `json:"observed_for,omitempty"`
	Confidence  string   `json:"confidence"`
	Status      string   `json:"status,omitempty"`
	DecidedBy   string   `json:"decided_by,omitempty"`
	DecidedAt   string   `json:"decided_at,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

func recordsToDTO(live []autogen.Proposal, records []autogen.ProposalRecord) []autogenProposalDTO {
	byID := make(map[string]autogen.ProposalRecord, len(records))
	for _, r := range records {
		byID[r.ContainerID] = r
	}
	out := make([]autogenProposalDTO, 0, len(live))
	for _, p := range live {
		dto := autogenProposalDTO{
			ContainerID: p.ContainerID,
			Ports:       p.Ports,
			Peers:       p.Peers,
			ObservedFor: p.ObservedFor,
			Confidence:  p.Confidence,
			Status:      string(autogen.StatusPending),
		}
		if rec, ok := byID[p.ContainerID]; ok {
			dto.Status = string(rec.Status)
			dto.DecidedBy = rec.DecidedBy
			if !rec.DecidedAt.IsZero() {
				dto.DecidedAt = rec.DecidedAt.UTC().Format(time.RFC3339)
			}
			dto.Reason = rec.Reason
		}
		out = append(out, dto)
	}

	liveSet := map[string]struct{}{}
	for _, p := range live {
		liveSet[p.ContainerID] = struct{}{}
	}
	for _, rec := range records {
		if _, ok := liveSet[rec.ContainerID]; ok {
			continue
		}
		dto := autogenProposalDTO{
			ContainerID: rec.ContainerID,
			Ports:       rec.Ports,
			Peers:       rec.Peers,
			ObservedFor: rec.ObservedFor,
			Confidence:  rec.Confidence,
			Status:      string(rec.Status),
			DecidedBy:   rec.DecidedBy,
			Reason:      rec.Reason,
		}
		if !rec.DecidedAt.IsZero() {
			dto.DecidedAt = rec.DecidedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerID < out[j].ContainerID })
	return out
}

type approveRequest struct {
	Mode string `json:"mode"`
}

type approveResponse struct {
	Mode        string   `json:"mode"`
	Snippet     string   `json:"snippet"`
	ContainerID string   `json:"container_id"`
	Ports       []uint16 `json:"ports,omitempty"`
	Peers       []string `json:"peers,omitempty"`
}

// @Summary Approve an autogen proposal
// @Description Materialises a pending observe-mode proposal as labels or a policy snippet and records the approval.
// @Tags autogen
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "container ID or unambiguous prefix"
// @Param body body approveRequest false "approval mode (`labels` or `policy`)"
// @Success 200 {object} approveResponse
// @Failure 400 {object} APIError
// @Failure 404 {object} APIError
// @Router /api/autogen/proposals/{id}/approve [post]
func (s *Server) handleApproveAutogen(c *gin.Context) {
	if s.autogen == nil {
		respondError(c, http.StatusBadRequest, "autogen_disabled",
			"FIREFIK_AUTOGEN_MODE=observe required")
		return
	}
	containerID := c.Param("id")
	if containerID == "" {
		respondError(c, http.StatusBadRequest, ErrCodeInvalidID, "container id required")
		return
	}
	var req approveRequest
	_ = c.ShouldBindJSON(&req)
	if req.Mode == "" {
		req.Mode = "labels"
	}
	if req.Mode != "labels" && req.Mode != "policy" {
		respondError(c, http.StatusBadRequest, "invalid_mode",
			"mode must be labels or policy")
		return
	}

	proposals := s.autogen.Propose(s.cfg.AutogenMinSamples, 15*time.Minute)
	var target *autogen.Proposal
	for i := range proposals {
		if strings.HasPrefix(proposals[i].ContainerID, containerID) || proposals[i].ContainerID == containerID {
			target = &proposals[i]
			break
		}
	}
	if target == nil {

		if store := s.autogen.StoreHandle(); store != nil {
			records, _ := store.ListProposals(c.Request.Context(), autogen.StatusPending)
			for i := range records {
				if strings.HasPrefix(records[i].ContainerID, containerID) || records[i].ContainerID == containerID {
					p := autogen.Proposal{
						ContainerID: records[i].ContainerID,
						Ports:       records[i].Ports,
						Peers:       records[i].Peers,
						Confidence:  records[i].Confidence,
					}
					target = &p
					break
				}
			}
		}
	}
	if target == nil {
		respondError(c, http.StatusNotFound, "proposal_not_found",
			"no pending proposal for this container")
		return
	}

	var snippet string
	if req.Mode == "policy" {
		snippet = proposalToPolicyDSL(*target)
	} else {
		snippet = proposalToLabels(*target)
	}

	if store := s.autogen.StoreHandle(); store != nil {
		if err := store.MarkProposal(c.Request.Context(), target.ContainerID, autogen.StatusApproved, "api", ""); err != nil {
			respondInternalError(c, "autogen_mark_failed", "failed to record approval", err)
			return
		}
	}
	if s.auditLog != nil {
		s.auditLog.AutogenApproved(target.ContainerID, "", target.Ports, target.Peers, req.Mode, "api")
	}

	c.JSON(http.StatusOK, approveResponse{
		Mode:        req.Mode,
		Snippet:     snippet,
		ContainerID: target.ContainerID,
		Ports:       target.Ports,
		Peers:       target.Peers,
	})
}

type rejectRequest struct {
	Reason string `json:"reason,omitempty"`
}

// @Summary Reject an autogen proposal
// @Description Marks an observe-mode proposal as rejected with an optional reason.
// @Tags autogen
// @Accept json
// @Security BearerAuth
// @Param id path string true "container ID or unambiguous prefix"
// @Param body body rejectRequest false "rejection reason"
// @Success 204 "no content"
// @Failure 400 {object} APIError
// @Router /api/autogen/proposals/{id}/reject [post]
func (s *Server) handleRejectAutogen(c *gin.Context) {
	if s.autogen == nil {
		respondError(c, http.StatusBadRequest, "autogen_disabled",
			"FIREFIK_AUTOGEN_MODE=observe required")
		return
	}
	containerID := c.Param("id")
	if containerID == "" {
		respondError(c, http.StatusBadRequest, ErrCodeInvalidID, "container id required")
		return
	}
	var req rejectRequest
	_ = c.ShouldBindJSON(&req)
	if store := s.autogen.StoreHandle(); store != nil {
		if err := store.MarkProposal(c.Request.Context(), containerID, autogen.StatusRejected, "api", req.Reason); err != nil {
			respondInternalError(c, "autogen_mark_failed", "failed to record rejection", err)
			return
		}
	}
	if s.auditLog != nil {
		s.auditLog.AutogenRejected(containerID, "", req.Reason, "api")
	}
	c.Status(http.StatusNoContent)
}

func proposalToLabels(p autogen.Proposal) string {
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

func proposalToPolicyDSL(p autogen.Proposal) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("policy \"autogen-%s\" {\n", shortID(p.ContainerID)))
	if len(p.Ports) > 0 {
		ports := make([]string, 0, len(p.Ports))
		for _, port := range p.Ports {
			ports = append(ports, fmt.Sprintf("%d", port))
		}
		b.WriteString(fmt.Sprintf("  allow if port in [%s]\n", strings.Join(ports, ", ")))
	}
	for _, peer := range p.Peers {
		b.WriteString(fmt.Sprintf("  allow if src_ip == %q\n", peer))
	}
	b.WriteString("}\n")
	return b.String()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
