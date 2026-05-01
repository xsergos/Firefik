package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"firefik/internal/audit"
)

const bulkMaxActions = 100

type BulkAction struct {
	ID     string `json:"id"     binding:"required"`
	Action string `json:"action" binding:"required,oneof=apply disable"`
}

type BulkRequest struct {
	Actions []BulkAction `json:"actions" binding:"required,min=1,max=100,dive"`
}

type BulkResultItem struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type BulkResponse struct {
	Results []BulkResultItem `json:"results"`
	Summary BulkSummary      `json:"summary"`
}

type BulkSummary struct {
	Total    int `json:"total"`
	Applied  int `json:"applied"`
	Disabled int `json:"disabled"`
	Failed   int `json:"failed"`
}

// @Summary Bulk apply/disable containers
// @Description Accepts up to 100 `{id, action}` entries and runs them against the engine. The endpoint is idempotent per-entry: a successful apply/disable repeated is a no-op. Failures are isolated per-entry.
// @Tags containers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body BulkRequest true "actions to perform"
// @Success 200 {object} BulkResponse
// @Failure 400 {object} APIError
// @Router /api/containers/bulk [post]
func (s *Server) handleBulkContainers(c *gin.Context) {
	var req BulkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorDetails(c, http.StatusBadRequest, ErrCodeInvalidBody,
			"invalid bulk request", err.Error())
		return
	}
	if len(req.Actions) > bulkMaxActions {
		respondErrorDetails(c, http.StatusBadRequest, ErrCodeInvalidBody,
			"too many actions in one bulk request", "max is 100")
		return
	}

	resp := BulkResponse{Results: make([]BulkResultItem, 0, len(req.Actions))}
	for _, a := range req.Actions {
		item := BulkResultItem{ID: a.ID, Action: a.Action, Status: "ok"}
		switch a.Action {
		case "apply":
			ctr, ok := s.resolveContainerSilent(c, a.ID)
			if !ok {
				item.Status = "error"
				item.Error = "container not resolved"
				break
			}
			if err := s.engine.ApplyContainer(c.Request.Context(), ctr.ID, audit.SourceAPI); err != nil {
				item.Status = "error"
				item.Error = err.Error()
			} else {
				resp.Summary.Applied++
			}
		case "disable":
			if !isValidContainerID(a.ID) {
				item.Status = "error"
				item.Error = "invalid container id"
				break
			}
			if err := s.engine.RemoveContainer(a.ID, audit.SourceAPI); err != nil {
				item.Status = "error"
				item.Error = err.Error()
			} else {
				resp.Summary.Disabled++
			}
		default:
			item.Status = "error"
			item.Error = "unknown action"
		}
		if item.Status == "error" {
			resp.Summary.Failed++
		}
		resp.Results = append(resp.Results, item)
	}
	resp.Summary.Total = len(req.Actions)
	c.JSON(http.StatusOK, resp)
}
