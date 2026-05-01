package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

type TrafficBucket struct {
	Timestamp string `json:"ts"`
	Accepted  int64  `json:"accepted"`
	Dropped   int64  `json:"dropped"`
}

type TrafficStore struct {
	mu      sync.Mutex
	buckets [1440]TrafficBucket
	head    int
}

func NewTrafficStore() *TrafficStore {
	return &TrafficStore{}
}

func (s *TrafficStore) RecordAction(action string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Truncate(time.Minute).Format(time.RFC3339)
	if s.buckets[s.head].Timestamp != now {
		s.head = (s.head + 1) % len(s.buckets)
		s.buckets[s.head] = TrafficBucket{Timestamp: now}
	}
	switch action {
	case "ACCEPT":
		s.buckets[s.head].Accepted++
	case "DROP":
		s.buckets[s.head].Dropped++
	}
}

func (s *TrafficStore) Last(n int) []TrafficBucket {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n > len(s.buckets) {
		n = len(s.buckets)
	}
	out := make([]TrafficBucket, 0, n)
	for i := n - 1; i >= 0; i-- {
		idx := (s.head - i + len(s.buckets)) % len(s.buckets)
		if s.buckets[idx].Timestamp != "" {
			out = append(out, s.buckets[idx])
		}
	}
	return out
}

// @Summary Runtime statistics
// @Description Container counts (total/running/enabled) and 60 one-minute traffic buckets (`accepted`/`dropped`).
// @Tags stats
// @Produce json
// @Security BearerAuth
// @Success 200 {object} StatsResponse
// @Failure 500 {object} APIError
// @Router /api/stats [get]
func (s *Server) handleGetStats(c *gin.Context) {
	containers, err := s.docker.ListContainers(c.Request.Context())
	if err != nil {
		respondInternalError(c, ErrCodeDockerUnavailable, "failed to list containers", err)
		return
	}

	fileRules, _ := config.LoadRulesFile(s.cfg.ConfigFile)

	total, enabled, running := 0, 0, 0
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

	c.JSON(http.StatusOK, StatsResponse{
		Containers: ContainerCounts{
			Total:   total,
			Running: running,
			Enabled: enabled,
		},
		Traffic: s.traffic.Last(60),
	})
}
