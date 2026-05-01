package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"firefik/internal/audit"
	"firefik/internal/controlplane"
	"firefik/internal/telemetry"
)

func buildServerAudit(logger *slog.Logger) *controlplane.SinkFanOut {
	fan := &controlplane.SinkFanOut{Logger: logger}

	if url := os.Getenv("FIREFIK_WEBHOOK_URL"); url != "" {
		opts := audit.WebhookOptions{
			URL:     url,
			Events:  parseEventList(os.Getenv("FIREFIK_WEBHOOK_EVENTS")),
			Secret:  serverEnvWithFile("FIREFIK_WEBHOOK_SECRET", "FIREFIK_WEBHOOK_SECRET_FILE"),
			Timeout: parseDurationOr(os.Getenv("FIREFIK_WEBHOOK_TIMEOUT_MS")+"ms", 5*time.Second),
		}
		sink, err := audit.NewWebhookSink(opts)
		if err != nil {
			logger.Warn("webhook sink disabled", "error", err)
		} else {
			fan.Sinks = append(fan.Sinks, sink)
			logger.Info("webhook sink enabled", "url", url, "events", opts.Events)
		}
	}

	if telemetry.LogsEnabledFromEnv() {
		fan.Sinks = append(fan.Sinks, audit.NewOTelSink())
		logger.Info("OTel audit sink enabled")
	}

	return fan
}

func parseEventList(v string) []string {
	if v == "" {
		return []string{
			"policy_approval_requested",
			"policy_approval_approved",
			"policy_approval_rejected",
		}
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return fallback
}

func serverEnvWithFile(envName, fileEnvName string) string {
	if v := os.Getenv(envName); v != "" {
		return v
	}
	if path := os.Getenv(fileEnvName); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

var _ = context.Background
