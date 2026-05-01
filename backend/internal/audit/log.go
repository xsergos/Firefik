package audit

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

type Source string

const (
	SourceLabel        Source = "label"
	SourceEvent        Source = "event"
	SourceAPI          Source = "api"
	SourceConfigReload Source = "config-reload"
	SourceStartup      Source = "startup"
	SourceManual       Source = "manual"
	SourceDrift        Source = "drift"
	SourceSchedule     Source = "schedule"
	SourceControlPlane Source = "control-plane"
)

const shortIDLen = 12

type Logger struct {
	log  *slog.Logger
	sink Sink
}

func New(logger *slog.Logger) *Logger {
	return &Logger{log: logger}
}

func (l *Logger) WithSink(sink Sink) *Logger {
	return &Logger{log: l.log, sink: sink}
}

func (l *Logger) Close() error {
	if l.sink == nil {
		return nil
	}
	return l.sink.Close()
}

func (l *Logger) emit(ev Event) {
	if l.sink == nil {
		return
	}
	if err := l.sink.Write(ev); err != nil && l.log != nil {
		l.log.Warn("audit sink write failed", "error", err)
	}
}

func shortID(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}
	return id
}

func (l *Logger) RulesApplied(containerID, containerName string, ips []net.IP, ruleSetCount int, defaultPolicy string, source Source) {
	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}
	l.log.Info("firewall rules applied",
		"log_type", "audit",
		"action", "apply",
		"container_id", containerID,
		"container_id_short", shortID(containerID),
		"container_name", containerName,
		"container_ips", ipStrs,
		"rule_sets", ruleSetCount,
		"default_policy", defaultPolicy,
		"source", source,
	)
	l.emit(Event{
		Timestamp:     time.Now().UTC(),
		Action:        "apply",
		Source:        source,
		ContainerID:   containerID,
		ContainerName: containerName,
		ContainerIPs:  ipStrs,
		RuleSets:      ruleSetCount,
		DefaultPolicy: defaultPolicy,
	})
}

func (l *Logger) RulesRemoved(containerID string, source Source) {
	l.log.Info("firewall rules removed",
		"log_type", "audit",
		"action", "remove",
		"container_id", containerID,
		"container_id_short", shortID(containerID),
		"source", source,
	)
	l.emit(Event{
		Timestamp:   time.Now().UTC(),
		Action:      "remove",
		Source:      source,
		ContainerID: containerID,
	})
}

func (l *Logger) LegacyCleanup(chain, suffix string, removed int, err string) {
	attrs := []any{
		"log_type", "audit",
		"action", "cleanup_legacy",
		"chain", chain,
		"suffix", suffix,
		"removed_chains", removed,
	}
	if err != "" {
		attrs = append(attrs, "error", err)
	}
	l.log.Info("blue-green cleanup", attrs...)
	meta := map[string]string{
		"chain":  chain,
		"suffix": suffix,
	}
	if err != "" {
		meta["error"] = err
	}
	l.emit(Event{
		Timestamp: time.Now().UTC(),
		Action:    "cleanup_legacy",
		Source:    SourceStartup,
		RuleSets:  removed,
		Metadata:  meta,
	})
}

func (l *Logger) TokenRotated(fingerprint string) {
	l.log.Info("API token rotated",
		"log_type", "audit",
		"action", "token_rotated",
		"fingerprint", fingerprint,
	)
	l.emit(Event{
		Timestamp: time.Now().UTC(),
		Action:    "token_rotated",
		Source:    SourceManual,
		Metadata:  map[string]string{"fingerprint": fingerprint},
	})
}

func (l *Logger) DriftDetected(driftType string, counts map[string]int) {
	attrs := []any{
		"log_type", "audit",
		"action", "drift_detected",
		"drift_type", driftType,
	}
	meta := map[string]string{"drift_type": driftType}
	for k, v := range counts {
		attrs = append(attrs, k, v)
		meta[k] = fmt.Sprintf("%d", v)
	}
	l.log.Warn("drift detected", attrs...)
	l.emit(Event{
		Timestamp: time.Now().UTC(),
		Action:    "drift_detected",
		Source:    SourceDrift,
		Metadata:  meta,
	})
}

func (l *Logger) PolicyUpdated(name, version, comment, source string) {
	meta := map[string]string{
		"policy":  name,
		"version": version,
		"source":  source,
	}
	if comment != "" {
		meta["comment"] = comment
	}
	l.log.Info("policy updated",
		"log_type", "audit",
		"action", "policy_updated",
		"policy", name,
		"version", version,
		"source", source,
	)
	l.emit(Event{
		Timestamp: time.Now().UTC(),
		Action:    "policy_updated",
		Source:    Source(source),
		Metadata:  meta,
	})
}

func (l *Logger) AutogenApproved(containerID, containerName string, ports []uint16, peers []string, mode, author string) {
	portStrs := make([]string, 0, len(ports))
	for _, p := range ports {
		portStrs = append(portStrs, fmt.Sprintf("%d", p))
	}
	l.log.Info("autogen proposal approved",
		"log_type", "audit",
		"action", "autogen_approved",
		"container_id", shortID(containerID),
		"container_name", containerName,
		"ports", ports,
		"peers", peers,
		"mode", mode,
	)
	l.emit(Event{
		Timestamp:     time.Now().UTC(),
		Action:        "autogen_approved",
		Source:        SourceAPI,
		ContainerID:   shortID(containerID),
		ContainerName: containerName,
		Metadata: map[string]string{
			"ports":  strings.Join(portStrs, ","),
			"peers":  strings.Join(peers, ","),
			"mode":   mode,
			"author": author,
		},
	})
}

func (l *Logger) AutogenRejected(containerID, containerName, reason, author string) {
	l.log.Info("autogen proposal rejected",
		"log_type", "audit",
		"action", "autogen_rejected",
		"container_id", shortID(containerID),
		"container_name", containerName,
		"reason", reason,
	)
	l.emit(Event{
		Timestamp:     time.Now().UTC(),
		Action:        "autogen_rejected",
		Source:        SourceAPI,
		ContainerID:   shortID(containerID),
		ContainerName: containerName,
		Metadata: map[string]string{
			"reason": reason,
			"author": author,
		},
	})
}

func (l *Logger) ReconcileStarted(source Source) {
	l.log.Info("reconcile started",
		"log_type", "audit",
		"action", "reconcile",
		"source", source,
	)
	l.emit(Event{
		Timestamp: time.Now().UTC(),
		Action:    "reconcile",
		Source:    source,
	})
}
