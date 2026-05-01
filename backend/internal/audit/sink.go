package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

type RotationConfig struct {
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

func (r RotationConfig) Enabled() bool { return r.MaxSizeMB > 0 }

func openFileSink(path string, rot RotationConfig) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopCloser{os.Stdout}, nil
	}
	if rot.Enabled() {
		return &lumberjack.Logger{
			Filename:   path,
			MaxSize:    rot.MaxSizeMB,
			MaxBackups: rot.MaxBackups,
			MaxAge:     rot.MaxAgeDays,
			Compress:   rot.Compress,
			LocalTime:  true,
		}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit file %s: %w", path, err)
	}
	return f, nil
}

type Sink interface {
	Write(ev Event) error
	io.Closer
}

type Event struct {
	Timestamp      time.Time         `json:"ts"`
	Action         string            `json:"action"`
	Source         Source            `json:"source"`
	ContainerID    string            `json:"container_id,omitempty"`
	ContainerName  string            `json:"container_name,omitempty"`
	ContainerIPs   []string          `json:"container_ips,omitempty"`
	RuleSets       int               `json:"rule_sets,omitempty"`
	DefaultPolicy  string            `json:"default_policy,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	OriginalFields map[string]any    `json:"-"`
}

type MultiSink struct {
	logger *slog.Logger
	sinks  []Sink
}

func NewMultiSink(logger *slog.Logger, sinks ...Sink) *MultiSink {
	return &MultiSink{logger: logger, sinks: sinks}
}

func (m *MultiSink) Write(ev Event) error {
	for _, s := range m.sinks {
		if err := s.Write(ev); err != nil && m.logger != nil {
			m.logger.Warn("audit sink write failed", "error", err)
		}
	}
	return nil
}

func (m *MultiSink) Close() error {
	var errs []string
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close: %s", strings.Join(errs, "; "))
	}
	return nil
}

type jsonSink struct {
	mu sync.Mutex
	w  io.WriteCloser
}

func NewJSONFileSink(path string, rot RotationConfig) (Sink, error) {
	w, err := openFileSink(path, rot)
	if err != nil {
		return nil, err
	}
	return &jsonSink{w: w}, nil
}

func (s *jsonSink) Write(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = s.w.Write(line)
	return err
}

func (s *jsonSink) Close() error { return s.w.Close() }

type cefSink struct {
	mu      sync.Mutex
	w       io.WriteCloser
	vendor  string
	product string
	version string
}

func NewCEFFileSink(path, version string, rot RotationConfig) (Sink, error) {
	w, err := openFileSink(path, rot)
	if err != nil {
		return nil, err
	}
	if version == "" {
		version = "dev"
	}
	return &cefSink{
		w:       w,
		vendor:  "Anthropic",
		product: "Firefik",
		version: version,
	}, nil
}

func (s *cefSink) Write(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	severity := 3
	switch ev.Action {
	case "remove":
		severity = 5
	case "reconcile":
		severity = 2
	}
	name := ev.Action
	ips := strings.Join(ev.ContainerIPs, ",")

	extras := appendKV(nil,
		"src", ips,
		"cs1", string(ev.Source),
		"cs1Label", "Source",
		"cs2", ev.ContainerID,
		"cs2Label", "ContainerID",
		"cs3", ev.ContainerName,
		"cs3Label", "ContainerName",
		"cs4", ev.DefaultPolicy,
		"cs4Label", "DefaultPolicy",
		"cn1", fmt.Sprintf("%d", ev.RuleSets),
		"cn1Label", "RuleSetCount",
		"rt", ev.Timestamp.UTC().Format(time.RFC3339),
	)

	line := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s\n",
		cefEscapeHeader(s.vendor),
		cefEscapeHeader(s.product),
		cefEscapeHeader(s.version),
		cefEscapeHeader(ev.Action),
		cefEscapeHeader(name),
		severity,
		strings.Join(extras, " "),
	)
	_, err := s.w.Write([]byte(line))
	return err
}

func (s *cefSink) Close() error { return s.w.Close() }

func kv(k, v string) string {
	if v == "" {
		return ""
	}
	return k + "=" + cefEscapeExtension(v)
}

func appendKV(dst []string, kvs ...string) []string {
	for i := 0; i+1 < len(kvs); i += 2 {
		if entry := kv(kvs[i], kvs[i+1]); entry != "" {
			dst = append(dst, entry)
		}
	}
	return dst
}

func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

func cefEscapeExtension(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
