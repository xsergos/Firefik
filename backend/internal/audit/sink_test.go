package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

type captureSink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	writes  int
	wantErr error
}

func (c *captureSink) Write(ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.wantErr != nil {
		return c.wantErr
	}
	return json.NewEncoder(&c.buf).Encode(ev)
}

func (c *captureSink) Close() error { return nil }

func TestJSONFileSink_Stdout(t *testing.T) {
	for _, path := range []string{"", "-"} {
		s, err := NewJSONFileSink(path, RotationConfig{})
		if err != nil {
			t.Fatalf("NewJSONFileSink(%q): %v", path, err)
		}
		if err := s.Write(Event{Action: "apply", Timestamp: time.Unix(0, 0).UTC()}); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
}

func TestMultiSink_FanOut(t *testing.T) {
	a := &captureSink{}
	b := &captureSink{}
	m := NewMultiSink(nil, a, b)
	defer m.Close()

	if err := m.Write(Event{Action: "apply"}); err != nil {
		t.Fatalf("multi write: %v", err)
	}
	if a.writes != 1 || b.writes != 1 {
		t.Fatalf("fan-out failed: a=%d b=%d", a.writes, b.writes)
	}
}

func TestMultiSink_ContinuesOnError(t *testing.T) {
	failing := &captureSink{wantErr: errors.New("disk full")}
	ok := &captureSink{}
	m := NewMultiSink(nil, failing, ok)
	defer m.Close()
	if err := m.Write(Event{Action: "apply"}); err != nil {
		t.Fatalf("multi write should not propagate sink errors: %v", err)
	}
	if ok.writes != 1 {
		t.Fatalf("non-failing sink should still receive events, got %d", ok.writes)
	}
}

func TestCEFEscape_Header(t *testing.T) {
	got := cefEscapeHeader(`prod|build\42`)
	want := `prod\|build\\42`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCEFEscape_Extension(t *testing.T) {
	got := cefEscapeExtension("key=val\nnext")
	want := `key\=val\nnext`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

type nopWriter struct{ io.Writer }

func (nopWriter) Close() error { return nil }

func TestCEFSink_RenderShape(t *testing.T) {
	buf := &bytes.Buffer{}
	sink := &cefSink{w: nopWriter{Writer: buf}, vendor: "Anthropic", product: "Firefik", version: "test"}
	ev := Event{
		Timestamp:     time.Unix(0, 0).UTC(),
		Action:        "apply",
		Source:        SourceAPI,
		ContainerID:   "abcdef012345",
		ContainerName: "nginx",
		ContainerIPs:  []string{"10.0.0.2"},
		RuleSets:      2,
		DefaultPolicy: "DROP",
	}
	if err := sink.Write(ev); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "CEF:0|Anthropic|Firefik|test|apply|apply|") {
		t.Fatalf("unexpected CEF prefix: %q", out)
	}
	if !strings.Contains(out, "cs2=abcdef012345") {
		t.Fatalf("CEF missing container id: %q", out)
	}
}

func TestJSONFileSink_RotationByMaxSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := NewJSONFileSink(path, RotationConfig{MaxSizeMB: 1, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewJSONFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	payload := strings.Repeat("x", 2048)
	for i := 0; i < 600; i++ {
		if err := s.Write(Event{Action: "apply", Metadata: map[string]string{"pad": payload}}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least one rotated backup, dir entries: %v", entries)
	}
}

func TestJSONFileSink_DefaultRotationEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := NewJSONFileSink(path, RotationConfig{MaxSizeMB: 100, MaxBackups: 5, MaxAgeDays: 30, Compress: true})
	if err != nil {
		t.Fatalf("NewJSONFileSink: %v", err)
	}
	defer s.Close()
	js, ok := s.(*jsonSink)
	if !ok {
		t.Fatalf("sink is not *jsonSink: %T", s)
	}
	if _, isLumber := js.w.(*lumberjack.Logger); !isLumber {
		t.Fatalf("expected lumberjack.Logger under the hood, got %T", js.w)
	}
}

func TestJSONFileSink_OptOutWhenMaxSizeZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := NewJSONFileSink(path, RotationConfig{MaxSizeMB: 0})
	if err != nil {
		t.Fatalf("NewJSONFileSink: %v", err)
	}
	defer s.Close()
	js, ok := s.(*jsonSink)
	if !ok {
		t.Fatalf("sink is not *jsonSink: %T", s)
	}
	if _, isFile := js.w.(*os.File); !isFile {
		t.Fatalf("expected *os.File under the hood when rotation disabled, got %T", js.w)
	}
}
