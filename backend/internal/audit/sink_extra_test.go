package audit

import (
	"path/filepath"
	"testing"
)

func TestNewCEFFileSinkStdout(t *testing.T) {
	for _, p := range []string{"", "-"} {
		s, err := NewCEFFileSink(p, "v1", RotationConfig{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}
}

func TestNewCEFFileSinkFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.cef")
	s, err := NewCEFFileSink(p, "v1", RotationConfig{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if err := s.Write(Event{Action: "apply", ContainerID: "abc"}); err != nil {
		t.Errorf("write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewCEFFileSinkDefaultsVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.cef")
	s, err := NewCEFFileSink(p, "", RotationConfig{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs := s.(*cefSink)
	if cs.version != "dev" {
		t.Errorf("version = %q", cs.version)
	}
	_ = s.Close()
}

func TestKVOmitsEmpty(t *testing.T) {
	if got := kv("k", ""); got != "" {
		t.Errorf("got %q", got)
	}
	if got := kv("k", "v"); got != "k=v" {
		t.Errorf("got %q", got)
	}
}

func TestNewJSONFileSinkOpenError(t *testing.T) {
	if _, err := NewJSONFileSink("/nonexistent/path/file.jsonl", RotationConfig{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewCEFFileSinkOpenError(t *testing.T) {
	if _, err := NewCEFFileSink("/nonexistent/path/file.cef", "v", RotationConfig{}); err == nil {
		t.Fatal("expected error")
	}
}
