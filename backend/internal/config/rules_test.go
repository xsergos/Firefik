package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesFile_EmptyPath(t *testing.T) {
	rf, err := LoadRulesFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rf.Rules) != 0 {
		t.Fatalf("expected empty rules, got %v", rf.Rules)
	}
}

func TestLoadRulesFile_MissingFile(t *testing.T) {

	rf, err := LoadRulesFile(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("missing file should not error, got: %v", err)
	}
	if len(rf.Rules) != 0 {
		t.Fatalf("expected empty result for missing file, got %v", rf.Rules)
	}
}

func TestLoadRulesFile_EmptyContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yml")
	if err := os.WriteFile(path, []byte("   \n\n  \t\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rf, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rf.Rules) != 0 {
		t.Fatalf("expected empty rules, got %v", rf.Rules)
	}
}

func TestLoadRulesFile_Valid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yml")
	content := `rules:
  - container: web
    name: web-http
    ports:
      - 80
      - 443
    allowlist:
      - 10.0.0.0/8
      - 192.168.1.1
    blocklist:
      - 1.2.3.4
    defaultPolicy: DROP
    protocol: tcp
    profile: strict
  - container: db
    name: db-pg
    ports:
      - 5432
    defaultPolicy: RETURN
    protocol: tcp
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	rf, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rf.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rf.Rules))
	}

	r0 := rf.Rules[0]
	if r0.Container != "web" || r0.Name != "web-http" {
		t.Errorf("r0 identity: %+v", r0)
	}
	if len(r0.Ports) != 2 || r0.Ports[0] != 80 || r0.Ports[1] != 443 {
		t.Errorf("r0 ports: %v", r0.Ports)
	}
	if len(r0.Allowlist) != 2 {
		t.Errorf("r0 allowlist: %v", r0.Allowlist)
	}
	if r0.DefaultPolicy != "DROP" {
		t.Errorf("r0 defaultPolicy: %q", r0.DefaultPolicy)
	}
	if r0.Protocol != "tcp" {
		t.Errorf("r0 protocol: %q", r0.Protocol)
	}
	if r0.Profile != "strict" {
		t.Errorf("r0 profile: %q", r0.Profile)
	}

	r1 := rf.Rules[1]
	if r1.Container != "db" || r1.Name != "db-pg" {
		t.Errorf("r1 identity: %+v", r1)
	}
	if len(r1.Ports) != 1 || r1.Ports[0] != 5432 {
		t.Errorf("r1 ports: %v", r1.Ports)
	}
}

func TestLoadRulesFile_Malformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yml")

	if err := os.WriteFile(path, []byte("rules: [not-an-object: value"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadRulesFile(path)
	if err == nil {
		t.Fatal("expected parse error for malformed yaml, got nil")
	}
}

func TestLoadRulesFile_ReadError(t *testing.T) {

	dir := t.TempDir()
	dirPath := filepath.Join(dir, "rules-is-a-dir")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, err := LoadRulesFile(dirPath)
	if err == nil {
		t.Fatal("expected error when path is a directory")
	}
}

func TestParseFileAllowlist(t *testing.T) {
	entries := []string{
		"10.0.0.0/8",
		"192.168.1.1",
		"::1",
		"  10.1.1.0/24 ",
		"",
		"not-an-ip",
	}
	nets, errs := ParseFileAllowlist(entries)
	if len(nets) != 4 {
		t.Errorf("expected 4 valid nets, got %d (%v)", len(nets), nets)
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d (%v)", len(errs), errs)
	}
}
