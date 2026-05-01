package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "templates.yml")
	if err := os.WriteFile(path, []byte(`
templates:
  - name: web-public
    description: HTTP + HTTPS from the internet
    ports: [80, 443]
    protocol: tcp
    ratelimit: 100/s
  - name: db-internal
    ports: [5432]
    allowlistNetworks:
      - backend-network
`), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := LoadTemplates(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 templates, got %d", len(got))
	}
	web, ok := got["web-public"]
	if !ok {
		t.Fatalf("web-public missing")
	}
	if len(web.Ports) != 2 || web.Ports[0] != 80 || web.Ports[1] != 443 {
		t.Errorf("ports = %v", web.Ports)
	}
	if web.Version == "" || len(web.Version) != 16 {
		t.Errorf("version should be 16 hex chars, got %q", web.Version)
	}
}

func TestCanonicalVersionStable(t *testing.T) {
	a := RuleTemplate{Name: "x", Ports: []uint16{443, 80}, Allowlist: []string{"10.0.0.0/8", "192.168.0.0/16"}}
	b := RuleTemplate{Name: "x", Ports: []uint16{80, 443}, Allowlist: []string{"192.168.0.0/16", "10.0.0.0/8"}}
	if canonicalVersion(a) != canonicalVersion(b) {
		t.Errorf("canonical version should be order-independent\n  a=%s\n  b=%s",
			canonicalVersion(a), canonicalVersion(b))
	}
}

func TestResolveTemplateNames(t *testing.T) {
	cases := map[string][]string{
		"":                           nil,
		"web-public":                 {"web-public"},
		"web-public,db-internal":     {"web-public", "db-internal"},
		" web-public , db-internal ": {"web-public", "db-internal"},
		"a,a,b":                      {"a", "b"},
	}
	for in, want := range cases {
		got := ResolveTemplateNames(in)
		if len(got) != len(want) {
			t.Errorf("%q: got %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q: got %v, want %v", in, got, want)
				break
			}
		}
	}
}

func TestDuplicateTemplateNameRejected(t *testing.T) {
	_, err := parseTemplateBytes([]byte(`
templates:
  - {name: dup, ports: [80]}
  - {name: dup, ports: [443]}
`))
	if err == nil {
		t.Fatal("duplicate name should produce error")
	}
}

func TestTemplateBundleAbsentIsNil(t *testing.T) {
	got, err := LoadTemplates("/does/not/exist.yml")
	if err != nil || got != nil {
		t.Errorf("missing path: want (nil, nil), got (%v, %v)", got, err)
	}
	got, err = LoadTemplates("")
	if err != nil || got != nil {
		t.Errorf("empty path: want (nil, nil), got (%v, %v)", got, err)
	}
}
