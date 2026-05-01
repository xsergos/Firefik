package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirEmpty(t *testing.T) {
	got, err := LoadDir("")
	if err != nil || got != nil {
		t.Errorf("got %v %v", got, err)
	}
}

func TestLoadDirMissing(t *testing.T) {
	got, err := LoadDir("/nonexistent/dir")
	if err != nil || got != nil {
		t.Errorf("got %v %v", got, err)
	}
}

func TestLoadDirSingleFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "p.policy")
	if err := os.WriteFile(tmp, []byte(`policy "p" { allow if port == 80 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = tmp
	got, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got["p"] == nil {
		t.Errorf("got %+v", got)
	}
}

func TestLoadDirMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.policy"), []byte(`policy "a" { allow if port == 80 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.policy"), []byte(`policy "b" { allow if port == 443 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte(`ignored`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, expected 2", len(got))
	}
}

func TestLoadDirDuplicatePolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.policy"), []byte(`policy "shared" { allow if port == 80 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.policy"), []byte(`policy "shared" { allow if port == 22 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Errorf("expected duplicate error")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile("/nonexistent/file.policy"); err == nil {
		t.Errorf("expected error")
	}
}

func TestLoadFileBadDSL(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.policy")
	if err := os.WriteFile(tmp, []byte(`{not a valid policy`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(tmp); err == nil {
		t.Errorf("expected parse error")
	}
}

func TestLoadDirParseError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.policy"), []byte(`{invalid`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Errorf("expected error")
	}
}
