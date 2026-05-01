package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRestore_Roundtrip(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	dbPath := filepath.Join(srcDir, "firefik.db")
	caDir := filepath.Join(srcDir, "ca")
	writeFile(t, dbPath, []byte("fake-sqlite-bytes"))
	writeFile(t, filepath.Join(caDir, "root.crt"), []byte("ROOT"))
	writeFile(t, filepath.Join(caDir, "issuing", "ca.key"), []byte("KEY"))

	out := filepath.Join(srcDir, "out.tar.gz")
	if err := runBackup([]string{"--db", dbPath, "--ca-state-dir", caDir, "--out", out}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output missing: %v", err)
	}

	dstDB := filepath.Join(dstDir, "firefik.db")
	dstCA := filepath.Join(dstDir, "ca")
	if err := runRestore([]string{"--from", out, "--db", dstDB, "--ca-state-dir", dstCA}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	dbData, err := os.ReadFile(dstDB)
	if err != nil {
		t.Fatalf("read restored db: %v", err)
	}
	if string(dbData) != "fake-sqlite-bytes" {
		t.Errorf("db mismatch: %q", dbData)
	}
	rootData, err := os.ReadFile(filepath.Join(dstCA, "root.crt"))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if string(rootData) != "ROOT" {
		t.Errorf("root mismatch: %q", rootData)
	}
	keyData, err := os.ReadFile(filepath.Join(dstCA, "issuing", "ca.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyData) != "KEY" {
		t.Errorf("key mismatch: %q", keyData)
	}
}

func TestBackup_MissingOut(t *testing.T) {
	if err := runBackup(nil); err == nil {
		t.Fatal("expected error when --out missing")
	}
}

func TestBackup_DBNotFound(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.tar.gz")
	err := runBackup([]string{"--db", filepath.Join(t.TempDir(), "absent.db"), "--out", out, "--ca-state-dir", ""})
	if err == nil {
		t.Fatal("expected error for missing db")
	}
}

func TestRestore_MissingFrom(t *testing.T) {
	if err := runRestore(nil); err == nil {
		t.Fatal("expected error when --from missing")
	}
}

func TestRestore_DryRunValidatesManifest(t *testing.T) {
	srcDir := t.TempDir()
	dbPath := filepath.Join(srcDir, "firefik.db")
	writeFile(t, dbPath, []byte("payload"))
	out := filepath.Join(srcDir, "out.tar.gz")
	if err := runBackup([]string{"--db", dbPath, "--ca-state-dir", "", "--out", out}); err != nil {
		t.Fatal(err)
	}
	if err := runRestore([]string{"--from", out, "--dry-run"}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
}

func TestRestore_RejectsBadMagic(t *testing.T) {
	src := filepath.Join(t.TempDir(), "bad.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	mf := backupManifest{Magic: "not-firefik", SchemaVersion: 1}
	body, _ := json.Marshal(mf)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0o600})
	tw.Write(body)
	tw.Close()
	gz.Close()
	f.Close()

	dst := filepath.Join(t.TempDir(), "db")
	err = runRestore([]string{"--from", src, "--db", dst, "--ca-state-dir", ""})
	if err == nil || !strings.Contains(err.Error(), "not a firefik backup") {
		t.Fatalf("expected magic mismatch, got %v", err)
	}
}

func TestRestore_RejectsNewerSchema(t *testing.T) {
	src := filepath.Join(t.TempDir(), "new.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	mf := backupManifest{Magic: backupMagic, SchemaVersion: 99}
	body, _ := json.Marshal(mf)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0o600})
	tw.Write(body)
	tw.Close()
	gz.Close()
	f.Close()

	err = runRestore([]string{"--from", src, "--db", filepath.Join(t.TempDir(), "x"), "--ca-state-dir", ""})
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("expected schema mismatch, got %v", err)
	}
}

func TestReadManifest_NotGzip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "raw.txt")
	writeFile(t, p, []byte("not a gzip file at all"))
	if _, err := readManifest(p); err == nil {
		t.Fatal("expected gzip error")
	}
}

func TestReadManifest_NoManifest(t *testing.T) {
	src := filepath.Join(t.TempDir(), "empty.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "other.txt", Size: 0, Mode: 0o600})
	tw.Close()
	gz.Close()
	f.Close()
	if _, err := readManifest(src); err == nil {
		t.Fatal("expected manifest-missing error")
	}
}

func TestBackup_BadFlag(t *testing.T) {
	if err := runBackup([]string{"--bogus"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestRestore_BadFlag(t *testing.T) {
	if err := runRestore([]string{"--bogus"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestRestore_FromMissingFile(t *testing.T) {
	if err := runRestore([]string{"--from", "/no/such/file"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestWriteStreamSuccess(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.bin")
	if err := writeStream(strings.NewReader("hello"), dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestWriteStreamCreateError(t *testing.T) {
	if err := writeStream(strings.NewReader("x"), "/no/such/path/dir/file"); err == nil {
		t.Errorf("expected error")
	}
}

func TestCloseAllNoCloser(t *testing.T) {
	if err := closeAll(); err != nil {
		t.Errorf("err: %v", err)
	}
}

type errCloser struct{ err error }

func (e errCloser) Close() error { return e.err }

func TestCloseAllReturnsFirstError(t *testing.T) {
	want := os.ErrPermission
	got := closeAll(errCloser{}, errCloser{err: want}, errCloser{err: os.ErrInvalid})
	if got != want {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestBackup_SHA256Recorded(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")
	writeFile(t, dbPath, []byte("hello"))
	out := filepath.Join(dir, "out.tar.gz")
	if err := runBackup([]string{"--db", dbPath, "--ca-state-dir", "", "--out", out}); err != nil {
		t.Fatal(err)
	}
	mf, err := readManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("hello"))
	if mf.DBSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha mismatch: %s", mf.DBSHA256)
	}
}
