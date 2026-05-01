package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fakeMMDB() []byte {
	return []byte("FIREFIK-FAKE-MMDB-PAYLOAD")
}

func fakeMMDBArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := fakeMMDB()
	hdr := &tar.Header{
		Name: "GeoLite2-Country_20260423/GeoLite2-Country.mmdb",
		Mode: 0o644,
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestResolveDownloadURL(t *testing.T) {
	cases := []struct {
		name        string
		src         SourceConfig
		wantContain string
		wantArchive bool
		wantErr     bool
	}{
		{"p3terx default", SourceConfig{Source: SourceP3TERX}, "P3TERX/GeoLite.mmdb", false, false},
		{"maxmind with key", SourceConfig{Source: SourceMaxmind, LicenseKey: "KEY"}, "maxmind.com", true, false},
		{"maxmind no key", SourceConfig{Source: SourceMaxmind}, "", false, true},
		{"url mmdb", SourceConfig{Source: SourceURL, DownloadURL: "https://m/x.mmdb"}, "x.mmdb", false, false},
		{"url tar.gz", SourceConfig{Source: SourceURL, DownloadURL: "https://m/x.tar.gz"}, "x.tar.gz", true, false},
		{"url tgz", SourceConfig{Source: SourceURL, DownloadURL: "https://m/x.tgz"}, "x.tgz", true, false},
		{"url missing", SourceConfig{Source: SourceURL}, "", false, true},
		{"unknown", SourceConfig{Source: "nope"}, "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, archived, err := resolveDownloadURL(tc.src)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (url=%q archived=%v)", url, archived)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(url, tc.wantContain) {
				t.Errorf("url %q missing %q", url, tc.wantContain)
			}
			if archived != tc.wantArchive {
				t.Errorf("archived=%v want %v", archived, tc.wantArchive)
			}
		})
	}
}

func TestValidateSources(t *testing.T) {
	cases := []struct {
		name    string
		src     SourceConfig
		wantErr bool
	}{
		{"p3terx ok", SourceConfig{Source: SourceP3TERX}, false},
		{"maxmind missing key", SourceConfig{Source: SourceMaxmind}, true},
		{"maxmind with key", SourceConfig{Source: SourceMaxmind, LicenseKey: "KEY"}, false},
		{"url missing", SourceConfig{Source: SourceURL}, true},
		{"url set", SourceConfig{Source: SourceURL, DownloadURL: "https://m/x.mmdb"}, false},
		{"unknown", SourceConfig{Source: "nope"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := NewUpdater(t.TempDir()+"/db.mmdb", tc.src, "0 0 * * *", noopLogger(), nil)
			err := u.validate()
			if tc.wantErr && err == nil {
				t.Fatalf("want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDownloadRawMMDB(t *testing.T) {
	body := fakeMMDB()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "firefik/") {
			t.Errorf("missing firefik UA: %q", ua)
		}
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
		Version:     "test",
	}, "0 0 * * *", noopLogger(), nil)

	changed, err := u.download()
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !changed {
		t.Fatal("first download should report changed=true")
	}
	got, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Error("mmdb body mismatch")
	}
	if got := u.loadETag(); got != `"abc123"` {
		t.Errorf("etag = %q", got)
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
}
func TestDownloadArchive(t *testing.T) {
	archive := fakeMMDBArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.tar.gz",
		Version:     "test",
	}, "0 0 * * *", noopLogger(), nil)

	changed, err := u.download()
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !changed {
		t.Fatal("first download should report changed=true")
	}
	got, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fakeMMDB()) {
		t.Error("mmdb body mismatch after tar extraction")
	}
}

func TestDownloadETagNotModified(t *testing.T) {
	body := fakeMMDB()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if inm := r.Header.Get("If-None-Match"); inm == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
		Version:     "test",
	}, "0 0 * * *", noopLogger(), nil)

	if changed, err := u.download(); err != nil || !changed {
		t.Fatalf("first download: changed=%v err=%v", changed, err)
	}
	if changed, err := u.download(); err != nil || changed {
		t.Fatalf("second download should be 304: changed=%v err=%v", changed, err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
}

func TestDownloadHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	u := NewUpdater(filepath.Join(t.TempDir(), "db.mmdb"), SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
	}, "0 0 * * *", noopLogger(), nil)

	_, err := u.download()
	if err == nil {
		t.Fatal("want error on 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error doesn't mention 503: %v", err)
	}
}

func TestDownloadRedirectCap(t *testing.T) {
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	u := NewUpdater(filepath.Join(t.TempDir(), "db.mmdb"), SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/loop",
	}, "0 0 * * *", noopLogger(), nil)
	_, err := u.download()
	if err == nil {
		t.Fatal("want error on infinite redirect")
	}
}

func TestResolveMaxmindMissingKey(t *testing.T) {
	_, _, err := resolveDownloadURL(SourceConfig{Source: SourceMaxmind})
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, err) {
		t.Fatal("error chain broken")
	}
}

func TestDownloadIfMissing_AlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dbPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
	}, "0 0 * * *", noopLogger(), nil)
	if err := u.downloadIfMissing(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected no http calls when file exists, got %d", calls)
	}
}

func TestDownloadIfMissing_FetchSucceeds(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buildStubMMDB())
	}))
	defer srv.Close()

	var got *DB
	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
	}, "0 0 * * *", noopLogger(), func(d *DB) { got = d })
	if err := u.downloadIfMissing(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == nil {
		t.Fatalf("onUpdate should have fired")
	}
	got.Close()
}

func TestDownloadIfMissing_FetchFails(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u := NewUpdater(dbPath, SourceConfig{
		Source:      SourceURL,
		DownloadURL: srv.URL + "/db.mmdb",
	}, "0 0 * * *", noopLogger(), nil)
	if err := u.downloadIfMissing(); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestReloadDB_HappyPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dbPath, buildStubMMDB(), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	u := NewUpdater(dbPath, SourceConfig{Source: SourceP3TERX}, "0 0 * * *", noopLogger(), func(d *DB) {
		called = true
		if d == nil {
			t.Fatalf("nil db passed to onUpdate")
		}
		d.Close()
	})
	u.reloadDB()
	if !called {
		t.Fatal("onUpdate should have fired")
	}
}

func TestReloadDB_MissingFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "missing.mmdb")
	called := false
	u := NewUpdater(dbPath, SourceConfig{Source: SourceP3TERX}, "0 0 * * *", noopLogger(), func(d *DB) {
		called = true
	})
	u.reloadDB()
	if called {
		t.Fatal("onUpdate must not fire when reload fails")
	}
}

func TestReloadDB_OpenError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dbPath, []byte("not-an-mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	u := NewUpdater(dbPath, SourceConfig{Source: SourceP3TERX}, "0 0 * * *", noopLogger(), func(d *DB) {
		called = true
	})
	u.reloadDB()
	if called {
		t.Fatal("onUpdate must not fire when reload fails to open")
	}
}

func TestRun_InvalidSource(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	u := NewUpdater(dbPath, SourceConfig{Source: "nope"}, "0 0 * * *", noopLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := u.Run(ctx); err != nil {
		t.Fatalf("Run with invalid source should return nil, got: %v", err)
	}
}

func TestRun_HappyPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dbPath, buildStubMMDB(), 0o644); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(dbPath, SourceConfig{Source: SourceP3TERX}, "0 0 * * *", noopLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if err := u.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRun_BadCron(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db.mmdb")
	if err := os.WriteFile(dbPath, buildStubMMDB(), 0o644); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(dbPath, SourceConfig{Source: SourceP3TERX}, "not a cron", noopLogger(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := u.Run(ctx); err == nil {
		t.Fatal("expected error for invalid cron")
	}
}
