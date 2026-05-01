package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchAPIContainerIDsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			http.Error(w, "no auth", 401)
			return
		}
		w.Write([]byte(`[{"containerID":"abc123"},{"containerID":"def456"},{"containerID":""}]`))
	}))
	defer srv.Close()

	ids, err := fetchAPIContainerIDs(srv.URL, "t", 0)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(ids) != 2 || ids[0] != "abc123" {
		t.Errorf("ids=%v", ids)
	}
}

func TestFetchAPIContainerIDsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	if _, err := fetchAPIContainerIDs(srv.URL, "", 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAPIContainerIDsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	if _, err := fetchAPIContainerIDs(srv.URL, "", 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAPIContainerIDsUnixUnsupported(t *testing.T) {
	if _, err := fetchAPIContainerIDs("unix:///x", "", 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAPIContainerIDsBadURL(t *testing.T) {
	if _, err := fetchAPIContainerIDs("http://[::1]:0/", "", 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAPIContainerIDsBadRequest(t *testing.T) {
	if _, err := fetchAPIContainerIDs("://invalid", "", 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdDiffNoDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"containerID":"abc"}]`))
	}))
	defer srv.Close()

	fb := newFakeBackend()
	fb.listIDs = []string{"abc"}
	defer swapResolveBackend(fb, "iptables")()

	out := captureStdout(t, func() {
		if err := cmdDiff([]string{"--api", srv.URL}); err != nil {
			t.Fatalf("diff: %v", err)
		}
	})
	if !strings.Contains(out, "drift:    false") {
		t.Errorf("got %q", out)
	}
}

func TestCmdDiffDriftDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"containerID":"abc"}]`))
	}))
	defer srv.Close()

	fb := newFakeBackend()
	fb.listIDs = []string{"def"}
	defer swapResolveBackend(fb, "iptables")()

	_ = captureStdout(t, func() {
		err := cmdDiff([]string{"--api", srv.URL})
		if err == nil || !strings.Contains(err.Error(), "drift") {
			t.Errorf("expected drift error, got %v", err)
		}
	})
}

func TestCmdDiffJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()

	out := captureStdout(t, func() {
		if err := cmdDiff([]string{"--api", srv.URL, "--output", "json"}); err != nil {
			t.Fatalf("diff: %v", err)
		}
	})
	if !strings.Contains(out, `"drift": false`) {
		t.Errorf("got %q", out)
	}
}

func TestCmdDiffFetchErr(t *testing.T) {
	if err := cmdDiff([]string{"--api", "http://127.0.0.1:1/"}); err == nil {
		t.Fatal("expected fetch error")
	}
}

func TestCmdDiffResolveErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdDiff([]string{"--api", srv.URL}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdDiffListErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	fb := newFakeBackend()
	fb.listErr = errors.New("oops")
	defer swapResolveBackend(fb, "iptables")()
	if err := cmdDiff([]string{"--api", srv.URL}); err == nil {
		t.Fatal("expected error")
	}
}
