package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdExplainMissingContainer(t *testing.T) {
	err := cmdExplain([]string{"--policy", "p"})
	if err == nil || !strings.Contains(err.Error(), "--container is required") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdExplainMissingPolicy(t *testing.T) {
	err := cmdExplain([]string{"--container", "abc"})
	if err == nil || !strings.Contains(err.Error(), "--policy") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdExplainPolicyFileNotFound(t *testing.T) {
	err := cmdExplain([]string{"--container", "abc", "--policy-file", "/nonexistent/path"})
	if err == nil || !strings.Contains(err.Error(), "read policy file") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdExplainSimulateOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer x" {
			http.Error(w, "auth", 401)
			return
		}
		w.Write([]byte(`{"policy":"web","container":"abc","defaultPolicy":"deny","ruleSets":[{"name":"web","ports":[80],"protocol":"tcp"}]}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := cmdExplain([]string{"--api", srv.URL, "--policy", "web", "--container", "abc", "--token", "x"}); err != nil {
			t.Fatalf("explain: %v", err)
		}
	})
	if !strings.Contains(out, "policy:        web") {
		t.Errorf("got %q", out)
	}
	if !strings.Contains(out, "rule-sets:     1") {
		t.Errorf("got %q", out)
	}
}

func TestCmdExplainPolicyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "policy.dsl")
	if err := os.WriteFile(tmp, []byte("allow tcp 80"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"policy":"inline","ruleSets":[]}`))
	}))
	defer srv.Close()

	_ = captureStdout(t, func() {
		if err := cmdExplain([]string{"--api", srv.URL, "--policy-file", tmp, "--container", "abc"}); err != nil {
			t.Fatalf("explain: %v", err)
		}
	})
}

func TestCmdExplainHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	err := cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc"})
	if err == nil || !strings.Contains(err.Error(), "simulate returned 500") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdExplainBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	err := cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc"})
	if err == nil || !strings.Contains(err.Error(), "decode simulate response") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdExplainTransportError(t *testing.T) {
	err := cmdExplain([]string{"--api", "http://127.0.0.1:1", "--policy", "p", "--container", "abc"})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestCmdExplainTextWithRuleSetDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"policy":"p","ruleSets":[{"name":"r","ports":[80,443],"protocol":"tcp","allowlist":["10.0.0.0/8"],"blocklist":["1.2.3.4"],"geoAllow":["RU"],"geoBlock":["KP"],"log":true,"logPrefix":"FW:"}],"warnings":["w1"],"errors":["e1"]}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc"}); err != nil {
			t.Fatalf("explain: %v", err)
		}
	})
	for _, want := range []string{"ports:", "allowlist:", "blocklist:", "geoallow:", "geoblock:", "log:"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output: %s", want, out)
		}
	}
}

func TestCmdExplainPacketTraceJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"policy":"p","defaultPolicy":"deny","ruleSets":[{"name":"r","ports":[80],"protocol":"tcp"}]}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc", "--packet", "tcp 1.2.3.4:33221 -> :80", "--output", "json"}); err != nil {
			t.Fatalf("explain: %v", err)
		}
	})
	if !strings.Contains(out, `"firstMatch"`) {
		t.Errorf("expected firstMatch trace in json: %s", out)
	}
}

func TestCmdExplainPacketTraceText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"policy":"p","defaultPolicy":"deny","ruleSets":[{"name":"r","ports":[80],"protocol":"tcp"}]}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc", "--packet", "tcp 1.2.3.4:33221 -> :80"}); err != nil {
			t.Fatalf("explain: %v", err)
		}
	})
	if !strings.Contains(out, "matched rule-set 0") {
		t.Errorf("got %q", out)
	}
}

func TestCmdExplainPacketTraceNoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"policy":"p","defaultPolicy":"deny","ruleSets":[{"name":"r","ports":[443],"protocol":"tcp"}]}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		_ = cmdExplain([]string{"--api", srv.URL, "--policy", "p", "--container", "abc", "--packet", "tcp 1.2.3.4:33221 -> :80"})
	})
	if !strings.Contains(out, "no rule-set matched") {
		t.Errorf("got %q", out)
	}
}

func TestFirstMatchFromPacket(t *testing.T) {
	sets := []simulateRuleSet{
		{Name: "a", Ports: []int{443}, Protocol: "tcp"},
		{Name: "b", Ports: []int{80}, Protocol: "tcp"},
		{Name: "c", Protocol: "udp"},
	}
	tr, err := firstMatchFromPacket("tcp 1.1.1.1:1 -> :80", sets)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tr == nil || tr.Name != "b" {
		t.Errorf("unexpected: %+v", tr)
	}

	if _, err := firstMatchFromPacket("tcp", sets); err == nil {
		t.Errorf("expected parse error")
	}
	if _, err := firstMatchFromPacket("tcp 1.1.1.1:1 -> 1.1.1.1:80", sets); err == nil {
		t.Errorf("expected parse error for missing leading colon")
	}
	if _, err := firstMatchFromPacket("tcp 1.1.1.1:1 -> :abc", sets); err == nil {
		t.Errorf("expected parse error for non-numeric port")
	}

	tr, err = firstMatchFromPacket("tcp 1.1.1.1:1 -> :22", sets)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tr != nil {
		t.Errorf("expected nil match, got %+v", tr)
	}

	wide := []simulateRuleSet{{Name: "any", Protocol: ""}}
	tr, err = firstMatchFromPacket("tcp 1.1.1.1:1 -> :22", wide)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tr == nil || tr.Name != "any" {
		t.Errorf("expected catch-all match, got %+v", tr)
	}
}
