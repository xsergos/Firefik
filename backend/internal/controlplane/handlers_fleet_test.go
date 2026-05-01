package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestHTTP_Agents_RequireAuth(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestHTTP_Agents_ListEmpty(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var out []agentDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty, got %d", len(out))
	}
}

func TestHTTP_Agents_ListAfterUpsert(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-a", Hostname: "host-a", Version: "0.1", Backend: "nftables", Chain: "FIREFIK"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var out []agentDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].InstanceID != "host-a" {
		t.Fatalf("unexpected list: %+v", out)
	}
	if out[0].Backend != "nftables" || out[0].Chain != "FIREFIK" {
		t.Fatalf("identity not propagated: %+v", out[0])
	}
}

func TestHTTP_Agent_NotFound(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents/missing", "", "secret")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d want 404", rec.Code)
	}
}

func TestHTTP_Agent_DetailWithSnapshot(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-a", Hostname: "host-a"}
	snap := AgentSnapshot{
		Agent: id,
		Containers: []ContainerState{
			{ID: "c1", Name: "nginx", Status: "running", FirewallStatus: "active", DefaultPolicy: "DROP", RuleSetCount: 2},
		},
		At: time.Now().UTC(),
	}
	if err := store.RecordSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents/host-a/snapshot", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var out agentDetailDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Agent.InstanceID != "host-a" {
		t.Fatalf("wrong agent: %+v", out.Agent)
	}
	if out.Snapshot == nil || len(out.Snapshot.Containers) != 1 || out.Snapshot.Containers[0].Name != "nginx" {
		t.Fatalf("wrong snapshot: %+v", out.Snapshot)
	}
}

func TestHTTP_Agent_DetailNoSnapshot(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-a", Hostname: "host-a"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents/host-a", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var out agentDetailDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Snapshot != nil {
		t.Fatalf("expected nil snapshot, got %+v", out.Snapshot)
	}
}

func TestHTTP_Agent_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents", "{}", "secret")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d want 405", rec.Code)
	}
}

func TestHTTP_AgentCommand_Disable(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-a", Hostname: "host-a"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	body := `{"action":"disable","container_id":"abc"}`
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", body, "secret")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var out commandResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.AgentID != "host-a" || out.Action != "disable" || out.ID == "" {
		t.Fatalf("unexpected response: %+v", out)
	}
	cmds, err := store.TakeCommands(context.Background(), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || cmds[0].Kind != CommandDisable || cmds[0].ContainerID != "abc" {
		t.Fatalf("unexpected enqueued cmds: %+v", cmds)
	}
}

func TestHTTP_AgentCommand_RejectsInvalidAction(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", `{"action":"explode"}`, "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400", rec.Code)
	}
}

func TestHTTP_AgentCommand_RequiresContainerID(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", `{"action":"disable"}`, "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400", rec.Code)
	}
}

func TestHTTP_AgentCommand_ReconcileNoContainerOK(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", `{"action":"reconcile"}`, "secret")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Agent_EmptyIDPath(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents/", "", "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Agent_PostToSnapshotNotAllowed(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/snapshot", "{}", "secret")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d want 405", rec.Code)
	}
}

func TestHTTP_Agent_UnknownSubresource(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/agents/host-a/strange", "", "secret")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d want 405", rec.Code)
	}
}

func TestHTTP_AgentCommand_Reconcile_Enqueued(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", `{"action":"token-rotate"}`, "secret")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	cmds, err := store.TakeCommands(context.Background(), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || cmds[0].Kind != CommandTokenRotate {
		t.Fatalf("unexpected enqueued cmds: %+v", cmds)
	}
}

func TestHTTP_AgentCommand_InvalidJSON(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if err := store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "host-a"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/host-a/commands", `{not-json`, "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400", rec.Code)
	}
}

func TestHTTP_AgentCommand_AgentNotFound(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/agents/no-such/commands", `{"action":"reconcile"}`, "secret")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d want 404", rec.Code)
	}
}

func TestNewCommandID_HexAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		id := newCommandID()
		if len(id) != 24 {
			t.Errorf("expected hex(12 bytes)=24 chars, got %d: %q", len(id), id)
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("non-hex char in %q", id)
			}
		}
		if seen[id] {
			t.Errorf("duplicate command id: %s", id)
		}
		seen[id] = true
	}
}

func TestAgentStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		lastSeen time.Time
		want     string
	}{
		{"unknown when zero", time.Time{}, "unknown"},
		{"healthy fresh", now.Add(-30 * time.Second), "healthy"},
		{"healthy edge", now.Add(-89 * time.Second), "healthy"},
		{"stale at 90s", now.Add(-95 * time.Second), "stale"},
		{"stale at 4m", now.Add(-4 * time.Minute), "stale"},
		{"dead at 5m", now.Add(-5 * time.Minute), "dead"},
		{"dead at 1h", now.Add(-time.Hour), "dead"},
	}
	for _, c := range cases {
		got := agentStatus(c.lastSeen, now)
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestAgentIDFromPath(t *testing.T) {
	cases := []struct {
		path string
		id   string
		sub  string
	}{
		{"/v1/agents/", "", ""},
		{"/v1/agents/abc", "abc", ""},
		{"/v1/agents/abc/", "abc", ""},
		{"/v1/agents/abc/snapshot", "abc", "snapshot"},
		{"/v1/agents/abc/snapshot/extra", "abc", "snapshot/extra"},
		{"/other", "", ""},
	}
	for _, c := range cases {
		id, sub := agentIDFromPath(c.path)
		if id != c.id || sub != c.sub {
			t.Errorf("path=%q got (%q,%q) want (%q,%q)", c.path, id, sub, c.id, c.sub)
		}
	}
}
