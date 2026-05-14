package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleFleetRules_DecodesRuleSetsFromInternalLabel(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-a", Hostname: "host-a"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ruleSetsJSON, _ := json.Marshal([]map[string]any{
		{"name": "web", "ports": []int{80, 443}, "allowlist": []string{"10.0.0.0/8"}},
	})
	snap := AgentSnapshot{
		Agent: id,
		At:    time.Now().UTC(),
		Containers: []ContainerState{{
			ID:             "abc123",
			Name:           "nginx",
			Status:         "running",
			FirewallStatus: "active",
			DefaultPolicy:  "DROP",
			Labels: map[string]string{
				"firefik.enable": "true",
				RuleSetsLabelKey: string(ruleSetsJSON),
			},
			RuleSetCount: 1,
		}},
	}
	if err := store.RecordSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/rules", nil)
	srv.handleFleetRules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var out []fleetRuleDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if len(out[0].RuleSets) != 1 {
		t.Fatalf("expected rule sets to be decoded from label, got %v", out[0].RuleSets)
	}
}

func TestHandleFleetRules_MissingRuleSetsYieldsEmptyArray(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-b", Hostname: "host-b"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	snap := AgentSnapshot{
		Agent: id,
		At:    time.Now().UTC(),
		Containers: []ContainerState{{
			ID:             "def456",
			Name:           "db",
			Status:         "running",
			FirewallStatus: "active",
			RuleSetCount:   2,
		}},
	}
	if err := store.RecordSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/rules", nil)
	srv.handleFleetRules(rec, req)
	var out []fleetRuleDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].RuleSets == nil || len(out[0].RuleSets) != 0 {
		t.Fatalf("missing label should still produce empty (not null) array: %+v", out)
	}
}

func TestHandleFleetContainers_StripsInternalRuleSetsLabel(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-c", Hostname: "host-c"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	snap := AgentSnapshot{
		Agent: id,
		At:    time.Now().UTC(),
		Containers: []ContainerState{{
			ID: "ghi789", Name: "api", Status: "running",
			Labels: map[string]string{
				"firefik.enable": "true",
				RuleSetsLabelKey: `[{"x":1}]`,
			},
		}},
	}
	if err := store.RecordSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/containers", nil)
	srv.handleFleetContainers(rec, req)
	var out []fleetContainerDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if _, present := out[0].Labels[RuleSetsLabelKey]; present {
		t.Fatalf("internal label leaked into panel containers response: %+v", out[0].Labels)
	}
	if out[0].Labels["firefik.enable"] != "true" {
		t.Fatalf("user labels stripped: %+v", out[0].Labels)
	}
	if len(out[0].RuleSets) != 1 {
		t.Fatalf("ruleSets should be decoded from the (now-stripped) label: %v", out[0].RuleSets)
	}
}

func TestDecodeRuleSetsFromLabels_BadJSON(t *testing.T) {
	got := decodeRuleSetsFromLabels(map[string]string{RuleSetsLabelKey: "{not-json"})
	if got == nil || len(got) != 0 {
		t.Fatalf("malformed JSON should fall back to empty array, got %+v", got)
	}
}

func TestStripInternalLabels_NoMutationWhenAbsent(t *testing.T) {
	in := map[string]string{"a": "1", "b": "2"}
	out := stripInternalLabels(in)
	if len(out) != 2 || out["a"] != "1" {
		t.Fatalf("absent key should be a no-op pass-through, got %+v", out)
	}
}
