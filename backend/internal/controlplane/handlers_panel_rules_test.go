package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHandleFleetContainers_NormalisesEmptyDefaultPolicy(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	id := AgentIdentity{InstanceID: "host-norm", Hostname: "host-norm"}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	snap := AgentSnapshot{
		Agent: id,
		At:    time.Now().UTC(),
		Containers: []ContainerState{{
			ID:            "rehydrate-id",
			Name:          "app",
			Status:        "running",
			DefaultPolicy: "",
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
	if out[0].DefaultPolicy != "RETURN" {
		t.Fatalf("empty DefaultPolicy should be normalised to RETURN, got %q", out[0].DefaultPolicy)
	}
}

func TestSanitizeRuleSets_FillsNilSlices(t *testing.T) {
	in := []any{
		map[string]any{"name": "rs1"},
		map[string]any{"name": "rs2", "ports": nil, "allowlist": nil, "blocklist": nil},
		map[string]any{"name": "rs3", "ports": []any{float64(80)}, "allowlist": []any{"10/8"}, "blocklist": []any{"1.2.3.4"}},
	}
	out := sanitizeRuleSets(in)
	for i, raw := range out {
		m := raw.(map[string]any)
		for _, k := range []string{"ports", "allowlist", "blocklist"} {
			v, ok := m[k]
			if !ok || v == nil {
				t.Errorf("row %d missing %s after sanitize: %+v", i, k, m)
			}
		}
	}
}

func TestHandlePolicy_PostValidateAtRoot(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/validate", strings.NewReader(`{"dsl":"allow tcp from 10.0.0.0/8 to port 22"}`))
	srv.handlePolicy(rec, req)
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/policies/validate should not return 405: body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
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

func TestHandleFleetRules_AppendsSyntheticHostRow(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	hostRulesJSON, _ := json.Marshal(HostRulesPayload{
		Default: "DROP",
		Rules: []HostRuleDTO{
			{Name: "ssh", Protocol: "tcp", Ports: []uint16{22}, Allowlist: []string{"10.0.0.0/8"}},
		},
	})
	id := AgentIdentity{
		InstanceID: "host-host",
		Hostname:   "host-host",
		Labels:     map[string]string{HostRulesLabelKey: string(hostRulesJSON)},
	}
	if err := store.UpsertAgent(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSnapshot(context.Background(), AgentSnapshot{Agent: id, At: time.Now().UTC()}); err != nil {
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
		t.Fatalf("expected 1 synthetic host row, got %d: %+v", len(out), out)
	}
	if out[0].ContainerID != "(host)" || out[0].ContainerName != "host firewall" {
		t.Fatalf("synthetic row not labelled correctly: %+v", out[0])
	}
	if out[0].DefaultPolicy != "DROP" {
		t.Fatalf("host default not propagated: %+v", out[0])
	}
	if len(out[0].RuleSets) != 1 {
		t.Fatalf("expected 1 host rule, got %v", out[0].RuleSets)
	}
}

func TestDecodeHostRulesFromLabels_BadJSON(t *testing.T) {
	_, ok := decodeHostRulesFromLabels(map[string]string{HostRulesLabelKey: "{not json"})
	if ok {
		t.Fatal("bad JSON should yield ok=false")
	}
}

func TestDecodeHostRulesFromLabels_EmptyPayload(t *testing.T) {
	_, ok := decodeHostRulesFromLabels(map[string]string{HostRulesLabelKey: `{"default":"","rules":[]}`})
	if ok {
		t.Fatal("empty payload (no default, no rules) should yield ok=false")
	}
}

func TestStripInternalLabels_StripsHostRulesKey(t *testing.T) {
	in := map[string]string{"firefik.enable": "true", HostRulesLabelKey: `{"x":1}`, RuleSetsLabelKey: `[{}]`}
	out := stripInternalLabels(in)
	if _, present := out[HostRulesLabelKey]; present {
		t.Fatalf("host_rules label leaked: %+v", out)
	}
	if _, present := out[RuleSetsLabelKey]; present {
		t.Fatalf("rule_sets label leaked: %+v", out)
	}
	if out["firefik.enable"] != "true" {
		t.Fatalf("non-internal label dropped: %+v", out)
	}
}
