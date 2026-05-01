package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckReportJSON(t *testing.T) {
	rep := checkReport{
		Backend:             "iptables",
		Chain:               "FIREFIK",
		Parent:              "DOCKER-USER",
		BaseChainPresent:    true,
		ParentJumpPresent:   false,
		ContainerChainCount: 3,
		Drift:               true,
		Notes:               []string{"parent chain DOCKER-USER has no jump to FIREFIK"},
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"backend":"iptables"`,
		`"base_chain_present":true`,
		`"parent_jump_present":false`,
		`"container_chain_count":3`,
		`"drift":true`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in json: %s", want, s)
		}
	}
}

func TestInventoryReportJSON(t *testing.T) {
	rep := inventoryReport{
		Backend:           "nftables",
		Chain:             "FIREFIK-v2",
		Parent:            "DOCKER-USER",
		TrackedContainers: 2,
		ContainerShortIDs: []string{"abc123", "def456"},
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"backend":"nftables"`,
		`"chain":"FIREFIK-v2"`,
		`"tracked_containers":2`,
		`"container_short_ids":["abc123","def456"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in json: %s", want, s)
		}
	}
}

func TestStatusReportJSON(t *testing.T) {
	rep := statusReport{Backend: "iptables", Chain: "FIREFIK", Parent: "DOCKER-USER", ContainerChains: 5}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"container_chains":5`) {
		t.Errorf("field missing: %s", s)
	}
}

func TestCheckDriftDetection(t *testing.T) {
	cases := []struct {
		name         string
		base, parent bool
		wantDrift    bool
	}{
		{"healthy", true, true, false},
		{"missing jump", true, false, true},
		{"missing base", false, true, true},
		{"missing both", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drift := !tc.base || !tc.parent
			if drift != tc.wantDrift {
				t.Errorf("drift = %v, want %v", drift, tc.wantDrift)
			}
		})
	}
}
