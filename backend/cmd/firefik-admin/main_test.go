package main

import "testing"

func TestIsSystemChain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"FIREFIK", false},
		{"FIREFIK-v2", false},
		{"FIREFIK-ABC123456789", false},
		{"firefik-v2", false},
		{"DOCKER-USER", true},
		{"DOCKER", true},
		{"DOCKER-ISOLATION-STAGE-1", true},
		{"docker-user", true},
		{"INPUT", true},
		{"input", true},
		{"OUTPUT", true},
		{"FORWARD", true},
		{"PREROUTING", true},
		{"POSTROUTING", true},
		{"DOCKER-CUSTOM", true},
		{"MyOwnChain", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isSystemChain(tc.in); got != tc.want {
				t.Fatalf("isSystemChain(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
