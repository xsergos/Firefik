package main

import (
	"reflect"
	"testing"
)

func TestDeriveSources(t *testing.T) {
	cases := []struct {
		name           string
		firewallStatus string
		labels         map[string]string
		want           []string
	}{
		{"disabled returns nil", "disabled", map[string]string{"firefik.enable": "true"}, nil},
		{"empty status returns nil", "", nil, nil},
		{"active with firefik label", "active", map[string]string{"firefik.enable": "true"}, []string{"label"}},
		{"active with firefik.firewall.X", "active", map[string]string{"firefik.firewall.web.ports": "80"}, []string{"label"}},
		{"active without firefik labels", "active", map[string]string{"app": "x"}, []string{"config"}},
		{"active no labels at all", "active", nil, []string{"config"}},
	}
	for _, c := range cases {
		got := deriveSources(c.firewallStatus, c.labels)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
