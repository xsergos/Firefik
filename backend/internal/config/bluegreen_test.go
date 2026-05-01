package config

import (
	"reflect"
	"testing"
)

func TestDeriveLegacyChains(t *testing.T) {
	cases := []struct {
		name      string
		base      string
		effective string
		suffixes  []string
		want      []string
	}{
		{
			name: "empty input",
			base: "FIREFIK", effective: "FIREFIK", suffixes: nil,
			want: nil,
		},
		{
			name: "single suffix",
			base: "FIREFIK", effective: "FIREFIK-v2", suffixes: []string{"v1"},
			want: []string{"FIREFIK-v1"},
		},
		{
			name: "multiple suffixes preserve order",
			base: "FIREFIK", effective: "FIREFIK-v3", suffixes: []string{"v1", "v2"},
			want: []string{"FIREFIK-v1", "FIREFIK-v2"},
		},
		{
			name: "dedup preserves first occurrence",
			base: "FIREFIK", effective: "FIREFIK-v3", suffixes: []string{"v1", "v2", "v1"},
			want: []string{"FIREFIK-v1", "FIREFIK-v2"},
		},
		{
			name: "skip effective chain",
			base: "FIREFIK", effective: "FIREFIK-v2", suffixes: []string{"v1", "v2"},
			want: []string{"FIREFIK-v1"},
		},
		{
			name: "skip empty suffix that collides with effective",
			base: "FIREFIK", effective: "FIREFIK", suffixes: []string{"", "v1"},
			want: []string{"FIREFIK-v1"},
		},
		{
			name: "empty suffix maps to base",
			base: "FIREFIK", effective: "FIREFIK-v2", suffixes: []string{""},
			want: []string{"FIREFIK"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveLegacyChains(tc.base, tc.effective, tc.suffixes)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
