package api

import "testing"

func TestIsValidContainerID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"abcdef012345", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"ab", false},
		{"abc", false},
		{"", false},
		{"invalid!", false},
		{"ABCDEF012345", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isValidContainerID(tc.in); got != tc.want {
				t.Fatalf("isValidContainerID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
