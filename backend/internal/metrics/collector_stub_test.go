//go:build !linux

package metrics

import "testing"

func TestNewIPTablesCollectorStub(t *testing.T) {
	c, err := NewIPTablesCollector("FIREFIK")
	if err != nil {
		t.Errorf("stub should not error: %v", err)
	}
	if c != nil {
		t.Errorf("stub should return nil collector")
	}
}

func TestNewNFTablesCollectorStub(t *testing.T) {
	c, err := NewNFTablesCollector("FIREFIK")
	if err != nil {
		t.Errorf("stub should not error: %v", err)
	}
	if c != nil {
		t.Errorf("stub should return nil collector")
	}
}
