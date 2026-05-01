package api

import (
	"sync"
	"testing"
)

func TestTokenProvider_SetGet(t *testing.T) {
	tp := NewTokenProvider("initial")
	if tp.Get() != "initial" {
		t.Errorf("want initial, got %q", tp.Get())
	}
	tp.Set("rotated")
	if tp.Get() != "rotated" {
		t.Errorf("want rotated, got %q", tp.Get())
	}
}

func TestTokenProvider_Fingerprint(t *testing.T) {
	tp := NewTokenProvider("")
	if tp.Fingerprint() != "" {
		t.Errorf("empty token should produce empty fingerprint, got %q", tp.Fingerprint())
	}
	tp.Set("secret-abc")
	fp1 := tp.Fingerprint()
	if len(fp1) != 16 {
		t.Errorf("fingerprint should be 16 hex chars, got %d: %q", len(fp1), fp1)
	}
	tp.Set("secret-abc")
	if tp.Fingerprint() != fp1 {
		t.Errorf("same token should produce same fingerprint")
	}
	tp.Set("secret-xyz")
	if tp.Fingerprint() == fp1 {
		t.Errorf("different token should produce different fingerprint")
	}
}

func TestTokenProvider_ConcurrentRead(t *testing.T) {
	tp := NewTokenProvider("start")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = tp.Get()
				_ = tp.Fingerprint()
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tp.Set("rotated")
		}(i)
	}
	wg.Wait()
}
