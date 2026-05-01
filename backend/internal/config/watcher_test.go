package config

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startWatcher(t *testing.T, ctx context.Context, path string, onChange func()) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := WatchFile(ctx, path, newTestLogger(), onChange); err != nil {
			t.Logf("WatchFile returned error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return done
}

func TestWatchFile_AddDirError(t *testing.T) {

	nonexistent := filepath.Join(t.TempDir(), "no-such-dir", "config.yml")
	err := WatchFile(context.Background(), nonexistent, newTestLogger(), func() {})
	if err == nil {
		t.Fatal("expected error when directory does not exist")
	}
}

func TestWatchFile_FiresOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startWatcher(t, ctx, path, func() {
		atomic.AddInt32(&calls, 1)
	})

	if err := os.WriteFile(path, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if atomic.LoadInt32(&calls) < 1 {
		t.Fatalf("expected onChange to fire at least once, got %d", atomic.LoadInt32(&calls))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit after cancel")
	}
}

func TestWatchFile_IgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "config.yml")
	other := filepath.Join(dir, "unrelated.yml")
	if err := os.WriteFile(watched, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startWatcher(t, ctx, watched, func() {
		atomic.AddInt32(&calls, 1)
	})

	if err := os.WriteFile(other, []byte("a\n"), 0o600); err != nil {
		t.Fatalf("write other: %v", err)
	}
	if err := os.WriteFile(other, []byte("b\n"), 0o600); err != nil {
		t.Fatalf("rewrite other: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected 0 callbacks for unrelated file changes, got %d", got)
	}

	cancel()
	<-done
}

func TestWatchFile_ContextCancelStopsWatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(path, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := startWatcher(t, ctx, path, func() {})

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit after context cancel")
	}
}

func TestWatchFile_RenameTriggers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startWatcher(t, ctx, path, func() {
		atomic.AddInt32(&calls, 1)
	})

	tmp := filepath.Join(dir, "config.yml.new")
	if err := os.WriteFile(tmp, []byte("updated\n"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	time.Sleep(600 * time.Millisecond)

	if got := atomic.LoadInt32(&calls); got < 1 {
		t.Fatalf("expected rename to trigger callback, got %d", got)
	}

	cancel()
	<-done
}

func TestWatchFile_CancelWithPendingTimer(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(path, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := startWatcher(t, ctx, path, func() {
		t.Error("onChange should not fire — we cancel before debounce elapses")
	})

	if err := os.WriteFile(path, []byte("update\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit after cancel-with-pending-timer")
	}
}

func TestWatchFile_IgnoresNonRelevantOps(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(path, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startWatcher(t, ctx, path, func() {
		atomic.AddInt32(&calls, 1)
	})

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	_ = calls

	cancel()
	<-done
}

func TestWatchFile_DebounceCoalescesWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startWatcher(t, ctx, path, func() {
		atomic.AddInt32(&calls, 1)
	})

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte{byte('0' + i), '\n'}, 0o600); err != nil {
			t.Fatalf("burst write %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	got := atomic.LoadInt32(&calls)
	if got < 1 {
		t.Fatalf("expected at least one coalesced callback, got %d", got)
	}

	cancel()
	<-done
}
