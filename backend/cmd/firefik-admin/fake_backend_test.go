package main

import (
	"log/slog"
	"net"
	"sync"

	"firefik/internal/docker"
	"firefik/internal/rules"
)

type fakeBackend struct {
	mu sync.Mutex

	setupErr   error
	cleanupErr error
	applyErr   error
	removeErr  error
	listErr    error
	healthErr  error

	healthReport rules.HealthReport
	listIDs      []string

	setupCalls   int
	cleanupCalls int
	applyCalls   int
	removeCalls  int
	listCalls    int
	healthCalls  int

	applied  []string
	removed  []string
	appliedArgs [][]any
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{}
}

func (f *fakeBackend) SetupChains() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setupCalls++
	return f.setupErr
}

func (f *fakeBackend) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanupCalls++
	return f.cleanupErr
}

func (f *fakeBackend) ApplyContainerRules(
	containerID string,
	containerName string,
	containerIPs []net.IP,
	ruleSets []docker.FirewallRuleSet,
	defaultPolicy string,
	autoAllowlist []net.IPNet,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyCalls++
	f.applied = append(f.applied, containerID)
	f.appliedArgs = append(f.appliedArgs, []any{containerID, containerName, defaultPolicy})
	return f.applyErr
}

func (f *fakeBackend) RemoveContainerChains(containerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls++
	f.removed = append(f.removed, containerID)
	return f.removeErr
}

func (f *fakeBackend) ListAppliedContainerIDs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]string, len(f.listIDs))
	copy(out, f.listIDs)
	return out, nil
}

func (f *fakeBackend) Healthy() (rules.HealthReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthCalls++
	if f.healthErr != nil {
		return rules.HealthReport{}, f.healthErr
	}
	return f.healthReport, nil
}

func swapResolveBackend(fb *fakeBackend, kind string) func() {
	prev := resolveBackendFn
	resolveBackendFn = func(g *globalFlags, setup bool) (rules.Backend, string, error) {
		if setup {
			if err := fb.SetupChains(); err != nil {
				return nil, kind, err
			}
		}
		return fb, kind, nil
	}
	return func() { resolveBackendFn = prev }
}

func swapResolveBackendErr(err error) func() {
	prev := resolveBackendFn
	resolveBackendFn = func(g *globalFlags, setup bool) (rules.Backend, string, error) {
		return nil, "", err
	}
	return func() { resolveBackendFn = prev }
}

func swapNewBackendForChain(fb *fakeBackend, kind string) func() {
	prev := newBackendForChainFn
	newBackendForChainFn = func(g *globalFlags, chain string, logger *slog.Logger) (rules.Backend, string, error) {
		return fb, kind, nil
	}
	return func() { newBackendForChainFn = prev }
}
