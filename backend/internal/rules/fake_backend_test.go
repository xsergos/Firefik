package rules

import (
	"context"
	"fmt"
	"net"
	"sync"

	"firefik/internal/docker"
)

type recordingBackend struct {
	mu sync.Mutex

	applied map[string]bool

	setupCalls       int
	cleanupCalls     int
	applyCalls       int
	removeCalls      int
	listCalls        int
	healthyCalls     int
	applyContainers  []string
	removeContainers []string

	setupErr   error
	cleanupErr error
	applyErr   error
	removeErr  error
	listErr    error
	healthyErr error

	applyErrByContainer  map[string]error
	removeErrByContainer map[string]error

	listOverride []string
}

func newRecordingBackend() *recordingBackend {
	return &recordingBackend{
		applied:              make(map[string]bool),
		applyErrByContainer:  make(map[string]error),
		removeErrByContainer: make(map[string]error),
	}
}

func (b *recordingBackend) SetupChains() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setupCalls++
	return b.setupErr
}

func (b *recordingBackend) Cleanup() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupCalls++
	return b.cleanupErr
}

func (b *recordingBackend) ApplyContainerRules(
	containerID string,
	containerName string,
	containerIPs []net.IP,
	ruleSets []docker.FirewallRuleSet,
	defaultPolicy string,
	autoAllowlist []net.IPNet,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyCalls++
	sid := shortID(containerID)
	b.applyContainers = append(b.applyContainers, sid)
	if err, ok := b.applyErrByContainer[sid]; ok {
		return err
	}
	if b.applyErr != nil {
		return b.applyErr
	}
	b.applied[sid] = true
	return nil
}

func (b *recordingBackend) RemoveContainerChains(containerID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeCalls++
	sid := shortID(containerID)
	b.removeContainers = append(b.removeContainers, sid)
	if err, ok := b.removeErrByContainer[sid]; ok {
		return err
	}
	if b.removeErr != nil {
		return b.removeErr
	}
	delete(b.applied, sid)
	return nil
}

func (b *recordingBackend) ListAppliedContainerIDs() ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listCalls++
	if b.listErr != nil {
		return nil, b.listErr
	}
	if b.listOverride != nil {
		out := make([]string, len(b.listOverride))
		copy(out, b.listOverride)
		return out, nil
	}
	out := make([]string, 0, len(b.applied))
	for id := range b.applied {
		out = append(out, id)
	}
	return out, nil
}

func (b *recordingBackend) Healthy() (HealthReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.healthyCalls++
	if b.healthyErr != nil {
		return HealthReport{}, b.healthyErr
	}
	return HealthReport{Backend: "recording"}, nil
}

func (b *recordingBackend) seedApplied(ids ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range ids {
		b.applied[shortID(id)] = true
	}
}

func (b *recordingBackend) applyCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applyCalls
}

func (b *recordingBackend) removeCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.removeCalls
}

type recordingDocker struct {
	mu sync.Mutex

	containers []docker.ContainerInfo
	listErr    error
	inspectErr error

	listCalls    int
	inspectCalls int

	inspectMissing map[string]bool
}

func (d *recordingDocker) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.listCalls++
	if d.listErr != nil {
		return nil, d.listErr
	}
	out := make([]docker.ContainerInfo, len(d.containers))
	copy(out, d.containers)
	return out, nil
}

func (d *recordingDocker) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inspectCalls++
	if d.inspectErr != nil {
		return docker.ContainerInfo{}, false, d.inspectErr
	}
	if d.inspectMissing[id] {
		return docker.ContainerInfo{}, false, nil
	}
	for _, c := range d.containers {
		if c.ID == id || matchContainerID(c.ID, id) {
			return c, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

func (d *recordingDocker) setContainers(ctrs ...docker.ContainerInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers = append([]docker.ContainerInfo(nil), ctrs...)
}

func makeContainer(id, name, ip string, extraLabels ...string) docker.ContainerInfo {

	if len(id) < ContainerIDShortLen {

		pad := make([]byte, ContainerIDShortLen-len(id))
		for i := range pad {
			pad[i] = '0'
		}
		id = id + string(pad)
	}
	if len(id) > ContainerIDShortLen {
		id = id[:ContainerIDShortLen]
	}

	labels := map[string]string{
		"firefik.enable":               "true",
		"firefik.firewall.web.ports":   "80,443",
		"firefik.firewall.web.profile": "web",
	}

	for i := 0; i+1 < len(extraLabels); i += 2 {
		labels[extraLabels[i]] = extraLabels[i+1]
	}

	networks := map[string]docker.NetworkEndpoint{
		"bridge": {IP: ip, PrefixLen: 24},
	}

	return docker.ContainerInfo{
		ID:       id,
		Name:     name,
		Status:   "running",
		Labels:   labels,
		Networks: networks,
	}
}

func expectIn(slice []string, s string) error {
	for _, v := range slice {
		if v == s {
			return nil
		}
	}
	return fmt.Errorf("%q not in %v", s, slice)
}
