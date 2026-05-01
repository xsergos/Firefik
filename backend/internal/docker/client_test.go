package docker

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/network"
)

func TestSummaryToInfo_BasicNamesNetworks(t *testing.T) {
	addr, _ := netip.ParseAddr("10.0.0.1")
	s := container.Summary{
		ID:     "0123456789abcdef00112233",
		Names:  []string{"/web"},
		State:  container.StateRunning,
		Labels: map[string]string{"a": "b"},
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {IPAddress: addr, IPPrefixLen: 24},
				"empty":  nil,
			},
		},
	}
	got := summaryToInfo(s)
	if got.ID != "0123456789ab" {
		t.Errorf("expected short id, got %q", got.ID)
	}
	if got.Name != "web" {
		t.Errorf("name=%q", got.Name)
	}
	if got.Status != string(container.StateRunning) {
		t.Errorf("status=%q", got.Status)
	}
	if got.Labels["a"] != "b" {
		t.Errorf("labels=%v", got.Labels)
	}
	ep, ok := got.Networks["bridge"]
	if !ok || ep.IP != "10.0.0.1" || ep.PrefixLen != 24 {
		t.Errorf("networks=%v", got.Networks)
	}
	if _, present := got.Networks["empty"]; present {
		t.Errorf("empty endpoint should be skipped")
	}
}

func TestSummaryToInfo_NoNamesNoNetworks(t *testing.T) {
	s := container.Summary{ID: "short"}
	got := summaryToInfo(s)
	if got.ID != "short" {
		t.Errorf("id=%q", got.ID)
	}
	if got.Name != "" {
		t.Errorf("expected empty name, got %q", got.Name)
	}
	if len(got.Networks) != 0 {
		t.Errorf("expected no networks")
	}
}

func TestSummaryToInfo_InvalidIPSkipped(t *testing.T) {
	var zero netip.Addr
	s := container.Summary{
		ID: "abcdef0123456789",
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"none": {IPAddress: zero},
			},
		},
	}
	got := summaryToInfo(s)
	if _, ok := got.Networks["none"]; ok {
		t.Errorf("invalid IP endpoint should be skipped")
	}
}

func TestSummariesToInfos(t *testing.T) {
	got := summariesToInfos([]container.Summary{
		{ID: "1", Names: []string{"/a"}},
		{ID: "2", Names: []string{"/b"}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("names=%v %v", got[0].Name, got[1].Name)
	}
}

func TestInspectResponseToInfo_Full(t *testing.T) {
	addr, _ := netip.ParseAddr("172.18.0.5")
	state := container.StateRunning
	resp := container.InspectResponse{
		ID:    "abcdefabcdef1234567890aa",
		Name:  "/svc",
		State: &container.State{Status: state},
		Config: &container.Config{
			Labels: map[string]string{"k": "v"},
		},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"net1": {IPAddress: addr, IPPrefixLen: 16},
				"nil":  nil,
			},
		},
	}
	info := inspectResponseToInfo(resp)
	if info.ID != "abcdefabcdef" {
		t.Errorf("id=%q", info.ID)
	}
	if info.Name != "svc" {
		t.Errorf("name=%q", info.Name)
	}
	if info.Status != string(state) {
		t.Errorf("status=%q", info.Status)
	}
	if info.Labels["k"] != "v" {
		t.Errorf("labels=%v", info.Labels)
	}
	if info.Networks["net1"].IP != "172.18.0.5" {
		t.Errorf("networks=%v", info.Networks)
	}
	if _, ok := info.Networks["nil"]; ok {
		t.Errorf("nil endpoint should be skipped")
	}
}

func TestInspectResponseToInfo_NilFields(t *testing.T) {
	resp := container.InspectResponse{ID: "x"}
	info := inspectResponseToInfo(resp)
	if info.ID != "x" {
		t.Errorf("id=%q", info.ID)
	}
	if info.Status != "" {
		t.Errorf("expected empty status, got %q", info.Status)
	}
	if info.Labels != nil {
		t.Errorf("expected nil labels")
	}
	if len(info.Networks) != 0 {
		t.Errorf("expected zero networks")
	}
}

func TestInspectResponseToInfo_InvalidIP(t *testing.T) {
	resp := container.InspectResponse{
		ID: "z",
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"none": {},
			},
		},
	}
	info := inspectResponseToInfo(resp)
	if _, ok := info.Networks["none"]; ok {
		t.Errorf("invalid IP should be skipped")
	}
}

func TestDispatchEvents_DeliversWatchedActions(t *testing.T) {
	msgs := make(chan EventMessage, 4)
	errs := make(chan error)
	msgs <- EventMessage{Action: events.Action("start"), Actor: events.Actor{ID: "c1"}}
	msgs <- EventMessage{Action: events.Action("ignored")}
	msgs <- EventMessage{Action: events.Action("die"), Actor: events.Actor{ID: "c2"}}
	close(msgs)

	var got []string
	dispatchEvents(context.Background(), msgs, errs, func(e EventMessage) {
		got = append(got, e.Actor.ID)
	}, nil)
	if len(got) != 2 || got[0] != "c1" || got[1] != "c2" {
		t.Errorf("delivered=%v", got)
	}
}

func TestDispatchEvents_StopsOnContextDone(t *testing.T) {
	msgs := make(chan EventMessage)
	errs := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dispatchEvents(ctx, msgs, errs, func(EventMessage) {}, nil)
}

func TestDispatchEvents_OnError(t *testing.T) {
	msgs := make(chan EventMessage)
	errs := make(chan error, 1)
	errs <- errors.New("boom")
	var captured error
	dispatchEvents(context.Background(), msgs, errs, func(EventMessage) {}, func(err error) { captured = err })
	if captured == nil {
		t.Fatal("expected captured error")
	}
}

func TestDispatchEvents_OnErrorNilHandler(t *testing.T) {
	msgs := make(chan EventMessage)
	errs := make(chan error, 1)
	errs <- errors.New("boom")
	dispatchEvents(context.Background(), msgs, errs, func(EventMessage) {}, nil)
}

func TestDispatchEvents_ErrChannelClosed(t *testing.T) {
	msgs := make(chan EventMessage)
	errs := make(chan error)
	close(errs)
	dispatchEvents(context.Background(), msgs, errs, func(EventMessage) {}, nil)
}

func TestDispatchEvents_CtxDoneAfterError(t *testing.T) {
	msgs := make(chan EventMessage)
	errs := make(chan error, 1)
	errs <- errors.New("err")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dispatchEvents(ctx, msgs, errs, func(EventMessage) {}, func(err error) {
		t.Errorf("onError should not fire when ctx is done")
	})
}

func TestNextEventDelay(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{1 * time.Second, 2 * time.Second},
		{29 * time.Second, 58 * time.Second},
		{30 * time.Second, 30 * time.Second},
		{60 * time.Second, 60 * time.Second},
	}
	for _, c := range cases {
		if got := nextEventDelay(c.in); got != c.want {
			t.Errorf("nextEventDelay(%v)=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestNewClient_FromEnv(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "1.44")
	c, err := NewClient()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestClient_InspectContextCancelled(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "1.44")
	c, err := NewClient()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, found, err := c.Inspect(ctx, "x")
	if err == nil && found {
		t.Errorf("expected error or not-found on cancelled ctx, got found=%v err=%v", found, err)
	}
}

func TestClient_ListContainers_FailsAgainstUnreachable(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "1.44")
	c, err := NewClient()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.ListContainers(ctx); err == nil {
		t.Errorf("expected error against unreachable docker")
	}
}

func TestClient_WatchEvents_StopsOnCtxCancel(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "1.44")
	c, err := NewClient()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.WatchEvents(ctx, func(EventMessage) {}, nil)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchEvents did not return")
	}
}
