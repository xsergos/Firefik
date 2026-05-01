package autogen

import (
	"testing"
	"time"
)

func TestObserverRecordAndPropose(t *testing.T) {
	o := NewObserver()
	now := time.Now()
	for i := 0; i < 12; i++ {
		o.Record(Flow{ContainerID: "abc", Protocol: "tcp", Port: 80, PeerIP: "1.2.3.4", At: now.Add(time.Duration(i) * time.Second)})
	}

	o.Record(Flow{ContainerID: "abc", Protocol: "tcp", Port: 443, PeerIP: "5.6.7.8", At: now})

	props := o.Propose(5, 0)
	if len(props) != 1 {
		t.Fatalf("want 1 proposal, got %d", len(props))
	}
	p := props[0]
	if p.ContainerID != "abc" {
		t.Errorf("container id = %q", p.ContainerID)
	}
	if len(p.Ports) != 1 || p.Ports[0] != 80 {
		t.Errorf("ports = %v (want [80] — 443 below threshold)", p.Ports)
	}
	if len(p.Peers) != 1 || p.Peers[0] != "1.2.3.4" {
		t.Errorf("peers = %v", p.Peers)
	}
}

func TestObserverSnapshotIsCopy(t *testing.T) {
	o := NewObserver()
	o.Record(Flow{ContainerID: "c1", Protocol: "tcp", Port: 80, At: time.Now()})
	s1 := o.Snapshot()
	s1["c1"].Ports["tcp/80"].Count = 9999
	s2 := o.Snapshot()
	if s2["c1"].Ports["tcp/80"].Count == 9999 {
		t.Errorf("snapshot must return an independent copy")
	}
}

func TestConfidenceTiers(t *testing.T) {
	cases := []struct {
		ports, peers int
		window       time.Duration
		want         string
	}{
		{10, 10, 5 * time.Minute, "warming"},
		{10, 10, 2 * time.Hour, "tentative"},
		{60, 0, 48 * time.Hour, "high"},
		{5, 5, 48 * time.Hour, "moderate"},
	}
	for _, c := range cases {
		if got := confidenceTier(c.ports, c.peers, c.window); got != c.want {
			t.Errorf("confidence(%d, %d, %s) = %q, want %q", c.ports, c.peers, c.window, got, c.want)
		}
	}
}
