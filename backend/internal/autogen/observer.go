package autogen

import (
	"context"
	"sort"
	"sync"
	"time"
)

type PortObservation struct {
	Protocol string
	Port     uint16
	Count    int
	FirstAt  time.Time
	LastAt   time.Time
}

type PeerObservation struct {
	IP      string
	Count   int
	FirstAt time.Time
	LastAt  time.Time
}

type ContainerObservation struct {
	Ports   map[string]*PortObservation
	Peers   map[string]*PeerObservation
	Updated time.Time
}

type Observer struct {
	mu    sync.Mutex
	win   map[string]*ContainerObservation
	start time.Time
	store Store
}

func NewObserver() *Observer {
	return &Observer{
		win:   make(map[string]*ContainerObservation),
		start: time.Now(),
		store: NewMemoryStore(),
	}
}

func NewObserverWithStore(store Store) *Observer {
	o := &Observer{
		win:   make(map[string]*ContainerObservation),
		start: time.Now(),
		store: store,
	}
	if store != nil {
		snap, _ := store.Snapshot(context.Background())
		for k, v := range snap {
			v := v
			o.win[k] = &v
		}
	}
	return o
}

func (o *Observer) StoreHandle() Store { return o.store }

type Flow struct {
	ContainerID string
	Protocol    string
	Port        uint16
	PeerIP      string
	At          time.Time
}

func (o *Observer) Record(f Flow) {
	if f.ContainerID == "" {
		return
	}
	if f.At.IsZero() {
		f.At = time.Now()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	obs, ok := o.win[f.ContainerID]
	if !ok {
		obs = &ContainerObservation{
			Ports: map[string]*PortObservation{},
			Peers: map[string]*PeerObservation{},
		}
		o.win[f.ContainerID] = obs
	}
	obs.Updated = f.At
	if f.Port > 0 {
		key := f.Protocol + "/" + portKey(f.Port)
		p, ok := obs.Ports[key]
		if !ok {
			p = &PortObservation{Protocol: f.Protocol, Port: f.Port, FirstAt: f.At}
			obs.Ports[key] = p
		}
		p.Count++
		p.LastAt = f.At
	}
	if f.PeerIP != "" {
		pe, ok := obs.Peers[f.PeerIP]
		if !ok {
			pe = &PeerObservation{IP: f.PeerIP, FirstAt: f.At}
			obs.Peers[f.PeerIP] = pe
		}
		pe.Count++
		pe.LastAt = f.At
	}

	if o.store != nil {
		_ = o.store.Observe(context.Background(), f)
	}
}

func (o *Observer) Snapshot() map[string]ContainerObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]ContainerObservation, len(o.win))
	for k, v := range o.win {
		cp := ContainerObservation{
			Ports:   make(map[string]*PortObservation, len(v.Ports)),
			Peers:   make(map[string]*PeerObservation, len(v.Peers)),
			Updated: v.Updated,
		}
		for pk, pv := range v.Ports {
			dup := *pv
			cp.Ports[pk] = &dup
		}
		for pk, pv := range v.Peers {
			dup := *pv
			cp.Peers[pk] = &dup
		}
		out[k] = cp
	}
	return out
}

func (o *Observer) LearningSince() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.start
}

type Proposal struct {
	ContainerID string   `json:"container_id"`
	Ports       []uint16 `json:"ports"`
	Peers       []string `json:"peers"`
	ObservedFor string   `json:"observed_for"`
	Confidence  string   `json:"confidence"`
}

func (o *Observer) Propose(minObservations int, minAge time.Duration) []Proposal {
	snap := o.Snapshot()
	since := time.Since(o.LearningSince())
	var out []Proposal
	for cid, obs := range snap {
		p := Proposal{
			ContainerID: cid,
			ObservedFor: since.Truncate(time.Second).String(),
		}
		for _, po := range obs.Ports {
			if po.Count >= minObservations && time.Since(po.FirstAt) >= minAge {
				p.Ports = append(p.Ports, po.Port)
			}
		}
		for _, pe := range obs.Peers {
			if pe.Count >= minObservations {
				p.Peers = append(p.Peers, pe.IP)
			}
		}
		sort.Slice(p.Ports, func(i, j int) bool { return p.Ports[i] < p.Ports[j] })
		sort.Strings(p.Peers)
		p.Confidence = confidenceTier(len(p.Ports), len(p.Peers), since)
		if len(p.Ports)+len(p.Peers) > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerID < out[j].ContainerID })
	return out
}

func confidenceTier(portCount, peerCount int, window time.Duration) string {
	switch {
	case window < time.Hour:
		return "warming"
	case window < 24*time.Hour:
		return "tentative"
	case portCount+peerCount >= 50:
		return "high"
	default:
		return "moderate"
	}
}

func portKey(p uint16) string {
	digits := []byte{}
	for p > 0 {
		digits = append([]byte{byte('0' + p%10)}, digits...)
		p /= 10
	}
	if len(digits) == 0 {
		return "0"
	}
	return string(digits)
}
