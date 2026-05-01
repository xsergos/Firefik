package main

import (
	"encoding/json"

	"firefik/internal/controlplane"
	"firefik/internal/logstream"
)

type cpLogBridge struct {
	hub *logstream.Hub
	out chan controlplane.LogLine
}

func newCPLogBridge(hub *logstream.Hub) *cpLogBridge {
	return &cpLogBridge{
		hub: hub,
		out: make(chan controlplane.LogLine, 256),
	}
}

func (b *cpLogBridge) Logs() <-chan controlplane.LogLine { return b.out }

func (b *cpLogBridge) Pump(stop <-chan struct{}) {
	if b.hub == nil {
		return
	}
	client := b.hub.Subscribe()
	defer b.hub.Unsubscribe(client)
	for {
		select {
		case <-stop:
			return
		case msg, ok := <-client.Messages():
			if !ok {
				return
			}
			line := controlplane.LogLine{
				Source: "nflog",
				Line:   string(msg),
			}
			var fields map[string]any
			if err := json.Unmarshal(msg, &fields); err == nil {
				line.Fields = stringifyMap(fields)
			}
			select {
			case b.out <- line:
			case <-stop:
				return
			default:
			}
		}
	}
}

func stringifyMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = jsonNumberString(t)
		case bool:
			if t {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		}
	}
	return out
}

func jsonNumberString(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
