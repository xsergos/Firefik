package main

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"firefik/internal/logstream"
)

func TestStringifyMap(t *testing.T) {
	in := map[string]any{
		"action":   "apply",
		"port":     float64(443),
		"enabled":  true,
		"disabled": false,
		"ignore":   []int{1, 2}, // unsupported -> dropped
		"nilv":     nil,
	}
	out := stringifyMap(in)
	want := map[string]string{
		"action":   "apply",
		"port":     "443",
		"enabled":  "true",
		"disabled": "false",
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %+v want %+v", out, want)
	}
}

func TestJSONNumberString(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{1.5, "1.5"},
		{-100, "-100"},
	}
	for _, c := range cases {
		if got := jsonNumberString(c.in); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

func TestCPLogBridge_NilHubReturns(t *testing.T) {
	b := newCPLogBridge(nil)
	stop := make(chan struct{})
	close(stop)
	b.Pump(stop)
}

func TestCPLogBridge_LogsChannelExposed(t *testing.T) {
	b := newCPLogBridge(nil)
	ch := b.Logs()
	if ch == nil {
		t.Fatal("Logs() returned nil")
	}
}

func TestCPLogBridge_Pump_ForwardsAndParsesJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := logstream.NewHub(logger)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go hub.Run(ctx)

	b := newCPLogBridge(hub)
	stop := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		b.Pump(stop)
		close(doneCh)
	}()

	time.Sleep(20 * time.Millisecond)
	hub.Broadcast([]byte(`{"action":"apply","port":443,"enabled":true}`))

	select {
	case line := <-b.Logs():
		if line.Source != "nflog" {
			t.Errorf("source=%q want nflog", line.Source)
		}
		if line.Fields["action"] != "apply" {
			t.Errorf("fields.action=%q want apply", line.Fields["action"])
		}
		if line.Fields["port"] != "443" {
			t.Errorf("fields.port=%q want 443", line.Fields["port"])
		}
		if line.Fields["enabled"] != "true" {
			t.Errorf("fields.enabled=%q want true", line.Fields["enabled"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: no log forwarded")
	}

	close(stop)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("Pump did not stop")
	}
}

func TestCPLogBridge_Pump_NonJSONLineHasNoFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := logstream.NewHub(logger)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go hub.Run(ctx)

	b := newCPLogBridge(hub)
	stop := make(chan struct{})
	go b.Pump(stop)

	time.Sleep(20 * time.Millisecond)
	hub.Broadcast([]byte("plain-text log"))

	select {
	case line := <-b.Logs():
		if line.Line != "plain-text log" {
			t.Errorf("line=%q want plain-text log", line.Line)
		}
		if len(line.Fields) != 0 {
			t.Errorf("fields should be nil/empty for non-JSON, got %+v", line.Fields)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	close(stop)
}

func TestCPLogBridge_Pump_StopsOnSignal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := logstream.NewHub(logger)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go hub.Run(ctx)

	b := newCPLogBridge(hub)
	stop := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		b.Pump(stop)
		close(doneCh)
	}()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("Pump did not stop on close(stop)")
	}
}
