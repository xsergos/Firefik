package controlplane

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type fakeLogSource struct {
	ch chan LogLine
}

func newFakeLogSource() *fakeLogSource {
	return &fakeLogSource{ch: make(chan LogLine, 16)}
}

func (f *fakeLogSource) Logs() <-chan LogLine { return f.ch }

func TestAgentLoop_WithLogSource_SetsField(t *testing.T) {
	loop := NewAgentLoop(AgentLoopConfig{}, AgentIdentity{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	src := newFakeLogSource()
	out := loop.WithLogSource(src)
	if out != loop {
		t.Fatal("WithLogSource should return same loop pointer")
	}
	if loop.logSource == nil {
		t.Fatal("logSource not set")
	}
}

func TestAgentLoop_LogForwarder_StopsOnContextCancel(t *testing.T) {
	loop := NewAgentLoop(AgentLoopConfig{}, AgentIdentity{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	src := newFakeLogSource()
	loop.WithLogSource(src)

	gc := &GRPCClient{}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		loop.logForwarder(ctx, gc)
	}()

	src.ch <- LogLine{Line: "test"}
	time.Sleep(20 * time.Millisecond)

	cancel()
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("logForwarder did not stop on context cancel")
	}
}

func TestAgentLoop_LogForwarder_StopsOnChannelClose(t *testing.T) {
	loop := NewAgentLoop(AgentLoopConfig{}, AgentIdentity{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	src := newFakeLogSource()
	loop.WithLogSource(src)

	gc := &GRPCClient{}

	doneCh := make(chan struct{})
	go func() {
		loop.logForwarder(context.Background(), gc)
		close(doneCh)
	}()

	close(src.ch)

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("logForwarder did not stop on channel close")
	}
}

func TestAgentLoop_LogForwarder_NilChannelExits(t *testing.T) {
	loop := NewAgentLoop(AgentLoopConfig{}, AgentIdentity{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	loop.logSource = nilLogSource{}
	gc := &GRPCClient{}
	doneCh := make(chan struct{})
	go func() {
		loop.logForwarder(context.Background(), gc)
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("logForwarder did not exit when source returns nil channel")
	}
}

type nilLogSource struct{}

func (nilLogSource) Logs() <-chan LogLine { return nil }
