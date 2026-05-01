package controlplane

import (
	"sync"
	"testing"
	"time"
)

func TestLogHub_PerAgentSubscriptionReceives(t *testing.T) {
	h := NewLogHub()
	sub := h.Subscribe("a1")
	defer sub.Close()

	h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "hello"})
	select {
	case got := <-sub.C():
		if got.Line != "hello" {
			t.Fatalf("unexpected line: %q", got.Line)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for log")
	}
}

func TestLogHub_PerAgentIgnoresOtherAgent(t *testing.T) {
	h := NewLogHub()
	sub := h.Subscribe("a1")
	defer sub.Close()

	h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a2"}, Line: "x"})
	select {
	case got := <-sub.C():
		t.Fatalf("should not receive: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLogHub_GlobalSubscriptionReceivesAll(t *testing.T) {
	h := NewLogHub()
	sub := h.Subscribe("")
	defer sub.Close()

	h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "a"})
	h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a2"}, Line: "b"})

	got := []string{}
	for i := 0; i < 2; i++ {
		select {
		case line := <-sub.C():
			got = append(got, line.Line)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestLogHub_CloseUnsubscribes(t *testing.T) {
	h := NewLogHub()
	sub := h.Subscribe("a1")
	sub.Close()

	h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "x"})

	if _, ok := <-sub.C(); ok {
		t.Fatal("expected closed channel")
	}
}

func TestLogHub_DropsWhenSlowConsumer(t *testing.T) {
	h := NewLogHub()
	sub := h.Subscribe("a1")
	defer sub.Close()

	for i := 0; i < logSubBuffer+10; i++ {
		h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "x"})
	}
	if h.Dropped() == 0 {
		t.Fatalf("expected drops on slow consumer; got %d", h.Dropped())
	}
}

func TestLogHub_NilCloseSafe(t *testing.T) {
	var sub *LogSubscription
	sub.Close()

	bare := &LogSubscription{}
	bare.Close()
}

func TestLogHub_PublishAfterCloseDoesNotPanic(t *testing.T) {
	h := NewLogHub()
	subA := h.Subscribe("a1")
	subB := h.Subscribe("")

	subA.Close()
	subB.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Publish after Close panicked: %v", r)
		}
	}()

	for i := 0; i < 16; i++ {
		h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "x"})
	}
}

func TestLogHub_RaceCloseVsPublish(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("race panic: %v", r)
		}
	}()

	for iter := 0; iter < 50; iter++ {
		h := NewLogHub()
		var subs []*LogSubscription
		for i := 0; i < 20; i++ {
			subs = append(subs, h.Subscribe("a1"))
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "x"})
			}
		}()
		go func() {
			defer wg.Done()
			for _, s := range subs {
				s.Close()
			}
		}()
		wg.Wait()
	}
}

func TestLogHub_ConcurrentSubAndPublish(t *testing.T) {
	h := NewLogHub()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := h.Subscribe("a1")
			defer s.Close()
			deadline := time.After(100 * time.Millisecond)
			for {
				select {
				case <-s.C():
				case <-deadline:
					return
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		h.Publish(LogLine{Agent: AgentIdentity{InstanceID: "a1"}, Line: "x"})
	}
	wg.Wait()
}
