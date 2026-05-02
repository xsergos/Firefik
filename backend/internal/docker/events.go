package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

type EventMessage = events.Message

type EventHandler func(event EventMessage)

var watchedActions = map[string]bool{
	"start":   true,
	"stop":    true,
	"die":     true,
	"destroy": true,
	"rename":  true,
}

const stableWindow = 30 * time.Second

func (c *Client) WatchEvents(ctx context.Context, handler EventHandler, onError func(error)) error {
	baseDelay := time.Second
	delay := baseDelay
	for {
		connectedAt := time.Now()
		result := c.sdk.Events(ctx, client.EventsListOptions{
			Filters: client.Filters{
				"type":  {"container": true},
				"event": {"start": true, "stop": true, "die": true, "destroy": true, "rename": true},
			},
		})
		dispatchEvents(ctx, result.Messages, result.Err, handler, onError)

		if ctx.Err() != nil {
			return nil //nolint:nilerr
		}

		if time.Since(connectedAt) >= stableWindow {
			delay = baseDelay
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}

		delay = nextEventDelay(delay)
	}
}

func dispatchEvents(ctx context.Context, msgs <-chan EventMessage, errs <-chan error, handler EventHandler, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			if watchedActions[string(msg.Action)] {
				handler(msg)
			}
		case err, ok := <-errs:
			if !ok {
				return
			}
			if ctx.Err() != nil {
				return
			}
			if onError != nil {
				onError(fmt.Errorf("docker events stream: %w", err))
			}
			return
		}
	}
}

func nextEventDelay(d time.Duration) time.Duration {
	if d < 30*time.Second {
		return d * 2
	}
	return d
}
