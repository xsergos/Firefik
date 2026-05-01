package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type RemoteSinkOptions struct {
	Endpoint     string
	AuthToken    string
	Timeout      time.Duration
	BufferSize   int
	RetryBackoff time.Duration
	Logger       *slog.Logger
}

func defaultedRemoteOptions(opts RemoteSinkOptions) RemoteSinkOptions {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1000
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = 2 * time.Second
	}
	return opts
}

type remoteSink struct {
	opts    RemoteSinkOptions
	ch      chan Event
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	client  *http.Client
	logger  *slog.Logger
	dropped uint64
	mu      sync.Mutex
}

func NewRemoteSink(opts RemoteSinkOptions) (Sink, error) {
	opts = defaultedRemoteOptions(opts)
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("remote audit sink: endpoint is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &remoteSink{
		opts:   opts,
		ch:     make(chan Event, opts.BufferSize),
		cancel: cancel,
		client: &http.Client{Timeout: opts.Timeout},
		logger: opts.Logger,
	}
	s.wg.Add(1)
	go s.run(ctx)
	return s, nil
}

func (s *remoteSink) Write(ev Event) error {
	select {
	case s.ch <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		dropped := s.dropped
		s.mu.Unlock()
		if s.logger != nil {
			s.logger.Warn("remote audit sink buffer full, dropping event",
				"action", ev.Action,
				"total_dropped", dropped,
			)
		}
	}
	return nil
}

func (s *remoteSink) Close() error {
	s.cancel()
	close(s.ch)
	s.wg.Wait()
	return nil
}

func (s *remoteSink) run(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.ch:
			if !ok {
				return
			}
			s.sendWithRetry(ctx, ev)
		}
	}
}

func (s *remoteSink) sendWithRetry(ctx context.Context, ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("remote audit sink marshal failed", "error", err)
		}
		return
	}
	body = append(body, '\n')

	backoff := s.opts.RetryBackoff
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.postOnce(body); err != nil {
			if s.logger != nil {
				s.logger.Warn("remote audit sink post failed, retrying",
					"attempt", attempt+1,
					"error", err,
				)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			continue
		}
		return
	}
	if s.logger != nil {
		s.logger.Warn("remote audit sink: giving up after 3 attempts", "action", ev.Action)
	}
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

func (s *remoteSink) postOnce(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.opts.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.opts.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.opts.AuthToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remote audit sink returned %d", resp.StatusCode)
	}
	return nil
}
