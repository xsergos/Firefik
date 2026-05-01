package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type WebhookOptions struct {
	URL     string
	Events  []string
	Secret  string
	Timeout time.Duration
}

type WebhookSink struct {
	client *http.Client
	url    string
	events map[string]struct{}
	secret string
}

func NewWebhookSink(opts WebhookOptions) (Sink, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("webhook sink: url is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	events := make(map[string]struct{}, len(opts.Events))
	for _, e := range opts.Events {
		t := strings.TrimSpace(e)
		if t != "" {
			events[t] = struct{}{}
		}
	}
	return &WebhookSink{
		client: &http.Client{Timeout: timeout},
		url:    opts.URL,
		events: events,
		secret: opts.Secret,
	}, nil
}

func (s *WebhookSink) Write(ev Event) error {
	if len(s.events) > 0 {
		if _, ok := s.events[ev.Action]; !ok {
			return nil
		}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.send(ev.Action, body)
	return nil
}

func (s *WebhookSink) send(action string, body []byte) {
	status, retry := s.postOnce(action, body)
	webhookSentTotal.WithLabelValues(status).Inc()
	if !retry {
		return
	}
	status, _ = s.postOnce(action, body)
	webhookSentTotal.WithLabelValues(status).Inc()
}

func (s *WebhookSink) postOnce(action string, body []byte) (string, bool) {
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return "error", false
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Firefik-Event", action)
	req.Header.Set("X-Firefik-Timestamp", ts)
	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write([]byte(action))
		mac.Write([]byte{'\n'})
		mac.Write([]byte(ts))
		mac.Write([]byte{'\n'})
		mac.Write(body)
		req.Header.Set("X-Firefik-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "error", true
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode >= 500:
		return "5xx", true
	case resp.StatusCode >= 400:
		return "4xx", false
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return "2xx", false
	default:
		return "other", false
	}
}

func (s *WebhookSink) Close() error { return nil }
