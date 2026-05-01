package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultTemplatePullInterval = 60 * time.Second

type TemplateSyncerConfig struct {
	Endpoint    string
	Token       string
	TLSConfig   *tls.Config
	Interval    time.Duration
	CacheDir    string
	DialTimeout time.Duration
	Logger      *slog.Logger
}

type TemplateSyncer struct {
	cfg TemplateSyncerConfig

	mu        sync.RWMutex
	templates map[string]PolicyTemplate
}

func NewTemplateSyncer(cfg TemplateSyncerConfig) *TemplateSyncer {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultTemplatePullInterval
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	return &TemplateSyncer{cfg: cfg, templates: map[string]PolicyTemplate{}}
}

func (t *TemplateSyncer) Run(ctx context.Context) error {
	if t.cfg.Endpoint == "" {
		return nil
	}
	if t.cfg.CacheDir != "" {
		if err := os.MkdirAll(t.cfg.CacheDir, 0o700); err != nil {
			return fmt.Errorf("template cache dir: %w", err)
		}
		t.loadFromDisk()
	}
	t.pullOnce(ctx)
	tick := time.NewTicker(t.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			t.pullOnce(ctx)
		}
	}
}

func (t *TemplateSyncer) Snapshot() []PolicyTemplate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]PolicyTemplate, 0, len(t.templates))
	for _, tmpl := range t.templates {
		out = append(out, tmpl)
	}
	return out
}

func (t *TemplateSyncer) Get(name string) (PolicyTemplate, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	tmpl, ok := t.templates[name]
	return tmpl, ok
}

func (t *TemplateSyncer) pullOnce(ctx context.Context) {
	dialCtx, cancel := context.WithTimeout(ctx, t.cfg.DialTimeout)
	defer cancel()
	creds := credentials.NewTLS(t.cfg.TLSConfig)
	if t.cfg.TLSConfig == nil {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.DialContext(dialCtx, t.cfg.Endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		t.warn("dial", err)
		return
	}
	defer conn.Close()
	cli := pb.NewControlPlaneClient(conn)

	rpcCtx, rpcCancel := context.WithTimeout(withAuth(ctx, t.cfg.Token), 10*time.Second)
	defer rpcCancel()
	resp, err := cli.ListTemplates(rpcCtx, &pb.ListTemplatesRequest{})
	if err != nil {
		t.warn("list", err)
		return
	}
	next := make(map[string]PolicyTemplate, len(resp.Templates))
	for _, pbT := range resp.Templates {
		nat := fromPBTemplate(pbT)
		next[nat.Name] = nat
	}
	t.mu.Lock()
	t.templates = next
	t.mu.Unlock()
	if t.cfg.CacheDir != "" {
		t.saveToDisk(next)
	}
	if t.cfg.Logger != nil {
		t.cfg.Logger.Debug("templates synced", "count", len(next), "peer", t.cfg.Endpoint)
	}
}

func (t *TemplateSyncer) saveToDisk(set map[string]PolicyTemplate) {
	keep := make(map[string]struct{}, len(set))
	for name, tmpl := range set {
		fileName := sanitiseTemplateName(name) + ".json"
		keep[fileName] = struct{}{}
		fp := filepath.Join(t.cfg.CacheDir, fileName)
		body, err := json.MarshalIndent(tmpl, "", "  ")
		if err != nil {
			continue
		}
		tmp := fp + ".part"
		if err := os.WriteFile(tmp, body, 0o600); err != nil {
			continue
		}
		if err := os.Rename(tmp, fp); err != nil {
			_ = os.Remove(tmp)
		}
	}
	entries, err := os.ReadDir(t.cfg.CacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".part") {
			_ = os.Remove(filepath.Join(t.cfg.CacheDir, name))
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		_ = os.Remove(filepath.Join(t.cfg.CacheDir, name))
	}
}

func (t *TemplateSyncer) loadFromDisk() {
	entries, err := os.ReadDir(t.cfg.CacheDir)
	if err != nil {
		return
	}
	loaded := map[string]PolicyTemplate{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(t.cfg.CacheDir, e.Name()))
		if err != nil {
			continue
		}
		var tmpl PolicyTemplate
		if err := json.Unmarshal(body, &tmpl); err != nil {
			continue
		}
		if tmpl.Name == "" {
			continue
		}
		loaded[tmpl.Name] = tmpl
	}
	t.mu.Lock()
	t.templates = loaded
	t.mu.Unlock()
}

func (t *TemplateSyncer) warn(stage string, err error) {
	if t.cfg.Logger == nil || errors.Is(err, context.Canceled) {
		return
	}
	t.cfg.Logger.Warn("template sync failed", "stage", stage, "error", err, "peer", t.cfg.Endpoint)
}

func sanitiseTemplateName(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}
