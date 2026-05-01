package api

import (
	"sort"
	"sync"

	"firefik/internal/config"
)

type TemplateStore struct {
	mu    sync.RWMutex
	byKey map[string]config.RuleTemplate
}

func NewTemplateStore(initial map[string]config.RuleTemplate) *TemplateStore {
	s := &TemplateStore{byKey: make(map[string]config.RuleTemplate, len(initial))}
	for k, v := range initial {
		s.byKey[k] = v
	}
	return s
}

func (s *TemplateStore) Set(templates map[string]config.RuleTemplate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey = make(map[string]config.RuleTemplate, len(templates))
	for k, v := range templates {
		s.byKey[k] = v
	}
}

func (s *TemplateStore) Get(name string) (config.RuleTemplate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byKey[name]
	return t, ok
}

func (s *TemplateStore) List() []config.RuleTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]config.RuleTemplate, 0, len(s.byKey))
	for _, v := range s.byKey {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
