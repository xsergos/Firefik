package api

import (
	"testing"

	"firefik/internal/config"
)

func TestTemplateStoreNew(t *testing.T) {
	s := NewTemplateStore(map[string]config.RuleTemplate{
		"a": {Name: "a"},
		"b": {Name: "b"},
	})
	if got, ok := s.Get("a"); !ok || got.Name != "a" {
		t.Errorf("got=%v ok=%v", got, ok)
	}
}

func TestTemplateStoreSetReplaces(t *testing.T) {
	s := NewTemplateStore(nil)
	s.Set(map[string]config.RuleTemplate{"x": {Name: "x"}})
	if _, ok := s.Get("x"); !ok {
		t.Errorf("missing x")
	}
	s.Set(map[string]config.RuleTemplate{"y": {Name: "y"}})
	if _, ok := s.Get("x"); ok {
		t.Errorf("x should be gone")
	}
	if _, ok := s.Get("y"); !ok {
		t.Errorf("missing y")
	}
}

func TestTemplateStoreList(t *testing.T) {
	s := NewTemplateStore(map[string]config.RuleTemplate{
		"b": {Name: "b"},
		"a": {Name: "a"},
		"c": {Name: "c"},
	})
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("len = %d", len(list))
	}
	if list[0].Name != "a" || list[1].Name != "b" || list[2].Name != "c" {
		t.Errorf("not sorted: %+v", list)
	}
}

func TestTemplateStoreGetMissing(t *testing.T) {
	s := NewTemplateStore(nil)
	if _, ok := s.Get("nope"); ok {
		t.Errorf("should not exist")
	}
}
