package autogen

import (
	"context"
	"path/filepath"
	"testing"
)

func TestObserverStoreHandleDefault(t *testing.T) {
	o := NewObserver()
	_ = o.StoreHandle()
}

func TestObserverStoreHandleSet(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteStore(context.Background(), tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	o := NewObserverWithStore(store)
	if o.StoreHandle() == nil {
		t.Errorf("expected non-nil")
	}
}
