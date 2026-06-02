package cachedcert

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPersistWritesBundle0600(t *testing.T) {
	dir := t.TempDir()
	bundle := testPEMBundle(t, "status.example.com")

	g := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := g.persist("status.example.com", bundle); err != nil {
		t.Fatalf("persist: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
}

func TestLoadFromDiskWarmsCache(t *testing.T) {
	dir := t.TempDir()
	bundle := testPEMBundle(t, "status.example.com")

	writer := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := writer.persist("status.example.com", bundle); err != nil {
		t.Fatalf("persist: %v", err)
	}

	reader := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := reader.loadFromDisk(); err != nil {
		t.Fatalf("loadFromDisk: %v", err)
	}

	entry, ok := reader.load("status.example.com")
	if !ok {
		t.Fatal("expected the SNI to be warm in the cache after loadFromDisk")
	}
	if entry.cert == nil || len(entry.cert.Certificate) == 0 {
		t.Fatal("expected a parsed certificate in the warm entry")
	}
}

func TestLoadFromDiskMissingDirIsCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist-yet")

	g := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := g.loadFromDisk(); err != nil {
		t.Fatalf("loadFromDisk on a missing dir should create it, got: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected dir to be created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 700", perm)
	}
}
