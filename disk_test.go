package cachedcert

import (
	"context"
	"errors"
	"net/http"
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

func TestSNIFromFile(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantSNI string
		wantOK  bool
	}{
		{"valid", sniCommentPrefix + "status.example.com\n-----BEGIN CERTIFICATE-----\n", "status.example.com", true},
		{"crlf", sniCommentPrefix + "status.example.com\r\n-----BEGIN CERTIFICATE-----\n", "status.example.com", true},
		{"no newline", sniCommentPrefix + "status.example.com", "", false},
		{"empty sni", sniCommentPrefix + "\n", "", false},
		{"missing prefix", "no header here\n-----BEGIN CERTIFICATE-----\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sni, ok := sniFromFile([]byte(tc.data))
			if ok != tc.wantOK {
				t.Fatalf("sniFromFile ok = %v, want %v", ok, tc.wantOK)
			}
			if sni != tc.wantSNI {
				t.Errorf("sniFromFile sni = %q, want %q", sni, tc.wantSNI)
			}
		})
	}
}

func TestLoadFromDiskSkipsBadFilesAndTempFiles(t *testing.T) {
	dir := t.TempDir()
	bundle := testPEMBundle(t, "good.example.com")

	g := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := g.persist("good.example.com", bundle); err != nil {
		t.Fatalf("persist: %v", err)
	}
	// A .pem file that is not a valid bundle must be skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "garbage.pem"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stray temp file must be ignored by the *.pem load glob.
	if err := os.WriteFile(filepath.Join(dir, ".tmp-leftover"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}

	reader := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := reader.loadFromDisk(); err != nil {
		t.Fatalf("loadFromDisk should skip bad files, got: %v", err)
	}

	if _, ok := reader.load("good.example.com"); !ok {
		t.Error("expected the valid certificate to be warm")
	}
	count := 0
	reader.cache.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Errorf("expected exactly 1 warm entry, got %d", count)
	}
}

func TestServeStaleFallsBackToCacheDir(t *testing.T) {
	dir := t.TempDir()
	up := newUpstream(t, serveStatus(http.StatusServiceUnavailable))

	writer := &CachedHTTPGetter{CacheDir: dir, cache: new(sync.Map), now: time.Now}
	if err := writer.persist("status.example.com", testPEMBundle(t, "status.example.com")); err != nil {
		t.Fatalf("persist: %v", err)
	}

	g := newTestGetter(t, up.URL)
	g.CacheDir = dir

	cert, err := g.GetCertificate(context.Background(), helloFor("status.example.com"))
	if err != nil {
		t.Fatalf("expected the certificate from cache_dir, got error: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected a certificate")
	}
	if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err != nil {
		t.Fatal(err)
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (the stale certificate is cached for stale_ttl)", got)
	}
}

func TestNoContentRemovesPersistedCert(t *testing.T) {
	dir := t.TempDir()
	up := newUpstream(t, serveBundle(testPEMBundle(t, "status.example.com")))

	current := time.Now()
	g := newTestGetter(t, up.URL)
	g.CacheDir = dir
	g.now = func() time.Time { return current }

	if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(g.diskPath("status.example.com")); err != nil {
		t.Fatalf("expected the certificate to be persisted: %v", err)
	}

	up.set(serveStatus(http.StatusNoContent))
	current = current.Add(61 * time.Second)
	if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(g.diskPath("status.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the persisted certificate to be removed after a 204, stat err: %v", err)
	}
}
