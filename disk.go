package cachedcert

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

const sniCommentPrefix = "# caddy-cached-cert sni="

// persist writes a certificate bundle to cache_dir as <sha256(sni)>.pem,
// prefixed with a comment line recording the SNI. The file is written 0600
// (it contains the private key) via a temp-file-and-rename for atomicity.
func (g *CachedHTTPGetter) persist(sni string, bundle []byte) error {
	if err := os.MkdirAll(g.CacheDir, 0o700); err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString(sniCommentPrefix)
	buf.WriteString(sni)
	buf.WriteByte('\n')
	buf.Write(bundle)

	path := g.diskPath(sni)
	tmp, err := os.CreateTemp(g.CacheDir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename below succeeded

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// No fsync before rename: this is a cache. A torn file after a crash just
	// fails to parse on the next load and the certificate is re-fetched.
	return os.Rename(tmpName, path)
}

// loadFromDisk reads every persisted bundle in cache_dir into the in-memory
// cache, so the cache is warm after a restart. The directory is created if it
// does not exist. Unreadable or unparseable files are logged and skipped.
func (g *CachedHTTPGetter) loadFromDisk() error {
	if err := os.MkdirAll(g.CacheDir, 0o700); err != nil {
		return err
	}

	entries, err := os.ReadDir(g.CacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		path := filepath.Join(g.CacheDir, entry.Name())
		sni, cert, err := readBundleFile(path)
		if err != nil {
			g.warn("loading cached certificate failed, skipping", path, err)
			continue
		}

		g.store(sni, &cacheEntry{cert: cert, expires: g.now().Add(g.ttlFor(""))})
	}
	return nil
}

// readFromDisk returns the certificate persisted in cache_dir for sni. A
// missing file is the normal case for a name that was never fetched, so only
// other problems are logged.
func (g *CachedHTTPGetter) readFromDisk(sni string) (*tls.Certificate, bool) {
	path := g.diskPath(sni)
	fileSNI, cert, err := readBundleFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		g.warn("loading cached certificate failed", path, err)
		return nil, false
	}
	if fileSNI != sni {
		g.warn("cached certificate belongs to another sni, skipping", path, nil)
		return nil, false
	}
	return cert, true
}

// forget removes the certificate persisted in cache_dir for sni. It runs after
// a 204, so a restart cannot load a certificate the upstream no longer serves,
// and an outage after the 204 cannot serve it as a stale certificate either.
func (g *CachedHTTPGetter) forget(sni string) {
	path := g.diskPath(sni)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		g.warn("removing cached certificate failed", path, err)
	}
}

// readBundleFile parses one file written by persist into its SNI and
// certificate.
func readBundleFile(path string) (string, *tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	sni, ok := sniFromFile(data)
	if !ok {
		return "", nil, fmt.Errorf("missing sni header")
	}
	cert, err := tlsCertFromCertAndKeyPEMBundle(data)
	if err != nil {
		return "", nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return sni, &cert, nil
}

func (g *CachedHTTPGetter) diskPath(sni string) string {
	sum := sha256.Sum256([]byte(sni))
	return filepath.Join(g.CacheDir, hex.EncodeToString(sum[:])+".pem")
}

// sniFromFile reads the SNI recorded in the leading comment line.
func sniFromFile(data []byte) (string, bool) {
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		return "", false
	}
	first := strings.TrimSuffix(string(data[:newline]), "\r")
	sni, found := strings.CutPrefix(first, sniCommentPrefix)
	if !found || sni == "" {
		return "", false
	}
	return sni, true
}

// warn logs a non-fatal disk-cache problem, tolerating a nil logger (unit
// tests construct the getter without Provision).
func (g *CachedHTTPGetter) warn(msg, path string, err error) {
	if g.logger == nil {
		return
	}
	fields := []zap.Field{zap.String("path", path)}
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	g.logger.Warn(msg, fields...)
}
