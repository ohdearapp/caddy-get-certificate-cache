package cachedcert

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
		data, err := os.ReadFile(path)
		if err != nil {
			g.warn("reading cached certificate failed", path, err)
			continue
		}

		sni, ok := sniFromFile(data)
		if !ok {
			g.warn("cached certificate missing sni header, skipping", path, nil)
			continue
		}

		cert, err := tlsCertFromCertAndKeyPEMBundle(data)
		if err != nil {
			g.warn("parsing cached certificate failed", path, err)
			continue
		}

		g.store(sni, &cacheEntry{cert: &cert, expires: g.now().Add(g.ttlFor(""))})
	}
	return nil
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
	first := string(data[:newline])
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
