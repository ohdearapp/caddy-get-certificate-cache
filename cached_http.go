// Package cachedcert provides a Caddy tls.get_certificate module that caches
// certificates fetched over HTTP, so they are served from memory on subsequent
// TLS handshakes instead of re-fetched every time.
package cachedcert

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	// defaultTTL is used for a cached certificate when neither an explicit ttl
	// is configured nor an s-maxage is present on the response. It matches the
	// staleness bound of the Varnish layer it replaces.
	defaultTTL = 60 * time.Second

	// defaultNegativeTTL is how long a 204 ("no certificate here") response is
	// remembered when no negative_ttl is configured.
	defaultNegativeTTL = 60 * time.Second
)

func init() {
	caddy.RegisterModule(new(CachedHTTPGetter))
}

// CachedHTTPGetter is a certmagic.Manager that fetches certificates from an
// HTTP endpoint (like Caddy's stock tls.get_certificate.http) and caches the
// result in memory, optionally persisting it to disk for warm restarts.
type CachedHTTPGetter struct {
	// URL is the endpoint queried on a cache miss. The certificate-providing
	// server_name (and the handshake's signature_schemes / cipher_suites) are
	// added as query parameters, identical to the stock http getter.
	URL string `json:"url,omitempty"`

	// TTL, when set, is how long a fetched certificate is cached. When zero,
	// the s-maxage of the response's Cache-Control header is used, falling back
	// to defaultTTL.
	TTL caddy.Duration `json:"ttl,omitempty"`

	// NegativeTTL is how long a 204 (no certificate) response is cached. When
	// zero, defaultNegativeTTL is used.
	NegativeTTL caddy.Duration `json:"negative_ttl,omitempty"`

	// CacheDir, when set, persists fetched certificate bundles to disk so the
	// cache survives a restart. Files are written 0600 in a 0700 directory.
	CacheDir string `json:"cache_dir,omitempty"`

	cache  *sync.Map // sni(string) -> *cacheEntry
	group  singleflight.Group
	logger *zap.Logger
	ctx    caddy.Context
	now    func() time.Time
}

type cacheEntry struct {
	cert     *tls.Certificate
	expires  time.Time
	negative bool
}

// CaddyModule returns the Caddy module information.
func (*CachedHTTPGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.cached_http",
		New: func() caddy.Module { return new(CachedHTTPGetter) },
	}
}

// Provision sets up the module.
func (g *CachedHTTPGetter) Provision(ctx caddy.Context) error {
	g.ctx = ctx
	g.logger = ctx.Logger()
	if g.cache == nil {
		g.cache = new(sync.Map)
	}
	if g.now == nil {
		g.now = time.Now
	}
	if g.CacheDir != "" {
		if err := g.loadFromDisk(); err != nil {
			return fmt.Errorf("loading cache_dir %q: %w", g.CacheDir, err)
		}
	}
	return nil
}

// Validate ensures the module is configured correctly.
func (g *CachedHTTPGetter) Validate() error {
	if g.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}

// UnmarshalCaddyfile parses the get_certificate cached_http directive:
//
//	cached_http <url> {
//	    ttl          <duration>
//	    negative_ttl <duration>
//	    cache_dir    <path>
//	}
func (g *CachedHTTPGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name
	if !d.NextArg() {
		return d.ArgErr()
	}
	g.URL = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing ttl: %v", err)
			}
			g.TTL = caddy.Duration(dur)
		case "negative_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing negative_ttl: %v", err)
			}
			g.NegativeTTL = caddy.Duration(dur)
		case "cache_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.CacheDir = d.Val()
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

func (g *CachedHTTPGetter) ttlFor(cacheControl string) time.Duration {
	if g.TTL > 0 {
		return time.Duration(g.TTL)
	}
	if d, ok := parseSMaxAge(cacheControl); ok {
		return d
	}
	return defaultTTL
}

func (g *CachedHTTPGetter) negativeTTL() time.Duration {
	if g.NegativeTTL > 0 {
		return time.Duration(g.NegativeTTL)
	}
	return defaultNegativeTTL
}

// parseSMaxAge extracts the s-maxage value (in seconds) from a Cache-Control
// header value. Returns ok=false when absent or unparseable.
func parseSMaxAge(cacheControl string) (time.Duration, bool) {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		value, found := strings.CutPrefix(part, "s-maxage=")
		if !found {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimSpace(value))
		// Treat a missing/garbage value the same as s-maxage<=0: fall back to
		// defaultTTL. A 0s cache would re-fetch on every handshake, defeating
		// the point of this module, and the upstream uses s-maxage purely as a
		// positive staleness bound (it signals "no cert" via a 204, not via
		// s-maxage=0).
		if err != nil || seconds <= 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	return 0, false
}

// load returns a live (unexpired) cache entry for sni, if present.
func (g *CachedHTTPGetter) load(sni string) (*cacheEntry, bool) {
	v, ok := g.cache.Load(sni)
	if !ok {
		return nil, false
	}
	entry := v.(*cacheEntry)
	if !g.now().Before(entry.expires) {
		return nil, false
	}
	return entry, true
}

func (g *CachedHTTPGetter) store(sni string, entry *cacheEntry) {
	g.cache.Store(sni, entry)
}

type fetchResult struct {
	cert     *tls.Certificate
	negative bool
}

// GetCertificate implements certmagic.Manager. It is called on every TLS
// handshake, so the hot path is a map lookup; only a miss performs HTTP.
func (g *CachedHTTPGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := strings.ToLower(hello.ServerName)

	if entry, ok := g.load(sni); ok {
		if entry.negative {
			return nil, nil
		}
		return entry.cert, nil
	}

	result, err, _ := g.group.Do(sni, func() (any, error) {
		// Another goroutine may have populated the cache while we waited on
		// singleflight; re-check before paying for an HTTP request.
		if entry, ok := g.load(sni); ok {
			return fetchResult{cert: entry.cert, negative: entry.negative}, nil
		}
		return g.fetch(ctx, sni, hello)
	})
	if err != nil {
		return nil, err
	}

	res := result.(fetchResult)
	if res.negative {
		return nil, nil
	}
	return res.cert, nil
}

// fetch queries the upstream URL for sni and caches the outcome. The request
// shape mirrors Caddy's stock tls.get_certificate.http getter.
func (g *CachedHTTPGetter) fetch(ctx context.Context, sni string, hello *tls.ClientHelloInfo) (fetchResult, error) {
	sigs := make([]string, len(hello.SignatureSchemes))
	for i, sig := range hello.SignatureSchemes {
		sigs[i] = fmt.Sprintf("%x", uint16(sig))
	}
	suites := make([]string, len(hello.CipherSuites))
	for i, cs := range hello.CipherSuites {
		suites[i] = fmt.Sprintf("%x", cs)
	}

	parsed, err := url.Parse(g.URL)
	if err != nil {
		return fetchResult{}, err
	}
	qs := parsed.Query()
	qs.Set("server_name", hello.ServerName)
	qs.Set("signature_schemes", strings.Join(sigs, ","))
	qs.Set("cipher_suites", strings.Join(suites, ","))
	if hello.Conn != nil {
		if localIP, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil && localIP != "" {
			qs.Set("local_ip", localIP)
		}
	}
	parsed.RawQuery = qs.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fetchResult{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		g.store(sni, &cacheEntry{negative: true, expires: g.now().Add(g.negativeTTL())})
		return fetchResult{negative: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, fmt.Errorf("got HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fetchResult{}, fmt.Errorf("reading response body: %w", err)
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(body)
	if err != nil {
		return fetchResult{}, err
	}

	ttl := g.ttlFor(resp.Header.Get("Cache-Control"))
	g.store(sni, &cacheEntry{cert: &cert, expires: g.now().Add(ttl)})

	if g.CacheDir != "" {
		if err := g.persist(sni, body); err != nil {
			g.logger.Warn("persisting certificate to cache_dir failed",
				zap.String("sni", sni), zap.Error(err))
		}
	}

	return fetchResult{cert: &cert}, nil
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*CachedHTTPGetter)(nil)
	_ caddy.Validator       = (*CachedHTTPGetter)(nil)
	_ caddyfile.Unmarshaler = (*CachedHTTPGetter)(nil)
	_ certmagic.Manager     = (*CachedHTTPGetter)(nil)
)

// loadFromDisk is implemented in disk.go (Task 5). Temporary stub so Task 3 compiles.
func (g *CachedHTTPGetter) loadFromDisk() error { return nil }

// persist is implemented in disk.go (Task 5). Temporary stub so this compiles.
func (g *CachedHTTPGetter) persist(sni string, bundle []byte) error { return nil }
