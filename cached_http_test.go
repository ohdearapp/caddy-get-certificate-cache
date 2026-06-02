package cachedcert

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	input := `cached_http https://app.example.com/cert {
		ttl 1h
		negative_ttl 30s
		cache_dir /var/cache/certs
	}`

	var g CachedHTTPGetter
	d := caddyfile.NewTestDispenser(input)
	if err := g.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if g.URL != "https://app.example.com/cert" {
		t.Errorf("URL = %q, want https://app.example.com/cert", g.URL)
	}
	if time.Duration(g.TTL) != time.Hour {
		t.Errorf("TTL = %v, want 1h", time.Duration(g.TTL))
	}
	if time.Duration(g.NegativeTTL) != 30*time.Second {
		t.Errorf("NegativeTTL = %v, want 30s", time.Duration(g.NegativeTTL))
	}
	if g.CacheDir != "/var/cache/certs" {
		t.Errorf("CacheDir = %q, want /var/cache/certs", g.CacheDir)
	}
}

func TestUnmarshalCaddyfileRequiresURL(t *testing.T) {
	var g CachedHTTPGetter
	d := caddyfile.NewTestDispenser(`cached_http`)
	if err := g.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error when no URL is given")
	}
}

func TestValidateRequiresURL(t *testing.T) {
	var g CachedHTTPGetter
	if err := g.Validate(); err == nil {
		t.Fatal("expected Validate to fail without a URL")
	}
	g.URL = "https://app.example.com/cert"
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate with URL: %v", err)
	}
}

func TestTTLFor(t *testing.T) {
	cases := []struct {
		name         string
		configured   time.Duration
		cacheControl string
		want         time.Duration
	}{
		{"configured wins", time.Hour, "public, s-maxage=60", time.Hour},
		{"s-maxage used", 0, "public, s-maxage=120", 120 * time.Second},
		{"fallback when no header", 0, "", defaultTTL},
		{"fallback when no s-maxage", 0, "public, max-age=10", defaultTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := CachedHTTPGetter{TTL: caddy.Duration(tc.configured)}
			got := g.ttlFor(tc.cacheControl)
			if got != tc.want {
				t.Errorf("ttlFor(%q) = %v, want %v", tc.cacheControl, got, tc.want)
			}
		})
	}
}

func TestProvisionSetsDefaults(t *testing.T) {
	g := CachedHTTPGetter{URL: "https://app.example.com/cert"}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if g.cache == nil {
		t.Error("expected cache to be initialized")
	}
	if g.now == nil {
		t.Error("expected now to be initialized")
	}
}

func TestParseSMaxAge(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		want         time.Duration
		wantOK       bool
	}{
		{"present", "public, s-maxage=120", 120 * time.Second, true},
		{"with spaces", "public,  s-maxage= 60 ", 60 * time.Second, true},
		{"zero is not ok", "public, s-maxage=0", 0, false},
		{"negative is not ok", "s-maxage=-5", 0, false},
		{"garbage is not ok", "public, s-maxage=abc", 0, false},
		{"absent", "public, max-age=10", 0, false},
		{"empty", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSMaxAge(tc.cacheControl)
			if ok != tc.wantOK {
				t.Fatalf("parseSMaxAge(%q) ok = %v, want %v", tc.cacheControl, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("parseSMaxAge(%q) = %v, want %v", tc.cacheControl, got, tc.want)
			}
		})
	}
}

func TestLoadTreatsExpiredEntryAsMiss(t *testing.T) {
	now := time.Now()
	g := CachedHTTPGetter{cache: new(sync.Map), now: func() time.Time { return now }}

	g.store("live.example.com", &cacheEntry{expires: now.Add(time.Minute)})
	g.store("stale.example.com", &cacheEntry{expires: now.Add(-time.Second)})

	if _, ok := g.load("live.example.com"); !ok {
		t.Error("expected a live entry to be a hit")
	}
	if _, ok := g.load("stale.example.com"); ok {
		t.Error("expected an expired entry to be a miss")
	}
	if _, ok := g.load("absent.example.com"); ok {
		t.Error("expected an absent entry to be a miss")
	}
}

func TestNegativeTTLDefault(t *testing.T) {
	var g CachedHTTPGetter
	if got := g.negativeTTL(); got != defaultNegativeTTL {
		t.Errorf("negativeTTL() = %v, want default %v", got, defaultNegativeTTL)
	}
	g.NegativeTTL = caddy.Duration(5 * time.Second)
	if got := g.negativeTTL(); got != 5*time.Second {
		t.Errorf("negativeTTL() = %v, want 5s", got)
	}
}

func TestUnmarshalCaddyfileRejectsUnknownSubdirective(t *testing.T) {
	var g CachedHTTPGetter
	d := caddyfile.NewTestDispenser(`cached_http https://app.example.com/cert {
		bogus 1h
	}`)
	if err := g.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for an unknown subdirective")
	}
}

func TestUnmarshalCaddyfileRejectsExtraArg(t *testing.T) {
	var g CachedHTTPGetter
	d := caddyfile.NewTestDispenser(`cached_http https://app.example.com/cert extra`)
	if err := g.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for an extra positional argument")
	}
}

func newTestGetter(t *testing.T, url string) *CachedHTTPGetter {
	t.Helper()
	return &CachedHTTPGetter{
		URL:   url,
		cache: new(sync.Map),
		now:   time.Now,
	}
}

func helloFor(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: host}
}

func TestGetCertificateCachesAfterFirstFetch(t *testing.T) {
	var hits int32
	bundle := testPEMBundle(t, "status.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)

	for i := 0; i < 3; i++ {
		cert, err := g.GetCertificate(context.Background(), helloFor("status.example.com"))
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if cert == nil || len(cert.Certificate) == 0 {
			t.Fatalf("handshake %d: expected a certificate", i)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (subsequent handshakes must be cached)", got)
	}
}

func TestGetCertificateRefetchesAfterExpiry(t *testing.T) {
	var hits int32
	bundle := testPEMBundle(t, "status.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Cache-Control", "public, s-maxage=60")
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	current := time.Now()
	g := newTestGetter(t, srv.URL)
	g.now = func() time.Time { return current }

	if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err != nil {
		t.Fatal(err)
	}
	current = current.Add(61 * time.Second)
	if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (expired entry must re-fetch)", got)
	}
}

func TestGetCertificateNoContentIsNegativeCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)

	for i := 0; i < 3; i++ {
		cert, err := g.GetCertificate(context.Background(), helloFor("unknown.example.com"))
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if cert != nil {
			t.Fatalf("handshake %d: expected nil cert for 204", i)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (204 must be negative-cached)", got)
	}
}

func TestGetCertificateErrorIsNotCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)

	for i := 0; i < 2; i++ {
		if _, err := g.GetCertificate(context.Background(), helloFor("status.example.com")); err == nil {
			t.Fatalf("handshake %d: expected an error for HTTP 500", i)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (errors must not be cached)", got)
	}
}

func TestGetCertificateSingleflightCollapsesConcurrentMisses(t *testing.T) {
	var hits int32
	bundle := testPEMBundle(t, "status.example.com")
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = g.GetCertificate(context.Background(), helloFor("status.example.com"))
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (singleflight must collapse concurrent misses)", got)
	}
}

func TestFetchSendsStockQueryParams(t *testing.T) {
	var gotQuery url.Values
	bundle := testPEMBundle(t, "status.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)
	hello := &tls.ClientHelloInfo{
		ServerName:       "status.example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
	}

	if _, err := g.GetCertificate(context.Background(), hello); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if got := gotQuery.Get("server_name"); got != "status.example.com" {
		t.Errorf("server_name = %q, want status.example.com", got)
	}
	if got := gotQuery.Get("signature_schemes"); got != "403" {
		t.Errorf("signature_schemes = %q, want 403 (hex of ECDSAWithP256AndSHA256)", got)
	}
	if got := gotQuery.Get("cipher_suites"); got != "1301" {
		t.Errorf("cipher_suites = %q, want 1301 (hex of TLS_AES_128_GCM_SHA256)", got)
	}
	if _, ok := gotQuery["local_ip"]; ok {
		t.Error("local_ip should be absent when hello.Conn is nil")
	}
}

func TestGetCertificateIgnoresCanceledHandshakeContext(t *testing.T) {
	bundle := testPEMBundle(t, "status.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	g := newTestGetter(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before the handshake calls in

	cert, err := g.GetCertificate(ctx, helloFor("status.example.com"))
	if err != nil {
		t.Fatalf("a canceled handshake context must not fail the fetch: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected a certificate despite the canceled handshake context")
	}
}
