package cachedcert

import (
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
