package cachedcert

import (
	"time"

	"github.com/caddyserver/caddy/v2"
)

// ExampleCachedHTTPGetter shows the configuration the module exposes. In
// practice it is registered as the Caddy module tls.get_certificate.cached_http
// and configured through the Caddyfile rather than constructed directly.
func ExampleCachedHTTPGetter() {
	getter := &CachedHTTPGetter{
		URL:         "https://app.example.com/cert",
		TTL:         caddy.Duration(time.Hour),
		NegativeTTL: caddy.Duration(time.Minute),
		CacheDir:    "/var/cache/caddy-certs",
	}
	_ = getter
}
