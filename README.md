# caddy-cached-cert

A [Caddy](https://caddyserver.com) module that caches `get_certificate` results in-process, so
externally-provided TLS certificates are served from memory instead of being re-fetched over HTTP
on every handshake.

## Why

Caddy's certificate manager library, [certmagic](https://github.com/caddyserver/certmagic), does
**not** cache the result of a `get_certificate` manager: by design it calls the manager on *every*
TLS handshake (see [caddyserver/caddy#7038](https://github.com/caddyserver/caddy/issues/7038)). For
certificates fetched from an HTTP endpoint via the stock
[`tls.get_certificate.http`](https://caddyserver.com/docs/modules/tls.get_certificate.http) getter,
that means a backend round trip on every handshake, even though the certificate rarely changes.

This module is a drop-in alternative that wraps the same HTTP fetch with an in-process cache. The
hot path becomes a map lookup (microseconds) instead of an HTTP request.

## Module ID

`tls.get_certificate.cached_http` (implements `certmagic.Manager`).

## Install

Build Caddy with this module using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/ohdear/caddy-cached-cert
```

> Because the module is compiled into Caddy, upgrading Caddy means re-running `xcaddy` with the
> module included.

## Configuration

### Caddyfile

```caddy
tls {
    get_certificate cached_http https://app.example.com/cert {
        ttl          1h
        negative_ttl 60s
        cache_dir    /var/cache/caddy-certs
    }
    on_demand
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| (argument) | URL | — (required) | Endpoint queried on a cache miss. `server_name`, `signature_schemes`, `cipher_suites` (and `local_ip` when available) are added as query parameters, identical to the stock `http` getter. |
| `ttl` | duration | from response | How long a fetched certificate is cached. When omitted, the `s-maxage` of the response's `Cache-Control` header is used, falling back to `60s`. |
| `negative_ttl` | duration | `60s` | How long a `204` ("no certificate for this name") response is remembered before re-querying. |
| `cache_dir` | path | (disabled) | If set, fetched certificate bundles are persisted here (`0600` files in a `0700` directory) and loaded on startup, so the cache survives restarts. **Contains private keys.** |

### Behaviour

- **HTTP 200**: response body is parsed as a PEM bundle (certificate chain + private key) and cached.
- **HTTP 204**: cached as a negative entry for `negative_ttl`; the handshake falls through to
  Caddy's on-demand / `ask` flow.
- **Any other status, or a parse error**: returned as an error and **not** cached, so a transient
  upstream failure is retried on the next handshake.
- Concurrent cache misses for the same name are coalesced into a single upstream request.
- Each upstream fetch is bounded by a 10s timeout, and it does not inherit the per-handshake
  context, so one client disconnecting cannot cancel a fetch that other handshakes are waiting on.

## Running the tests

```bash
go test ./...
go test -race ./...   # what CI runs
gofmt -l .            # must print nothing
go vet ./...
```

Requires Go 1.25 or newer.

## Deployment notes

- Point `cache_dir` at a directory only the Caddy user can read; it stores private keys. The `0700`
  mode is applied only when the module creates the directory.
- Keep the previous Caddy binary around for instant rollback after swapping in a build that
  includes this module.

## License

[Apache-2.0](LICENSE).
