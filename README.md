# caddy-get-certificate-cache

[![Go Reference](https://pkg.go.dev/badge/github.com/ohdearapp/caddy-get-certificate-cache.svg)](https://pkg.go.dev/github.com/ohdearapp/caddy-get-certificate-cache)
[![CI](https://github.com/ohdearapp/caddy-get-certificate-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/ohdearapp/caddy-get-certificate-cache/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ohdearapp/caddy-get-certificate-cache)](https://goreportcard.com/report/github.com/ohdearapp/caddy-get-certificate-cache)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

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
xcaddy build --with github.com/ohdearapp/caddy-get-certificate-cache
```

To build against a local checkout (for development), point the module at it with a `replace`:

```bash
git clone https://github.com/ohdearapp/caddy-get-certificate-cache.git
xcaddy build --with github.com/ohdearapp/caddy-get-certificate-cache=./caddy-get-certificate-cache
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
        stale_ttl    60s
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
| `stale_ttl` | duration | `60s` | How long the last good certificate is served after a failed fetch before the upstream is tried again. See [When the upstream fails](#when-the-upstream-fails). |
| `cache_dir` | path | (disabled) | If set, fetched certificate bundles are persisted here (`0600` files in a `0700` directory) and loaded on startup, so the cache survives restarts. **Contains private keys.** |

### Behaviour

- **HTTP 200**: response body is parsed as a PEM bundle (certificate chain + private key) and cached.
- **HTTP 204**: cached as a negative entry for `negative_ttl`; the handshake falls through to
  Caddy's on-demand / `ask` flow. The certificate for that name is also removed from `cache_dir`.
- **Any other status, a network error, a timeout or a parse error**: the fetch has failed. See
  below.
- Concurrent cache misses for the same name are coalesced into a single upstream request.
- Each upstream fetch is bounded by a 10s timeout, and it does not inherit the per-handshake
  context, so one client disconnecting cannot cancel a fetch that other handshakes are waiting on.
- Entries loaded from `cache_dir` on startup are re-aged: they get a fresh TTL on load (the
  original `Cache-Control` is not persisted), so a warm-restart entry re-validates within one TTL.

### When the upstream fails

A failed fetch does not fail the handshake when there is a last good certificate for the name.
The module serves that certificate instead, and logs a warning:

```
upstream certificate fetch failed, serving the last good certificate  {"sni": "status.example.com", "error": "got HTTP 503", ...}
```

- The last good certificate comes from memory. When memory has nothing for the name, it is read
  from `cache_dir`.
- It is only served while it is still valid. Once its `NotAfter` has passed, the fetch error is
  returned and the handshake fails.
- It is cached for `stale_ttl`. The upstream is tried again once that runs out. So a failing
  upstream gets at most one request per name per `stale_ttl`, and the warning is logged once per
  name per `stale_ttl`, not once per handshake.
- A 204 still means "no certificate". After a 204 there is no last good certificate for that name,
  so an outage after a 204 fails the handshake.
- With no last good certificate, the error is returned and **not** cached, so the next handshake
  tries the upstream again.

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
