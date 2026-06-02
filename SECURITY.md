# Security Policy

This module handles TLS private keys: it fetches certificate bundles over HTTP and, when `cache_dir`
is configured, writes them to disk. Security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email **support@ohdear.app** with the details. Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept, and
- the version (git tag or commit) you tested.

You will get an acknowledgement within a few business days. Once the issue is confirmed and a fix is
available, we will release it and credit you in the release notes unless you prefer to stay anonymous.

## Scope

In scope: anything that could expose cached private keys, serve a wrong or stale certificate, or let
an attacker influence which certificate is served (for example via the cache key or the upstream
request shape).

Out of scope: vulnerabilities in Caddy, certmagic, or other upstream dependencies. Report those to
their respective maintainers.
