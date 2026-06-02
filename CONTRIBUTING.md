# Contributing

Thanks for your interest in improving this module. Bug reports, fixes, and focused features are all
welcome.

## Development

Requires Go 1.25 or newer.

```bash
go test ./...        # run the tests
go test -race ./...  # what CI runs
gofmt -l .           # must print nothing
go vet ./...
golangci-lint run    # optional locally; runs in CI
```

## Pull requests

- Keep changes focused; one concern per PR.
- Add or update tests for any behaviour change. The race detector must stay green.
- Run `gofmt -l .` and make sure it prints nothing before pushing.
- Explain the *why* in the PR description, not just the *what*.

For anything security-related, see [SECURITY.md](SECURITY.md) instead of opening a public issue.
