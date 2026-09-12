# Contributing to Tidegate

Thanks for your interest in making AI agents safer to use. 🦞🐚

## Ways to contribute

- **Bug reports** — found a redaction bypass, a crash, or a routing bug? Open an issue.
- **New patterns** — know an API key format, PII pattern, or sensitive data type we missed? Add it to the rules.
- **New cloud provider routes** — want to see Google, Cohere, or HuggingFace supported? Add a route in the router.
- **Agent integrations** — tested Tidegate with an agent we don't list? Let us know.
- **Docs** — clearer docs save someone's data.

## Before you start

1. **Go 1.25+** — Tidegate uses recent Go features.
2. **Ollama** (optional) — needed for `local-only` tier testing. `tidegate setup-ollama` configures a model.
3. Clone, build, and run tests:

```bash
git clone https://github.com/qo-roj/tidegate.git
cd tidegate
make build
make test        # runs all tests with -race
```

## Pull request checklist

- [ ] Tests pass: `make test`
- [ ] Code is formatted: `make fmt`
- [ ] If adding a new redaction pattern, add a test case for it
- [ ] If adding a new route, document the path prefix in the README
- [ ] If changing behavior, update the relevant doc in `docs/`

## Redaction patterns

Patterns live in `rules/defaults.conf` (and embedded in the binary via `go:embed`). To add a new pattern:

1. Add a `[patterns]` entry in `rules/defaults.conf` with a regex
2. Add test cases in `internal/redact/redactor_test.go`
3. Run `make test` to verify

## Architecture overview

See [`docs/architecture.md`](docs/architecture.md) for the full design. Quick summary:

- `internal/redact/` — pattern matching and token replacement
- `internal/classify/` — content tier classification (public / redacted / local-only / blocked)
- `internal/route/` — routing logic: what goes to cloud, what goes to Ollama
- `internal/proxy/` — HTTP reverse proxy with SSE streaming
- `internal/rules/` — config parser (file + embedded defaults)
- `internal/audit/` — SQLite audit log
- `internal/ollama/` — local model client with two-stage redaction
- `internal/config/` — layered config loading

## Security disclosures

Found a way to bypass redaction? **Please don't open a public issue.**

Email the maintainers directly so we can fix it before disclosure. Include:
- The input that bypassed redaction
- Which tier it should have been classified as
- What the cloud API received

## Code style

- Go conventions: `gofmt`, `go vet`, meaningful commit messages
- Keep functions focused — the codebase is deliberately small
- Tests alongside code in the same package (`*_test.go`)

---

*The tide comes in. The shell decides what stays.*