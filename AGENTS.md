# ScopeDB CLI Repository Notes

The global working agreements apply. Keep this file limited to constraints specific to this repository.

## Product boundaries

- The installed binary is `scope`; the repository and release project are `scopedb-cli`.
- Treat this repository as a thin client for ScopeDB Cloud. Do not implement a ScopeQL parser, planner, or execution engine here.
- Keep control-plane DTOs and transport behavior inside `internal/controlplane`. Replace that package with generated code when a versioned OpenAPI contract becomes available.
- Use `github.com/scopedb/goscopedb` for data-plane behavior instead of duplicating its wire protocol.

## CLI contracts

- Write command payloads to stdout and prompts, warnings, and progress to stderr.
- Never include session tokens, API keys, verification codes, or credential file contents in logs or errors.
- Keep configuration precedence explicit: flags, environment, config file, defaults. Do not add Viper or implicit environment binding.
- The OS keyring is the default credential store. Plaintext storage must remain an explicit opt-in and must use restrictive file permissions.
- Machine authentication requires both `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`; a partial pair must fail without falling back to human credentials.
- Preserve the documented exit-code contract and machine-readable output shapes.
- Any destructive command must require confirmation on a TTY and an explicit flag when non-interactive.

## Code and tests

- Keep Apache-2.0 headers on Go, TOML, and YAML files; `mise run fix` applies missing or stale headers.
- Construct Cobra commands through constructors and injected dependencies; do not register commands through package `init` functions or mutable globals.
- Keep domain and transport errors structured until the process boundary in `cmd/scope`.
- Add tests at observable boundaries: HTTP contracts, credential safety, auth resolution, cancellation, and rendered output. Avoid tests that merely mirror command registration or static literals.
- Run `mise run check` and `mise run test:race` before merging behavior changes.
