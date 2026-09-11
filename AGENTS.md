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

## Documentation

- Keep the README concise and user-facing. Leave private review status, naming rationale, internal architecture, and implementation notes out of it.
- Take ScopeQL examples from ScopeDB documentation or tests instead of inventing syntax.
- Keep each Markdown prose paragraph and list item on one source line. Format Markdown tables so their columns and separators align in the source.

## Changelog

- Update `CHANGELOG.md` in the same PR as significant changes observable by `scope` users. Compare the final behavior with the preceding release tag, including release candidates; use the latest tag as the baseline for `Unreleased`.
- Include new capabilities, breaking changes, correctness or compatibility fixes, and concrete improvements to existing behavior. Exclude documentation edits, tests, internal refactors, CI, tooling, and dependency maintenance unless they change what users can run or observe; describe that effect when they do.
- Verify that a bug existed in the baseline release before listing a fix. For changes to unreleased functionality, describe its final behavior in the feature entry and omit intermediate corrections.
- Keep `## Unreleased` at the top and group entries under `### Breaking changes`, `### New features`, `### Bug fixes`, and `### Improvements`, in that order, omitting empty categories. Put finalized entries under their release version below `Unreleased`.
- Write one bullet per coherent user-visible change, naming the affected command or workflow and its result. Include migration steps for breaking changes and limit performance claims to workloads supported by evidence. Omit commit history, PR or issue numbers, and implementation details unless needed to understand compatibility, migration, or risk.

## Pull requests

- Use the semantic title format defined in `.github/semantic.yml`, write the entire title in lowercase, and keep the description concise.
- Use a `Summary` section for simple pull requests. Add `Design Notes` only when needed, and do not list test commands in the pull request description.
