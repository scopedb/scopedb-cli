# ScopeDB CLI

`scope` is the command-line interface for ScopeDB Cloud. It is a thin SaaS client: authentication and workspace management use the ScopeDB control plane, while queries use the public [`goscopedb`](https://github.com/scopedb/goscopedb) data-plane client.

This repository is in private review. Command names and output contracts may change before the first public release.

## Why the binary is named `scope`

The product name remains ScopeDB; the command is deliberately shorter. A generic word can collide with another executable, so installation packages must own a single unambiguous `scope` binary and the documentation always uses the fully qualified product name “ScopeDB CLI.” The repository and release artifacts use `scopedb-cli` for discoverability.

## Install from source

Go 1.25 or newer is required when installing directly from source:

```sh
go install github.com/scopedb/scopedb-cli/cmd/scope@latest
```

Development tool versions are pinned with [mise](https://mise.jdx.dev/). During private review, build from a checkout instead:

```sh
mise install
mise run build
./bin/scope version
```

Tagged releases are configured to produce `scope` binaries for macOS, Linux, and Windows on amd64 and arm64.

## Quick start

Log in with an email verification code:

```sh
scope login
scope status
scope workspace list
scope query 'FROM events | LIMIT 10'
```

The login session and its short-lived data token are stored in the operating system keyring. On a host without a usable keyring, plaintext storage can be enabled explicitly:

```sh
scope login --insecure-storage
```

That fallback writes an unencrypted, permission-restricted credentials file. The CLI never silently downgrades to plaintext storage.

For CI and other non-interactive use, provide a data-plane endpoint and API key together:

```sh
SCOPEDB_ENDPOINT=https://your-workspace.example.com \
SCOPEDB_API_KEY=... \
scope query --format json 'FROM events | LIMIT 10'
```

If only one of those variables is present, the command fails instead of falling back to a cached human session.

## Commands

```text
scope login                         Start an email OTP session
scope logout                        Revoke the session and clear local credentials
scope status [-f table|json]        Show auth and current workspace state
scope workspace list                List accessible workspaces
scope workspace use <id-or-name>    Rotate the session to another workspace
scope workspace show                Show current workspace connection details
scope query [scopeql]                Execute a one-shot ScopeQL statement
scope api-key list                   List API keys without secrets
scope api-key create <name>          Create a key; its secret is shown once
scope api-key revoke <name>          Revoke a key by name
scope doctor                         Check config, credentials, and control-plane reachability
scope open [page]                    Open the ScopeDB console
scope completion <shell>             Generate shell completion
scope version                        Print build metadata
```

Query input can be an argument, a file, or stdin. Query results support table, JSON, JSON Lines, and CSV:

```sh
scope query --file report.scopeql --format csv --output report.csv
cat report.scopeql | scope query --format jsonl
```

Output files are not overwritten unless `--force` is passed. `Ctrl+C` triggers best-effort cancellation of an already submitted server-side statement.

## Configuration

Configuration precedence is command-line flags, environment, config file, then defaults. The config file contains no secrets.

`scope login` persists the resolved non-secret endpoints and credential-backend choice as the active profile, so a login performed with `--control-url` continues to work on later commands without repeating the flag.

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Control plane | `--control-url` | `SCOPEDB_CONTROL_URL` | `https://control.scopedb.cloud` |
| Web console | `--console-url` | `SCOPEDB_CONSOLE_URL` | `https://console.scopedb.cloud` |
| Credential backend | — | `SCOPEDB_CREDENTIAL_STORE` | `keyring` |

`SCOPEDB_CONFIG_DIR` overrides the platform-native config directory, primarily for development and isolated automation. `SCOPEDB_CREDENTIAL_STORE` accepts `keyring` or `plaintext`.

## Output and exit contract

Command results are written to stdout. Prompts, warnings, and operational messages are written to stderr, so structured output can be piped safely. Secrets are never included in errors or status output.

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | General failure |
| 2 | Invalid command usage or configuration |
| 3 | Authentication or authorization failure |
| 4 | Resource not found |
| 5 | Retryable or temporary failure |
| 130 | Interrupted |

## Architecture

The command layer contains orchestration only. It depends on small boundaries for configuration, credentials, the control plane, the data plane, and rendering:

```text
cmd/scope
  -> internal/cli
       -> internal/auth -> internal/controlplane
                        -> internal/credential
       -> internal/dataplane -> goscopedb
       -> internal/output
```

The control-plane client is handwritten and isolated because the service does not yet publish a versioned OpenAPI document. It is intended to be replaced by a generated client without changing command behavior once that contract exists. The CLI deliberately does not embed a ScopeQL parser or database engine.

## Development

```sh
mise install
mise run check
mise run test:race
mise run build
```

`mise run check` verifies formatting and module metadata, then runs `golangci-lint`. Network-facing tests use local `httptest` servers and do not require a ScopeDB account.

## License

Apache License 2.0. See [LICENSE](LICENSE).
