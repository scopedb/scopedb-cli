# ScopeDB CLI

`scope` is the command-line interface for [ScopeDB](https://www.scopedb.io/).

> [!IMPORTANT]
> ScopeDB CLI is in public preview. Current releases are release candidates intended for evaluation and may change before the first stable release.

## Install

### Prebuilt binaries

Download the release archive for your platform from [GitHub Releases](https://github.com/scopedb/scopedb-cli/releases):

| Platform               | Archive pattern                                  |
| ---------------------- | ------------------------------------------------ |
| macOS on Apple silicon | `scope_<version>_darwin_arm64.tar.gz`            |
| macOS on Intel         | `scope_<version>_darwin_amd64.tar.gz`            |
| Linux on x86-64        | `scope_<version>_linux_amd64.tar.gz`             |
| Linux on ARM64         | `scope_<version>_linux_arm64.tar.gz`             |
| Windows on x86-64      | `scope_<version>_windows_amd64.zip`              |
| Windows on ARM64       | `scope_<version>_windows_arm64.zip`              |

Compare the archive's SHA-256 digest with its entry in `checksums.txt`, extract it, and place `scope` (`scope.exe` on Windows) in a directory on your `PATH`.

For example, after extracting the archive on macOS or Linux:

```sh
mkdir -p "$HOME/.local/bin"
install -m 0755 scope "$HOME/.local/bin/scope"
scope version
```

Ensure `$HOME/.local/bin` is on your `PATH` before running `scope`.

### Install from source

With Go 1.27 or newer:

```sh
go install github.com/scopedb/scopedb-cli/cmd/scope@latest
```

## Get started

Sign in to ScopeDB Cloud and run a query:

```sh
scope login
scope status
scope doctor
scope query 'SELECT 1 AS ready'
scope query 'FROM system.tables LIMIT 10'
```

`scope login` prompts for an email address and verification code, then stores the session in the operating system keyring. A pending account or an account without a workspace can stay logged in; `scope status` shows the account status and next steps. Run `scope open` to check approval status or create your first workspace in the Console. Once a workspace is available, select it without logging in again:

```sh
scope workspace list
scope workspace use <id-or-name>
scope status
```

## Query output

Queries can be provided inline, from a file, or through stdin. Results can be rendered as a table, JSON, JSON Lines, or CSV.

```sh
scope query --file report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv --output tables.csv
```

Run `scope --help` or `scope <command> --help` for the complete command reference. See the [ScopeDB documentation](https://docs.scopedb.io/) for ScopeQL and service documentation.

## Automation

For CI and other non-interactive environments, set the data-plane endpoint and API key:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"

scope doctor
scope query --format json 'SELECT 1 AS ready'
```

Both variables are required and override the saved login for queries, status, and connection checks. Setting only one fails instead of falling back to your login. Unset both to return to your logged-in workspace.

For SDK setup, get the endpoint with `scope workspace show` and create an application key with `scope api-key create <name>`. Use the same endpoint and key in your SDK configuration, then run `scope doctor` to verify them. See the [CLI and SDK connection guide](docs/connect.md) for the complete workflow and troubleshooting.

## Development

Development tools are managed with [mise](https://mise.jdx.dev/):

```sh
mise install
mise run check
mise run test:race
mise run build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
