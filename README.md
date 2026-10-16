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
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
scope query 'FROM system.tables LIMIT 10'
```

`scope auth login` opens your browser, asks you to approve the request in the ScopeDB Console, and stores the login in the operating system keyring. On a machine without a browser, such as an SSH session, use `scope auth login --device` and approve the printed link or code from another device; add `--open` to open the prefilled link in a browser on the machine running the CLI. The CLI never switches between the two flows on its own. Pass `--workspace <id-or-name>` to choose the workspace for the login. Without it, the login keeps the workspace already selected for the profile or selects the only workspace the account owns; an account with several workspaces gets the list and a prompt to choose, so the CLI never picks one at random.

A pending account or an account without a workspace can stay logged in; `scope auth status` shows the account status and next steps. Run `scope console --open` to check approval status or create your first workspace in the Console. Once a workspace is available, select it without logging in again:

```sh
scope workspace list
scope workspace use <id-or-name>
scope workspace create --name analytics
scope auth status
```

The workspace selection is stored locally for the current login, so it does not affect your Console session or another machine. `scope workspace create` selects the workspace it created when the login has no selection yet, and leaves an existing selection alone. `scope auth status` shows the credential source, identity, and connection target. Use `scope workspace get` for deployment details and `scope doctor` to verify query access.

`scope console [page]` provides shortcuts to Console pages: `home` (default), `query`, `data`, `keys`, and `connect`. For example, `scope console query` prints the query page URL; add `--open` to also open it in your browser.

## Query output

Queries can be provided inline, from a file with `--file` or `-f`, or through stdin. Use `--format` to select the output format. Results can be rendered as a table, JSON, JSON Lines, or CSV.

```sh
scope query -f report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv --output tables.csv
```

Files created with `scope query --output` have permissions `0600` on Unix-like systems.

## JSON output

Business commands support `--format json` for scripts while keeping their usual human-readable output by default. Action commands return an object describing the result; `scope auth logout` reports `changed: true` when it clears an existing login and `changed: false` when already logged out.

```sh
scope auth status --format json
scope workspace use <id-or-name> --format json
scope console --format json
```

Results go to stdout; prompts, warnings, and errors go to stderr. `scope doctor --format json` prints its report and exits nonzero if checks fail. `scope version --format json` prints machine-readable version information; `--json` is also supported.

`scope workspace list` accepts `--limit N` to show at most N items. The default and `--limit 0` show all items. This limits displayed results without reducing the amount fetched.

Run `scope --help` or `scope <command> --help` for the complete command reference. See the [ScopeDB documentation](https://docs.scopedb.io/) for ScopeQL and service documentation.

## Automation

For CI and other non-interactive environments, set the data-plane endpoint and API key:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"

scope doctor
scope query --format json 'SELECT 1 AS ready'
```

Both variables are required and override the saved login for queries, `auth status`, and connection checks. Setting only one fails instead of falling back to your login. Unset both to return to your logged-in workspace.

For SDK setup, get the endpoint with `scope workspace get` and create an application key in the [Console](https://console.scopedb.io/keys). Use the same endpoint and key in your SDK configuration, then run `scope doctor` to verify them. See the [CLI and SDK connection guide](docs/connect.md) for the complete workflow and troubleshooting.

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
