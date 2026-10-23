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

`scope auth login` opens your browser, asks you to approve the request in the ScopeDB Console, and stores the login in the operating system keyring. Upgrading from an older CLI asks you to log in again. If the browser does not open, open the printed URL on the same device. For approval from another device, such as when using SSH or a container, run `scope auth login --use-device-code`. Add `--no-browser` to either flow to skip opening the browser automatically. A browser-launch failure leaves the selected flow waiting for approval.

Login does not require an interactive terminal. Authorization instructions and progress go to stderr; `--format text|json` selects the result format on stdout. For unattended access, use `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`; `scope auth status --format json` and `scope workspace list --format json` report machine-readable state.

Pass `--workspace <id-or-name>` to select a workspace explicitly. Without it, the login keeps the workspace already selected for the profile if the account still owns it and it is not scheduled for deletion. Otherwise, it selects the first available workspace by ID, even when several workspaces are available. The text and JSON results report the selected workspace name and ID. Use `scope workspace use <id-or-name>` to switch afterwards.

A pending account or an account without a workspace can stay logged in; `scope auth status` shows the account status and next steps. Run `scope console --open` to check approval status and create your first workspace in the Console. Once a workspace is available, select it without logging in again:

```sh
scope workspace list
scope workspace use <id-or-name>
scope auth status
```

The workspace selection is stored locally for the current login, so it does not affect your Console session or another machine. `scope auth status` shows the credential source, identity, and connection target. Use `scope workspace get` for deployment details and `scope doctor` to verify query access.

`scope console [page]` provides shortcuts to Console pages: `home` (default), `query`, `data`, `keys`, and `connect`. For example, `scope console query` prints the query page URL; add `--open` to also open it in your browser.

## Query output

Queries can be provided inline, from a file with `--file` or `-f`, or through stdin. Results go to stdout; use `--format` to select a table, JSON, JSON Lines, or CSV. Use shell redirection to save results to a file.

```sh
scope query -f report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv > tables.csv
```

The shell controls file replacement and permissions. Redirecting with `>` can truncate an existing file before the query runs; write to a temporary file and move it after success if you need to preserve the previous result on failure.

`scope query` and the query check in `scope doctor` require ScopeDB 0.6.0 or later. `--timeout` limits client-side waiting (default: five minutes) and attempts server cancellation when it expires. `--timeout 0` disables this client limit; the server's default one-hour elapsed-time limit still applies.

After a timeout or Ctrl+C, diagnostics include the statement ID and distinguish confirmed cancellation, an already completed statement, a server failure, and an unconfirmed outcome. The command keeps its timeout or interrupt exit code and writes no query results. If the statement already completed, retrieve its result using the ID instead of rerunning a statement with side effects.

## JSON output

Business commands support `--format json` for scripts while keeping their usual human-readable output by default. Action commands return an object describing the result; `scope auth logout` reports `changed: true` when it clears an existing login and `changed: false` when already logged out.

```sh
scope auth status --format json
scope workspace use <id-or-name> --format json
scope api-key revoke <name> --yes --format json
scope console --format json
```

Results go to stdout; prompts, warnings, and errors go to stderr. `scope doctor --format json` prints its report and exits nonzero if checks fail. `scope version --format json` prints machine-readable version information; `--json` is also supported.

`scope workspace list` and `scope api-key list` accept `--limit N` to show at most N items. The default and `--limit 0` show all items. This limits displayed results without reducing the amount fetched.

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

For SDK setup, get the endpoint with `scope workspace get` and create an application key with `scope api-key create <name>`. Use the same endpoint and key in your SDK configuration, then run `scope doctor` to verify them. See the [CLI and SDK connection guide](docs/connect.md) for the complete workflow and troubleshooting.

## Development

Development tools are managed with [mise](https://mise.jdx.dev/). Tasks use Bash (Git Bash on Windows):

```sh
mise install
mise run check
mise run test:race
mise run build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
