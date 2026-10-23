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

On Linux, the default login storage requires a working D-Bus session and Secret Service, such as GNOME Keyring. For servers or containers without a usable keyring, set both `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY` for queries, or explicitly run `scope auth login --use-device-code --no-browser --insecure-storage` to store login credentials unencrypted in a `0600` file. The CLI never switches to plaintext storage automatically. See [headless Linux setup](docs/connect.md#use-headless-linux) for both workflows.

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

Once a statement ID has been received, timeout and Ctrl+C diagnostics include it and distinguish confirmed cancellation, an already completed statement, a server failure, and an unconfirmed outcome. The command keeps its timeout or interrupt exit code and writes no query results. If the statement already completed, retrieve its result using the ID instead of rerunning a statement with side effects.

## Catalog

Catalog commands require ScopeDB 0.6.0 or later. `get`, `plan`, and `apply` default to the entire tenant. Select one resource with `--database DB`, `--schema DB.SCHEMA`, `--table DB.SCHEMA.TABLE`, or `--view DB.SCHEMA.VIEW`. These scope flags are mutually exclusive and require fully qualified names. Bare names are case insensitive; use backticks to preserve case or include special characters, for example ``'scopedb.public.`Events.Daily`'``.

Browse resource names, then export the definition to edit:

```sh
scope catalog list databases
scope catalog list schemas --database scopedb
scope catalog list tables --schema scopedb.public
scope catalog get --table scopedb.public.events > events.yaml
# Edit events.yaml.
scope catalog apply --table scopedb.public.events -f events.yaml
```

`list` supports databases, schemas, tables, and views. Limit schemas with `--database`; limit tables or views with `--database` or `--schema`. Returned names are fully qualified and can be passed to `get`.

A definition replaces the complete selected resource: omitted objects and fields are cleared. Start from `get` when editing an existing resource. `apply -f` displays a YAML diff on stderr and asks for confirmation, defaulting to no. Confirm with `y` or `yes`; changes that may permanently lose data display a warning first. Automation requires `--yes` and additionally `--allow-destructive` to permit data loss. Input files accept YAML or JSON, and `-f -` reads stdin; when stdin carries the definition, pass `--yes` or use a saved plan.

Save a plan for review and apply it later:

```sh
scope catalog plan --table scopedb.public.events -f events.yaml > plan.yaml
scope catalog apply --plan plan.yaml
scope catalog apply --table scopedb.public.events -f events.yaml --yes --format json > applied.json
```

`plan` writes the plan to stdout and the diff to stderr. A plan contains the original request, normalized before/after definitions, a `destructive` risk flag, connection identity, and catalog version. Machine-authenticated plans bind to the API key through a hash without including the key itself. Plans can contain custom storage credentials from the source definition; protect them like the source configuration.

`apply --plan` submits the saved request without another preview or prompt; destructive plans require `--allow-destructive`. If the catalog or connection has changed, apply fails. Regenerate and review the plan after editing its source or changing the target. `--plan -` reads a saved plan from stdin.

```sh
scope catalog drop --table scopedb.public.events
scope catalog drop --table scopedb.public.events --yes --allow-destructive
scope catalog drop --all --yes --allow-destructive
```

`drop` requires a resource scope or `--all` to clear the tenant's complete user catalog. It previews the deletion and uses the same confirmation rules as apply. Data loss risks include removing tables or physical columns, shortening retention, and changing deduplication on existing tables; the server checks each request independently.

All commands write structured results to stdout, using YAML by default or JSON with `--format json`. Apply and drop return the actual before/after definitions and `destructive` flag. Diffs, warnings, prompts, and progress go to stderr. Use shell redirection to save results; the shell controls file replacement and permissions.

`--timeout` sets a positive per-request duration, defaulting to five minutes. Preview and commit each receive the full budget; time spent reviewing a diff does not consume it. A timeout or interrupted connection during commit can leave the outcome unknown. The CLI never automatically retries a Catalog write. If a write succeeds but reporting its result fails, the error says it was applied. Read the catalog before deciding whether to submit another change.

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
