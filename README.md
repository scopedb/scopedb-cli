# ScopeDB CLI

`scope` is the command-line interface for [ScopeDB](https://www.scopedb.io/).

> [!IMPORTANT]
> ScopeDB CLI is in public preview. Compatibility changes increment the minor version; patch releases contain backward-compatible fixes. Review the [changelog](CHANGELOG.md) before upgrading.

## Install

### Prebuilt binaries

Download the most recently published release, including release candidates, from [GitHub Releases](https://github.com/scopedb/scopedb-cli/releases). GitHub's `/releases/latest` shortcut excludes prereleases. Choose your platform's archive under **Assets**; `<version>` is the release tag without its leading `v`:

| Platform               | Archive pattern                       |
| ---------------------- | ------------------------------------- |
| macOS on Apple silicon | `scope_<version>_darwin_arm64.tar.gz` |
| macOS on Intel         | `scope_<version>_darwin_amd64.tar.gz` |
| Linux on x86-64        | `scope_<version>_linux_amd64.tar.gz`  |
| Linux on ARM64         | `scope_<version>_linux_arm64.tar.gz`  |
| Windows on x86-64      | `scope_<version>_windows_amd64.zip`   |
| Windows on ARM64       | `scope_<version>_windows_arm64.zip`   |

Compare the archive's SHA-256 digest with its entry in `checksums.txt`, extract it, and place `scope` (`scope.exe` on Windows) in a directory on your `PATH`.

For example, after extracting the archive on macOS or Linux:

```sh
mkdir -p "$HOME/.local/bin"
install -m 0755 scope "$HOME/.local/bin/scope"
scope version
```

Ensure `$HOME/.local/bin` is on your `PATH` before running `scope`.

### Install from source

With Go 1.27.3 or newer:

```sh
go install github.com/scopedb/scopedb-cli/cmd/scope@latest
```

Go's `@latest` selects the highest release version, or the highest prerelease when no release version exists; it does not follow `main`. To opt into a newer prerelease, download its archive from GitHub Releases or replace `@latest` with its exact tag. Run the same command again to update, and ensure Go's binary directory (`GOBIN`, or `$(go env GOPATH)/bin` by default) is on your `PATH`.

## Get started

This README and [connection guide](docs/connect.md) follow the selected repository revision; `main` can include unreleased changes. For an installed release, read the README included in its archive or browse the documentation at its matching [release tag](https://github.com/scopedb/scopedb-cli/tags). Run `scope version` to identify your version and `scope --help` to check its commands. Review the [changelog](CHANGELOG.md) for migration steps when upgrading.

Sign in to ScopeDB Cloud and run a query:

```sh
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
scope query 'FROM system.tables LIMIT 10'
```

`scope auth login` opens your browser and asks you to approve the request in the ScopeDB Console. If the browser does not open, open the printed URL on the same device. For approval from another device, such as when using SSH or a container, run `scope auth login --use-device-code`. Add `--no-browser` to either flow to skip opening the browser automatically. A browser-launch failure leaves the selected flow waiting for approval.

Login does not require an interactive terminal. Authorization instructions and progress go to stderr; `--format text|json` selects the result format on stdout.

Login prefers the OS keyring. If keyring storage fails, the CLI warns and saves credentials unencrypted in a file (`0600` on Unix); `scope auth status` shows its location. `--insecure-storage` selects plaintext for that login only. On servers and other hosts without a browser, use device authorization. See [headless Linux setup](docs/connect.md#use-headless-linux).

Set `SCOPEDB_HOME` to override the directory used for configuration and plaintext credentials. Otherwise, the CLI uses a `scopedb` subdirectory of your operating system's user configuration directory.

Pass `--workspace <id>` to select a workspace explicitly. Without it, the login keeps the workspace already selected for the profile if the account can still access it and it is not scheduled for deletion. Otherwise, it selects the first available workspace by ID, even when several workspaces are available. Use `scope workspace use <id>` to switch afterwards. Both commands require an ID from `scope workspace list`; display names are not accepted.

A pending account or an account without a workspace can stay logged in; `scope auth status` shows the account status and next steps. Run `scope console --open` to check approval status and create your first workspace in the Console. Once a workspace is available, select it without logging in again:

```sh
scope workspace list
scope workspace use <id>
scope auth status
```

The workspace selection is stored locally for the current login, so it does not affect your Console session or another machine. Workspaces shared with you appear in `scope workspace list` alongside the ones you own; select either with `scope workspace use <id>`. `scope auth status` shows the credential source, identity, and connection target. Use `scope workspace get` for deployment details and `scope doctor` to verify query access.

`scope console [page]` provides shortcuts to Console pages: `home` (default), `query`, `data`, `keys`, and `connect`. For example, `scope console query` prints the query page URL; add `--open` to also open it in your browser.

## Query output

Queries can be provided inline, from a file with `--file` or `-f`, or through stdin. Results go to stdout; use `--format` to select a table, JSON, JSON Lines, or CSV. Use shell redirection to save results to a file.

```sh
scope query -f report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv > tables.csv
```

The shell controls file replacement and permissions. Redirecting with `>` can truncate an existing file before the query runs; write to a temporary file and move it after success if you need to preserve the previous result on failure.

Queries have no client-side wait limit by default. Use `scope query --timeout 5m` to limit waiting and attempt server cancellation when the limit expires. `--timeout 0` disables this client limit; it does not change the server's default one-hour elapsed-time limit or network timeouts. The limit covers submitting and waiting for the statement, excluding input, authentication, and output. Cancellation may take an additional five seconds.

Once a statement ID has been received, timeout and Ctrl+C diagnostics include it and distinguish confirmed cancellation, an already completed statement, a server failure, and an unconfirmed outcome. The command keeps its timeout or interrupt exit code and writes no query results. If the statement already completed, retrieve its result using the ID instead of rerunning a statement with side effects.

## Catalog

`get`, `plan`, and `apply` default to the entire catalog. Select one resource with `--database DB`, `--schema DB.SCHEMA`, `--table DB.SCHEMA.TABLE`, or `--view DB.SCHEMA.VIEW`. These scope flags are mutually exclusive and require fully qualified names. Bare names are case insensitive; use backticks to preserve case or include special characters, for example ``'scopedb.public.`Events.Daily`'``.

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

`plan` writes the plan to stdout and the diff to stderr. A plan contains the requested change, its preview, and the target connection, workspace, and catalog version. Plans can contain custom storage credentials from the source definition; protect them like the source configuration.

`apply --plan` submits the saved request without another preview or prompt; destructive plans require `--allow-destructive`. If the catalog or connection has changed, apply fails. Regenerate and review the plan after editing its source or changing the target. `--plan -` reads a saved plan from stdin.

```sh
scope catalog drop --table scopedb.public.events
scope catalog drop --table scopedb.public.events --yes --allow-destructive
scope catalog drop --all --yes --allow-destructive
```

`drop` requires a resource scope or `--all` to clear the tenant's complete user catalog. It previews the deletion and uses the same confirmation rules as apply. Data loss risks include removing tables or physical columns, shortening retention, and changing deduplication on existing tables; the server checks each request independently.

All commands write structured results to stdout, using YAML by default or JSON with `--format json`. Apply and drop return the actual before/after definitions and `destructive` flag. Diffs, warnings, prompts, and progress go to stderr. Use shell redirection to save results; the shell controls file replacement and permissions.

`--request-timeout` limits each Catalog request, defaulting to five minutes; `0` disables this limit. Preview and commit each receive the full budget; input, authentication, and time spent reviewing a diff do not consume it. Authentication requests retain their separate control-plane timeout. A timeout or interrupted connection during commit can leave the outcome unknown. The CLI never automatically retries a Catalog write. If a write succeeds but reporting its result fails, the error says it was applied. Read the catalog before deciding whether to submit another change.

## JSON output

Business commands support `--format json` for scripts while keeping their usual human-readable output by default. Action commands return an object describing the result; `scope auth logout` reports `changed: true` when it clears an existing login and `changed: false` when already logged out.

```sh
scope auth status --format json
scope workspace use <id> --format json
scope api-key revoke <id> --yes --format json
scope console --format json
```

Results go to stdout; prompts, warnings, and errors go to stderr. `scope doctor --format json` prints its report and exits nonzero if checks fail. `scope version --format json` prints machine-readable version information; `--json` is also supported.

Use an ID from `scope api-key list` in scripts; unique names are accepted, and ID matches take precedence. JSON results contain `id`, `name`, and `revoked`, including when you decline confirmation. See [API key management](docs/connect.md#get-application-credentials) for permissions and interactive use.

`scope workspace list` and `scope api-key list` accept `--limit N` to show at most N items. The default and `--limit 0` show all items. This limits displayed results without reducing the amount fetched.

Run `scope --help` or `scope <command> --help` for the complete command reference. See the [ScopeDB documentation](https://docs.scopedb.io/) for ScopeQL and service documentation.

## Applications

The CLI connects with your login and its selected workspace; it does not accept API keys. For an application, get the endpoint with `scope workspace get` and create an API key with `scope api-key create <name> --expires-in 720h`, then pass both to your SDK client. See the [CLI and SDK connection guide](docs/connect.md) for the complete workflow and troubleshooting.

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
