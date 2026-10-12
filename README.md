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

`scope auth login` prompts for an email address and verification code, then stores the session in the operating system keyring. A pending account or an account without a workspace can stay logged in; `scope auth status` shows the account status and next steps. Run `scope console --open` to check approval status or create your first workspace in the Console. Once a workspace is available, select it without logging in again:

```sh
scope workspace list
scope workspace use <id-or-name>
scope auth status
```

`scope auth status` shows the credential source, identity, and connection target. Use `scope workspace get` for deployment details and `scope doctor` to verify query access.

The verification code is hidden when entered at a terminal. For piped input, provide `--email` and send the code on stdin; passing `--code` exposes it in process arguments.

`scope console [page]` provides shortcuts to Console pages: `home` (default), `query`, `data`, `keys`, and `connect`. For example, `scope console query` prints the query page URL; add `--open` to also open it in your browser.

## Query output

Queries can be provided inline, from a file with `--file` or `-f`, or through stdin. Use `--format` to select the output format. Results can be rendered as a table, JSON, JSON Lines, or CSV.

```sh
scope query -f report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv --output tables.csv
```

Files created with `scope query --output` have permissions `0600` on Unix-like systems.

## Catalog

Catalog commands require a server with the declarative Catalog API. `get`, `apply`, and `plan` default to the entire tenant. Select one resource with `--database DB`, `--schema DB.SCHEMA`, `--table DB.SCHEMA.TABLE`, or `--view DB.SCHEMA.VIEW`. These scope flags are mutually exclusive and require fully qualified names. Bare names are case insensitive; use backticks to preserve case or include dots and special characters, for example ``'scopedb.public.`Events.Daily`'``.

Browse resource names, then export the definition to edit:

```sh
scope catalog list databases
scope catalog list schemas --database scopedb
scope catalog list tables --schema scopedb.public
scope catalog get --table scopedb.public.events > events.yaml
# Edit events.yaml.
scope catalog apply --table scopedb.public.events -f events.yaml
```

`list databases`, `list schemas`, `list tables`, and `list views` default to the entire tenant and return fully qualified names. A definition replaces the complete selected resource: omitted objects are removed, and omitted collections are empty. Start from `get` when editing an existing resource. To manage the entire tenant, use `scope catalog get > catalog.yaml` and `scope catalog apply -f catalog.yaml`.

`apply -f` displays a unified YAML diff on stderr. Changes that may permanently lose data display a warning before confirmation. Press Enter to approve the displayed changes, or Ctrl-C to cancel. Use `--yes` in automation and additionally pass `--allow-destructive` to permit data loss. Output defaults to YAML; `--format json` produces JSON. Files accept either format, and `-f -` reads stdin.

For agents and reviewed changes, save a plan and apply it explicitly:

```sh
scope catalog plan --table scopedb.public.events -f events.yaml > plan.yaml
scope catalog apply --plan plan.yaml
# GitOps: save the actual before/after result as an audit artifact.
scope catalog apply --table scopedb.public.events -f events.yaml --yes > applied.yaml
```

`plan` displays a YAML diff on stderr and writes the complete snapshot to stdout. A plan contains the original request, normalized before/after definitions, a `destructive` risk flag, connection, and catalog version. Machine-authenticated plans also bind to the API key through a hash, without including the key itself. Plans retain any custom storage credentials in the submitted definition; protect them like the source configuration.

`apply --plan` submits the saved request and writes the execution result to stdout without prompting, redisplaying the saved diff, or rereading the source file; destructive plans require `--allow-destructive`. Treat the plan as a snapshot; edit the definition and regenerate the plan to change it. If the catalog changes, apply fails and asks you to plan again. Plans include any deletions caused by the replacement definition. Planning alone can also be used for audits.

The output of an apply contains its actual before/after state and the `destructive` flag. Data loss risks include removing tables or physical columns, shortening retention, and changing deduplication on existing tables.

```sh
scope catalog drop --table scopedb.public.events
scope catalog drop --table scopedb.public.events --yes --allow-destructive
scope catalog drop --all --yes --allow-destructive
```

`drop` requires a resource scope or `--all` to clear the tenant's complete user catalog. `drop` displays the deletion diff and asks for confirmation; use `--yes --allow-destructive` to automate deleting stored data. To clear only the tables in a schema, export that schema, set `tables: []`, and apply the edited definition. The CLI sends `allow_destructive=true` after interactive approval or an explicit flag; the server checks every request independently.

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

Development tools are managed with [mise](https://mise.jdx.dev/):

```sh
mise install
mise run check
mise run test:race
mise run build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
