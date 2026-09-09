# ScopeDB CLI

`scope` is the command-line interface for [ScopeDB](https://www.scopedb.io/).

## Install

Install from source with Go 1.25 or newer:

```sh
go install github.com/scopedb/scopedb-cli/cmd/scope@latest
```

## Get started

Sign in to ScopeDB Cloud, inspect the current workspace, and run a query:

```sh
scope login
scope status
scope query 'SELECT 1 AS ready'
scope query 'FROM system.tables LIMIT 10'
```

For CI and other non-interactive environments, set the data-plane endpoint and API key:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"

scope doctor
scope query --format json 'SELECT 1 AS ready'
```

Both variables are required. Interactive login stores credentials in the operating system keyring by default.

## Query output

Queries can be provided inline, from a file, or through stdin. Results can be rendered as a table, JSON, JSON Lines, or CSV.

```sh
scope query --file report.scopeql --format json
scope query 'FROM system.tables LIMIT 10' --format csv --output tables.csv
```

Run `scope --help` or `scope <command> --help` for the complete command reference. See the [ScopeDB documentation](https://docs.scopedb.io/) for ScopeQL and service documentation.

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
