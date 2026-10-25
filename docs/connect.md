# Connect the CLI and your application

This guide follows the selected repository revision; `main` can include unreleased changes. For an installed release, browse the guide at its matching [release tag](https://github.com/scopedb/scopedb-cli/tags). Run `scope version` to identify your version and `scope --help` to check its commands. See the [changelog](../CHANGELOG.md) for migration steps when upgrading.

Use `scope auth login` for terminal exploration. Use a workspace endpoint and API key for application SDKs and CI. The CLI login is stored in your OS keyring when available, with a plaintext fallback; SDKs do not read it.

## Verify your login

```sh
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
```

Login opens your browser by default and waits for a callback on the same device. The CLI prints the approval URL before opening the browser, so you can open it manually if the browser does not launch. A browser-launch failure does not switch authorization flows. `--no-browser` skips the automatic launch and keeps the same-device callback.

After approval, the browser acknowledges receipt of authorization. Return to your terminal for the final login result or error details; you can close the browser window.

For SSH, containers, or approval from another device, select device authorization explicitly:

```sh
scope auth login --use-device-code --no-browser
```

Open the printed verification link on any device and approve the request. `--use-device-code` selects device authorization; `--no-browser` independently disables automatic browser opening. Omit `--no-browser` to also open the verification link in a local browser. Neither flow requires an interactive terminal.

Login keeps an accessible saved workspace or selects the only workspace not scheduled for deletion, and prints its name and ID. With multiple eligible workspaces, an interactive terminal shows a picker; without interaction, login succeeds without selecting a workspace. Use `scope workspace use` for the picker, `scope workspace use <id>` to switch directly, or `scope auth login --workspace <id>` during login. Explicit arguments accept IDs only. The picker displays names and IDs, so repeated or missing names remain distinguishable. Cancelling it never selects a default row. Workspace IDs also support shell completion.

A failed explicit workspace selection reports that the login was saved and exits unsuccessfully; select an accessible ID afterwards. A non-interactive login without a target returns success, but workspace-dependent commands fail until you select one. Workspaces shared with you are selected the same way as workspaces you own.

If your account is awaiting approval or has no workspace, follow the instructions from `scope auth status`. Use `scope console --open` to open the Console. Once a workspace is available, select it with `scope workspace list` and `scope workspace use <id>`.

`scope auth status` reports the active credential source: `environment`, `keyring`, or `plaintext`, and the credential file path when using plaintext. In login mode it verifies your login against ScopeDB and reports when the login expires; in environment mode it displays the configured endpoint without validating the API key. Use `scope workspace get` to inspect the selected login workspace and its deployment status.

`scope doctor` runs a small read-only query when a workspace is selected. It reports incomplete account setup as a warning; exit code 0 alone does not mean you can query. A passing `data plane` check confirms query access. Use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts.

## Manage connections

A named connection stores an authentication type and its target. OAuth connections hold service URLs and a default workspace; API key connections hold a data endpoint and either a stored key or an explicit environment-variable reference. Secrets are stored separately from `config.toml`.

```sh
scope auth login --connection development --workspace <workspace-id>
scope connection add automation --auth-type api_key --endpoint https://your-workspace.example.com --api-key-env APP_API_KEY
scope connection list --format json
scope connection set-default development
scope --connection automation query 'SELECT 1 AS ready'
scope --connection development auth status
```

`connection add NAME` saves an OAuth configuration without logging in. `auth login --connection NAME` can also create an OAuth connection after authorization succeeds. API key connections require `--auth-type api_key`, `--endpoint`, and exactly one of `--api-key-stdin` or `--api-key-env NAME`. The former reads one key from standard input and saves it using the OS keyring with the same warned plaintext fallback as OAuth credentials; `--insecure-storage` explicitly selects plaintext for that key. The latter stores only the variable name and requires that variable to contain a key when the connection is used. Adding an existing connection fails without overwriting its configuration or credentials.

The configuration has this shape:

```toml
default_connection = "development"

[connections.development]
auth_type = "oauth"
control_url = "https://control.scopedb.cloud"
console_url = "https://console.scopedb.cloud"
workspace_id = "<workspace-id>"

[connections.automation]
auth_type = "api_key"
endpoint = "https://your-workspace.example.com"
api_key_env = "APP_API_KEY"
```

Selection precedence is `--connection` (`-c`), `SCOPEDB_CONNECTION`, the generic `SCOPEDB_ENDPOINT`/`SCOPEDB_API_KEY` pair, then `default_connection`. The pair supplies a temporary API key connection and must be complete. Explicit named selection ignores the generic pair, including incomplete values; it never mixes credentials from another connection or falls back when its own credentials are missing. `SCOPEDB_HOME` selects the configuration and plaintext credential directory.

The first added connection becomes the default. An unqualified first OAuth login creates `default`; adding or logging into another connection does not replace an existing default. `connection set-default NAME` changes only that default. Per-command and environment selection do not persist. Unknown names fail except during creation. Names contain 1 to 64 letters, digits, dots, underscores, or hyphens. Removing the default clears the selection; select another explicitly or run `connection set-default NAME` before unqualified commands.

`connection list` reports saved configuration, with `default` and `effective` markers. Identity and workspace names are last known information, not proof of a valid login. `auth status` reports the connection, `auth_type`, target, and credential source. For OAuth it also verifies the login and reports user identity, workspace, and login expiry; for API keys it reports the source and endpoint without validating server access. Use `doctor` to verify data access.

### Select a workspace

`scope --connection development workspace use <id>` validates and saves that connection's default workspace. Two terminals using the same connection share this saved default. For a single command, use `--workspace <id>` with `query`, `catalog`, `workspace get`, `api-key` operations, `auth status`, or `doctor`. The override validates access, keeps the saved workspace unchanged, and never falls back to a different target. `auth login --workspace <id>` instead saves the selection as part of login. API key connections reject workspace overrides and OAuth-only operations such as workspace discovery and API key administration.

Each running OAuth command keeps its resolved identity and target through refresh and concurrent changes. Each connection owns its own login grant, rotating refresh credentials, and data-token cache, including when multiple connections authorize the same account. Workspace selection is a default, not an authorization restriction. Login refuses to overwrite a renewable login; log out of that connection first or use a new name.

### Log out or remove a connection

```sh
scope --connection development auth logout
scope connection remove development --yes
```

`auth logout` revokes the selected OAuth grant and clears its credentials/cache while retaining its configuration and workspace. It does not end other connections or browser sign-in. It does not apply to API key connections.

`connection remove NAME` deletes the selected configuration and local credentials. It first revokes an OAuth connection's existing grant; a revocation failure retains the configuration and credentials for retry. Removing an API key connection does not revoke the service-side key or change an external secret variable. Use `api-key revoke` with an OAuth connection to revoke a key on the service. Removal requires confirmation on an interactive terminal or `--yes` when non-interactive. Cancellation preserves the connection.

### Migrate existing configuration

Existing single-login OAuth credentials migrate into the `default` OAuth connection, retaining their workspace and storage backend. Other legacy service records migrate on access with `scope auth login --connection NAME --control-url URL`. Older email-session credentials require a new login. Existing `[profiles.NAME]` configuration is read as OAuth connections and rewritten as `[connections.NAME]` on the next configuration write; `current_profile` becomes `default_connection`, and existing credential references are retained. Replace `--profile`, `SCOPEDB_PROFILE`, and `profile use` in scripts with `--connection`, `SCOPEDB_CONNECTION`, and `connection set-default`.

Credentials are isolated by connection and configuration directory, including in the OS keyring. Changing `SCOPEDB_HOME` does not share an existing connection's credentials with the new directory. Legacy migration must retire the old shared keyring record; if access prevents this, restore access and retry. Avoid running an older CLI against migrated configuration. Existing connections cannot be redirected to another control-plane origin through service overrides.

## Use headless Linux

On Linux, the OS keyring requires a working D-Bus session and a Secret Service provider, such as GNOME Keyring, with an accessible login collection. Servers, SSH sessions, and containers may not have these services available. If keyring storage fails during a new login, the CLI prints a warning to stderr and saves the credentials unencrypted in `credentials.json`. Device authorization and storage selection are independent.

For servers and CI, use a workspace endpoint and API key:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope doctor
scope query --format json 'SELECT 1 AS ready'
```

Without explicit named selection, both variables select a temporary connection: `query`, `auth status`, and `doctor` skip the keyring and do not require login. A partial pair fails. Select an OAuth connection explicitly for workspace and API key management.

For a CLI login on a host without a usable keyring:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
scope auth login --use-device-code --no-browser
scope auth status
scope query 'SELECT 1 AS ready'
```

Approve the printed device code in a browser on another device. `--use-device-code` selects that authorization flow, and `--no-browser` skips opening a browser on the host. Add `--insecure-storage` to choose plaintext directly for this login. It does not change future login defaults. Plaintext credentials use permissions `0600` on Unix. On Linux, `credentials.json` and `config.toml` default to `$XDG_CONFIG_HOME/scopedb` or `~/.config/scopedb`; `SCOPEDB_HOME` overrides their directory.

Queries and other commands discover the existing login, and refresh writes back to the same store without automatic downgrade. A fallback file takes precedence over an old keyring entry for the same connection. Logout revokes the active login and clears both stores. If the keyring cannot be cleared, the command reports the failure and removes local file tokens while retaining a non-secret logout marker so an old keyring entry cannot become active again. Restore keyring access and rerun `scope auth logout` to finish cleanup.

To return to keyring storage, restore keyring access, run `scope auth logout`, then run `scope auth login` without `--insecure-storage`. Each new login tries the keyring again. `config.toml` stores connections, service addresses, and workspace defaults, not a credential-store preference; legacy `credential_store` entries and `SCOPEDB_CREDENTIAL_STORE` are ignored.

## Get application credentials

Show the selected workspace's endpoint and create a key for your application:

```sh
scope workspace get
scope api-key create my-app --expires-in 720h
```

The key is shown only once on stdout. Store it in your application's secret manager. The command requires a CLI login; an existing API key cannot manage keys through the CLI. The workspace owner sees every key in the workspace, while a member sees and manages only keys they created. `scope api-key list` shows each key's creator to help distinguish keys with the same name. Use separate keys for development, staging, and production.

Revoke a key with `scope api-key revoke <id>`, using the ID from `scope api-key list`. A unique name also works, but repeated names require an ID; if an ID also matches another key's name, the ID wins. The confirmation shows the selected name and ID, and declining it sends no deletion.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. Set both values in your application environment or local shell:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope auth status
scope doctor --timeout 15s
scope query --format json 'SELECT 1 AS ready'
```

`scope auth status` reports `environment` when a temporary API key connection is selected. An explicit `--connection` or `SCOPEDB_CONNECTION` instead uses that named connection's own credentials. A temporary connection cannot perform workspace or API key administration. Unset both generic variables to use the saved default:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
```

To end an OAuth login, run `scope --connection NAME auth logout`. Explicit connection selection ignores unrelated machine environment credentials. Logout does not revoke application API keys.

## Connect an SDK

Use the same endpoint and key that passed the CLI connection check. Pass them explicitly to your SDK client; the CLI does not configure SDKs or export its short-lived login credentials.

| Client                | Setup and runnable examples                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------- |
| JavaScript/TypeScript | [scopedb](https://github.com/scopedb/scopedb-js#readme)                                     |
| Go                    | [goscopedb](https://github.com/scopedb/goscopedb#readme)                                    |
| Rust                  | [scopedb-client](https://github.com/scopedb/scopedb-client/tree/main/scopedb-client#readme) |

Start with `SELECT 1 AS ready` before querying application tables. Keep keys in trusted server-side code and use the SDK's documented write examples after your read-only connection test succeeds.

## Diagnose a failed connection

```sh
scope doctor --format json --timeout 15s
```

Each remote check has its own timeout, defaulting to five seconds. Resolving login credentials and running the test query share one check's timeout. `--timeout 0` disables this per-check limit; individual control-plane HTTP requests retain their 15-second limit. Ctrl+C can interrupt checks in either mode. Cancellation may take an additional five seconds while the CLI attempts to cancel an already-submitted query.

If a timed-out query reports that server cancellation could not be confirmed, retain the statement ID and check its outcome before retrying. The statement may have completed or still be running; repeating a write could duplicate its effects. A successful cancellation request only confirms cancellation when the returned statement status is `cancelled`.

| Symptom                          | Next step                                                                                                 |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Only one connection variable set | Set both `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`, or unset both to use your login.                       |
| Not logged in                    | Run `scope auth login`, or configure both connection variables.                                           |
| OS keyring unavailable           | See [headless Linux setup](#use-headless-linux) for API key access or explicit plaintext login.           |
| No workspace selected            | Run `scope workspace list`, then `scope workspace use <id>`.                                              |
| Workspace is still provisioning  | Check `scope workspace get` or the Console and retry when the workspace is ready.                         |
| API key rejected                 | Check that the endpoint and key belong to the same workspace and the key has not expired or been revoked. |
| Operation timed out              | Check connectivity; increase `doctor --timeout` only if the per-check limit is too short.                 |

JSON diagnostics keep the same `ok` and `checks` fields as table diagnostics. Failed checks exit with code 1; invalid flags exit with code 2; Ctrl+C exits with code 130. Include a reported request ID when asking for support, and omit API keys and session credentials.
