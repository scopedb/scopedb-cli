# Connect the CLI and your application

Use `scope auth login` for terminal exploration. Use a workspace endpoint and API key for application SDKs and CI. The CLI login is stored in your OS keyring when available, with a plaintext fallback; SDKs do not read it.

## Verify your login

```sh
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
```

Login opens your browser by default and waits for a callback on the same device. The CLI prints the approval URL before opening the browser, so you can open it manually if the browser does not launch. A browser-launch failure does not switch authorization flows. `--no-browser` skips the automatic launch and keeps the same-device callback.

For SSH, containers, or approval from another device, select device authorization explicitly:

```sh
scope auth login --use-device-code --no-browser
```

Open the printed verification link on any device and approve the request. `--use-device-code` selects device authorization; `--no-browser` independently disables automatic browser opening. Omit `--no-browser` to also open the verification link in a local browser. Neither flow requires an interactive terminal.

Login keeps a valid workspace selection or automatically selects the first workspace that is not scheduled for deletion, and prints its name and ID. Use `scope workspace use <id-or-name>` to switch.

If your account is awaiting approval or has no workspace, follow the instructions from `scope auth status`. Use `scope console --open` to open the Console. Once a workspace is available, select it with `scope workspace list` and `scope workspace use <id-or-name>`.

`scope auth status` reports the active credential source: `environment`, `keyring`, or `plaintext`, and the credential file path when using plaintext. In login mode it verifies your login against ScopeDB and reports when the login expires; in environment mode it displays the configured endpoint without validating the API key. Use `scope workspace get` to inspect the selected login workspace and its deployment status.

`scope doctor` runs a small read-only query when a workspace is selected. It reports incomplete account setup as a warning; exit code 0 alone does not mean you can query. A passing `data plane` check confirms query access. Use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts.

## Use headless Linux

On Linux, the OS keyring requires a working D-Bus session and a Secret Service provider, such as GNOME Keyring, with an accessible login collection. Servers, SSH sessions, and containers may not have these services available. If keyring storage fails during a new login, the CLI prints a warning to stderr and saves the credentials unencrypted in `credentials.json`. Device authorization and storage selection are independent.

For servers and CI, use a workspace endpoint and API key:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope doctor
scope query --format json 'SELECT 1 AS ready'
```

With both variables set, `scope query`, `scope auth status`, and `scope doctor` skip the keyring and do not require `scope auth login`. Setting only one variable fails. Workspace and API key management still require a CLI login.

For a CLI login on a host without a usable keyring:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
scope auth login --use-device-code --no-browser
scope auth status
scope query 'SELECT 1 AS ready'
```

Approve the printed device code in a browser on another device. `--use-device-code` selects that authorization flow, and `--no-browser` skips opening a browser on the host. Add `--insecure-storage` to choose plaintext directly for this login. It does not change future login defaults. Plaintext credentials use permissions `0600` on Unix. On Linux, `credentials.json` and `config.toml` default to `$XDG_CONFIG_HOME/scopedb` or `~/.config/scopedb`; `SCOPEDB_CONFIG_DIR` overrides their directory.

Queries and other commands discover the existing login, and refresh writes back to the same store without automatic downgrade. A fallback file takes precedence over an old keyring entry for the same control-plane URL. Logout revokes the active login and clears both stores. If the keyring cannot be cleared, the command reports the failure and removes local file tokens while retaining a non-secret logout marker so an old keyring entry cannot become active again. Restore keyring access and rerun `scope auth logout` to finish cleanup.

To return to keyring storage, restore keyring access, run `scope auth logout`, then run `scope auth login` without `--insecure-storage`. Each new login tries the keyring again. `config.toml` stores service addresses, not a credential-store preference; legacy `credential_store` entries and `SCOPEDB_CREDENTIAL_STORE` are ignored.

## Get application credentials

Show the selected workspace's endpoint and create a key for your application:

```sh
scope workspace get
scope api-key create my-app --expires-in 720h
```

The key is shown only once on stdout. Store it in your application's secret manager. The command requires a CLI login; an existing API key cannot manage keys through the CLI. Use separate keys for development, staging, and production.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. Set both values in your application environment or local shell:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope auth status
scope doctor --timeout 15s
scope query --format json 'SELECT 1 AS ready'
```

`scope auth status` reports `environment` as the credential source when both variables are set. Queries and connection checks then use those credentials even if you are logged in to another workspace. `scope workspace use` selects a workspace for your login session and warns when environment credentials override data commands. Workspace details and API key management also use your login. A partial environment pair prevents data access even after selecting a workspace. To return to login-based queries, unset both variables:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
```

To end your login session, run `scope auth logout` after unsetting both variables. The command refuses to log out while machine credentials are configured; it does not revoke application API keys.

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
| No workspace selected            | Run `scope workspace list`, then `scope workspace use <id-or-name>`.                                      |
| Workspace is still provisioning  | Check `scope workspace get` or the Console and retry when the workspace is ready.                         |
| API key rejected                 | Check that the endpoint and key belong to the same workspace and the key has not expired or been revoked. |
| Operation timed out              | Check connectivity; increase `doctor --timeout` only if the per-check limit is too short.                 |

JSON diagnostics keep the same `ok` and `checks` fields as table diagnostics. Failed checks exit with code 1; invalid flags exit with code 2; Ctrl+C exits with code 130. Include a reported request ID when asking for support, and omit API keys and session credentials.
