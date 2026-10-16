# Connect the CLI and your application

Use `scope auth login` for terminal exploration. Use a workspace endpoint and API key for application SDKs and CI. The CLI login is stored in your OS keyring; SDKs do not read it.

## Verify your login

```sh
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
```

If your account is awaiting approval or has no workspace, follow the instructions from `scope auth status`. Use `scope console --open` to open the Console. Once a workspace is available, select it with `scope workspace list` and `scope workspace use <id-or-name>`.

`scope auth status` reports the active credential source: `environment`, `keyring`, or `plaintext`. In login mode it verifies your login against ScopeDB and reports when the login expires; in environment mode it displays the configured endpoint without validating the API key. Use `scope workspace get` to inspect the selected login workspace and its deployment status.

`scope doctor` runs a small read-only query when a workspace is selected. It reports incomplete account setup as a warning; exit code 0 alone does not mean you can query. A passing `data plane` check confirms query access. Use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts.

## Get application credentials

Show the selected workspace's endpoint:

```sh
scope workspace get
```

Create an application key in the Console's [API keys](https://console.scopedb.io/keys) page. The key is shown only once; store it in your application's secret manager. A CLI login is a delegated credential that cannot manage persistent keys, so create and revoke them in the Console. Use separate keys for development, staging, and production.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. Set both values in your application environment or local shell:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope auth status
scope doctor --timeout 15s
scope query --format json 'SELECT 1 AS ready'
```

`scope auth status` shows `api_key` mode when both variables are set. Queries and connection checks then use those credentials even if you are logged in to another workspace. `scope workspace use` selects a workspace for your login and warns when environment credentials override data commands. Workspace details also use your login. A partial environment pair prevents data access even after selecting a workspace. To return to login-based queries, unset both variables:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
```

To end your login, run `scope auth logout` after unsetting both variables. The command revokes the login in ScopeDB and then removes the local credentials; if ScopeDB cannot be reached, it reports that the login stays valid until it expires or is revoked in the Console. The command refuses to log out while machine credentials are configured, and it never affects application API keys.

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
| No workspace selected            | Run `scope workspace list`, then `scope workspace use <id-or-name>`.                                      |
| Workspace is still provisioning  | Check `scope workspace get` or the Console and retry when the workspace is ready.                         |
| API key rejected                 | Check that the endpoint and key belong to the same workspace and the key has not expired or been revoked. |
| Operation timed out              | Check network access to the endpoint and retry with a larger `--timeout`.                                 |

JSON diagnostics keep the same `ok` and `checks` fields as table diagnostics. Failed checks exit with code 1; invalid flags exit with code 2; Ctrl+C exits with code 130. Include a reported request ID when asking for support, and omit API keys and session credentials.
