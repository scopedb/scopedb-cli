# Connect the CLI and your application

Use `scope login` for terminal exploration. Use a workspace endpoint and API key for application SDKs and CI. The CLI login is stored in your OS keyring; SDKs do not read it.

## Verify your login

```sh
scope login
scope status
scope doctor
scope query 'SELECT 1 AS ready'
```

If your account is awaiting approval or has no workspace, follow the instructions from `scope status`. Use `scope open` to open the Console. Once a workspace is available, select it with `scope workspace list` and `scope workspace use <id-or-name>`.

`scope doctor` runs a small read-only query when a workspace is selected. It reports incomplete account setup as a warning; exit code 0 alone does not mean you can query. A passing `data plane` check confirms query access. Use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts.

## Get application credentials

Show the selected workspace's endpoint and create a key for your application:

```sh
scope workspace show
scope api-key create my-app --expires-in 720h
```

The key is shown only once on stdout. Store it in your application's secret manager. The command requires a CLI login; an existing API key cannot manage keys through the CLI. Use separate keys for development, staging, and production.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. Set both values in your application environment or local shell:

```sh
export SCOPEDB_ENDPOINT="https://your-workspace.example.com"
export SCOPEDB_API_KEY="your-api-key"
scope status
scope doctor --timeout 15s
scope query --format json 'SELECT 1 AS ready'
```

`scope status` shows `api_key` mode when both variables are set. Queries and connection checks then use those credentials even if you are logged in to another workspace. Workspace selection and API key management still use your login. To return to login-based queries, unset both variables:

```sh
unset SCOPEDB_ENDPOINT SCOPEDB_API_KEY
```

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

Each remote check has its own timeout. Resolving login credentials and running the test query share one check's timeout. Cancellation may take an additional five seconds while the CLI attempts to cancel an already-submitted query.

If a timed-out query reports that server cancellation could not be confirmed, retain the statement ID and check its outcome before retrying. The statement may have completed or still be running; repeating a write could duplicate its effects. A successful cancellation request only confirms cancellation when the returned statement status is `cancelled`.

| Symptom                          | Next step                                                                                                 |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Only one connection variable set | Set both `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`, or unset both to use your login.                       |
| Not logged in                    | Run `scope login`, or configure both connection variables.                                                |
| No workspace selected            | Run `scope workspace list`, then `scope workspace use <id-or-name>`.                                      |
| Workspace is still provisioning  | Check `scope status` or the Console and retry when the workspace is ready.                                |
| API key rejected                 | Check that the endpoint and key belong to the same workspace and the key has not expired or been revoked. |
| Operation timed out              | Check network access to the endpoint and retry with a larger `--timeout`.                                 |

JSON diagnostics keep the same `ok` and `checks` fields as table diagnostics. Failed checks exit with code 1; invalid flags exit with code 2; Ctrl+C exits with code 130. Include a reported request ID when asking for support, and omit API keys and session credentials.
