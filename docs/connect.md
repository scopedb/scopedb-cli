# Connect the CLI and your application

This guide follows the selected repository revision; `main` can include unreleased changes. For an installed release, browse the guide at its matching [release tag](https://github.com/scopedb/scopedb-cli/tags). Run `scope version` to identify your version and `scope --help` to check its commands. See the [changelog](../CHANGELOG.md) for migration steps when upgrading.

Use `scope auth login` for the CLI. Use a workspace endpoint and API key for application SDKs. The CLI login is stored in your OS keyring when available, with a plaintext fallback; SDKs do not read it.

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

Login keeps a valid workspace selection or automatically selects the first workspace that is not scheduled for deletion, and prints its name and ID. Workspaces shared with you are listed and selected the same way as workspaces you own. Use `scope workspace use <id>` to switch, or `scope auth login --workspace <id>` to select a workspace during login. Both commands require an ID from `scope workspace list`; display names are not accepted.

If your account is awaiting approval or has no workspace, follow the instructions from `scope auth status`. Use `scope console --open` to open the Console. Once a workspace is available, select it with `scope workspace list` and `scope workspace use <id>`.

`scope auth status` verifies your login against ScopeDB and reports its credential source, `keyring` or `plaintext`, the credential file path when using plaintext, and when the login expires. Use `scope workspace get` to inspect the selected login workspace and its deployment status.

`scope doctor` runs a small read-only query when a workspace is selected. It reports incomplete account setup as a warning; exit code 0 alone does not mean you can query. A passing `data plane` check confirms query access. Use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts.

## Use headless Linux

On Linux, the OS keyring requires a working D-Bus session and a Secret Service provider, such as GNOME Keyring, with an accessible login collection. Servers, SSH sessions, and containers may not have these services available. If keyring storage fails during a new login, the CLI prints a warning to stderr and saves the credentials unencrypted in `credentials.json`. Device authorization and storage selection are independent.

For a CLI login on a host without a usable keyring:

```sh
scope auth login --use-device-code --no-browser
scope auth status
scope query 'SELECT 1 AS ready'
```

Approve the printed device code in a browser on another device. `--use-device-code` selects that authorization flow, and `--no-browser` skips opening a browser on the host. Add `--insecure-storage` to choose plaintext directly for this login. It does not change future login defaults. Plaintext credentials use permissions `0600` on Unix. On Linux, `credentials.json` and `config.toml` default to `$XDG_CONFIG_HOME/scopedb` or `~/.config/scopedb`; `SCOPEDB_HOME` overrides their directory.

Queries and other commands discover the existing login, and refresh writes back to the same store without automatic downgrade. A fallback file takes precedence over an old keyring entry for the same control-plane URL. Logout revokes the active login and clears both stores. If the keyring cannot be cleared, the command reports the failure and removes local file tokens while retaining a non-secret logout marker so an old keyring entry cannot become active again. Restore keyring access and rerun `scope auth logout` to finish cleanup.

To return to keyring storage, restore keyring access, run `scope auth logout`, then run `scope auth login` without `--insecure-storage`. Each new login tries the keyring again. `config.toml` stores service addresses, not a credential-store preference; legacy `credential_store` entries and `SCOPEDB_CREDENTIAL_STORE` are ignored.

## Get application credentials

Show the selected workspace's endpoint and create a key for your application:

```sh
scope workspace get
scope api-key create my-app --expires-in 720h
```

The key is shown only once on stdout. Store it in your application's secret manager. The command requires a CLI login; an existing API key cannot manage keys through the CLI. The workspace owner sees every key in the workspace, while a member sees and manages only keys they created. `scope api-key list` shows each key's creator to help distinguish keys with the same name. Use separate keys for development, staging, and production.

Revoke a key with `scope api-key revoke <id>`, using the ID from `scope api-key list`. A unique name also works, but repeated names require an ID; if an ID also matches another key's name, the ID wins. The confirmation shows the selected name and ID, and declining it sends no deletion.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. The key only grants access to the workspace it was created in. The CLI does not read API keys: `scope query`, `scope catalog`, and `scope doctor` always use your login and the workspace selected with `scope workspace use`. The CLI ignores `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`, so you can keep them set for SDK applications, but they do not choose the CLI's workspace. Run `scope auth status` to confirm the target before changing the catalog.

The CLI is meant for interactive use. In CI and other unattended jobs, use [workload identity](#run-in-ci) when your provider can issue an OIDC token, or connect through an SDK with an API key. Do not copy CLI login credentials to another host: the refresh token rotates on every use, and reusing an old one revokes the login.

To end your login session, run `scope auth logout`. Logout does not revoke application API keys.

## Run in CI

A CI job can exchange its OIDC identity token for a short-lived credential bound to one workspace, without a browser and without storing a platform secret. A workspace owner first creates a workload identity policy in the ScopeDB Console that names the CI provider and the exact token subject, such as `repo:acme/infra:environment:production`.

```sh
scope auth login --workload-identity --workspace <workspace-id> --insecure-storage
```

`--workspace` is required and takes a workspace ID. The login reads the job's OIDC token from `SCOPEDB_OIDC_TOKEN_FILE`, then `SCOPEDB_OIDC_TOKEN`, then the GitHub Actions OIDC request variables. On GitHub Actions, grant the job `id-token: write` permission and the CLI requests a token itself; no token variable is needed. Other CI providers must place a JWT in one of the `SCOPEDB_OIDC_TOKEN` variables, with the control-plane origin as its audience — the origin is the configured `control_url` without a path, query, or fragment, which is also the audience the GitHub request uses. A token issued for another service is rejected, and a provider that cannot set the audience cannot use this exchange.

A workload login only runs data commands such as `scope query`, `scope catalog`, and `scope doctor` against its bound workspace. It does not create a ScopeDB user session, so `scope workspace` and `scope api-key` commands are unavailable, and there is no refresh token. The login expires with the issued credential; rerun the same login to re-exchange. `scope auth status` shows the bound workspace, matched policy, and expiry; `scope auth logout` removes the local credential.

Prefer an ephemeral credential directory and plaintext storage in CI, since the credential is short-lived and the job discards it:

```yaml
env:
  SCOPEDB_HOME: ${{ runner.temp }}/scopedb
steps:
  - run: scope auth login --workload-identity --workspace "$SCOPEDB_WORKSPACE_ID" --insecure-storage
```

A deployment older than the workload identity feature rejects the exchange; upgrade the platform and retry. `scope auth login --workload-identity` needs a CLI release that includes it, so check `scope version` before rollout.

## Connect an SDK

Pass the endpoint and key explicitly to your SDK client; the CLI does not configure SDKs or export its short-lived login credentials.

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

Each remote check has its own timeout, defaulting to five seconds. Resolving login credentials and running the test query share one check's timeout. `--timeout 0` disables this per-check limit; individual control-plane HTTP requests retain their 15-second limit. Ctrl+C can interrupt checks. Cancellation may take an additional five seconds while the CLI attempts to cancel an already-submitted query.

If a timed-out query reports that server cancellation could not be confirmed, retain the statement ID and check its outcome before retrying. The statement may have completed or still be running; repeating a write could duplicate its effects. A successful cancellation request only confirms cancellation when the returned statement status is `cancelled`.

| Symptom                         | Next step                                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Not logged in                   | Run `scope auth login`.                                                                                |
| OS keyring unavailable          | See [headless Linux setup](#use-headless-linux) for device authorization and explicit plaintext login. |
| No workspace selected           | Run `scope workspace list`, then `scope workspace use <id>`.                                           |
| Workspace is still provisioning | Check `scope workspace get` or the Console and retry when the workspace is ready.                      |
| Operation timed out             | Check connectivity; increase `doctor --timeout` only if the per-check limit is too short.              |

JSON diagnostics keep the same `ok` and `checks` fields as table diagnostics. Failed checks exit with code 1; invalid flags exit with code 2; Ctrl+C exits with code 130. Include a reported request ID when asking for support, and omit API keys and session credentials.
