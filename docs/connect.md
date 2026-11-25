# Connect the CLI and your application

This guide follows the selected repository revision; `main` can include unreleased changes. For an installed release, browse the guide at its matching [release tag](https://github.com/scopedb/scopedb-cli/tags). Run `scope version` to identify your version and `scope --help` to check its commands. See the [changelog](../CHANGELOG.md) for migration steps when upgrading.

Use `scope auth login` for the CLI. Use a workspace endpoint and API key for application SDKs. The CLI stores its login in your OS keyring when available, with a local file fallback; SDKs do not read it.

## Verify your login

```sh
scope auth login
scope auth status
scope doctor
scope query 'SELECT 1 AS ready'
```

`scope auth login` prints an approval URL, opens your browser, and completes sign-in through a local callback once approved in the ScopeDB Console (pass `--no-browser` to open the printed URL yourself). Running `scope auth login` again lets you re-authenticate or switch accounts.

For SSH, containers, or approval from another device, use device authorization:

```sh
scope auth login --use-device-code --no-browser
```

Open the printed verification link in any browser to approve the request (omit `--no-browser` to also launch a local browser).

Login keeps your selected workspace or picks an available one automatically; pass `--workspace <id>` during login or run `scope workspace list` and `scope workspace use <id>` to switch (both owned and shared workspaces require IDs, not display names). If your account still needs approval or has no workspace yet, open the Console with `scope console --open` and run `scope workspace use <id>` once one is ready.

`scope auth status` checks your login against ScopeDB and shows the credential source (`keyring` or `plaintext`, including the file path), expiration, and target workspace. `scope workspace get` inspects workspace details and provisioning status, and `scope doctor` runs connectivity plus a read-only data-plane query check (use `scope query 'SELECT 1 AS ready'` as a readiness gate in scripts, since `doctor` reports incomplete account setup as a warning).

## Use headless Linux

On Linux, the OS keyring requires D-Bus and a Secret Service provider such as GNOME Keyring. On servers, SSH sessions, and containers without one, `scope auth login` warns on stderr and saves credentials unencrypted in `credentials.json` (`0600` on Unix, under `$XDG_CONFIG_HOME/scopedb` or `~/.config/scopedb` unless `SCOPEDB_HOME` is set):

```sh
scope auth login --use-device-code --no-browser
scope auth status
scope query 'SELECT 1 AS ready'
```

Pass `--insecure-storage` to write `credentials.json` directly without trying the keyring for that login. Subsequent commands and token refreshes stay on whichever store holds the active login; to return to the keyring after restoring access, re-authenticate with `scope auth login` without `--insecure-storage`.

## Get application credentials

Show the selected workspace's endpoint and create a key for your application:

```sh
scope workspace get
scope api-key create my-app --expires-in 720h
```

Keys created without `--expires-in` or `--expires-at` get a default expiration. Pass `--expires-in` with a duration such as `720h`, or `--expires-at` with an RFC3339 timestamp, to choose the expiration. The command reports the expiration on stderr; create a replacement key and update your application before the old key expires.

Pass `--permissions` with a JSON array to restrict what the key can do; omit it for full workspace access. Each rule names a `resource` (`table`, `statement`, or `catalog`) and its `access` (`read`, `write`, or both); table rules also scope the rule to `database`, `schema`, and a list of `tables` patterns where `*` matches any sequence. Permissions are fixed at creation and cannot change later, so decide them before creating the key. For example, a key that can only read matching tables and run statements:

```sh
scope api-key create ingest --permissions '[
  {"resource":"table","database":"scopedb","schema":"public","tables":["events","logs_*"],"access":["read"]},
  {"resource":"statement","access":["read","write"]}
]'
```

The key is shown only once on stdout. Store it in your application's secret manager. The command requires a CLI login; an existing API key cannot manage keys through the CLI. The workspace owner sees every key in the workspace, while a member sees and manages only keys they created. `scope api-key list` shows each key's creator to help distinguish keys with the same name. Use separate keys for development, staging, and production.

Revoke a key with `scope api-key revoke <id>`, using the ID from `scope api-key list`. A unique name also works, but repeated names require an ID; if an ID also matches another key's name, the ID wins. The confirmation shows the selected name and ID, and declining it sends no deletion.

Copy the workspace's data-plane endpoint, without appending `/v1/statements`. The key only grants access to the workspace it was created in. The CLI does not read API keys: `scope query`, `scope catalog`, and `scope doctor` always use your login and the workspace selected with `scope workspace use`. The CLI ignores `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`, so you can keep them set for SDK applications, but they do not choose the CLI's workspace. Run `scope auth status` to confirm the target before changing the catalog.

Do not copy CLI login credentials to another host: the refresh token rotates on every use, and reusing an old one revokes the login. For unattended jobs, see [Run in CI without a login](#run-in-ci-without-a-login); other automation connects through an SDK with an API key.

To end your login session, run `scope auth logout`. Logout does not revoke application API keys.

## Run in CI without a login

In GitHub Actions, the `scopedb/login-action` action signs data commands in with the job's OIDC token, without `scope auth login` and without a stored credential:

```yaml
permissions:
  contents: read
  id-token: write
jobs:
  apply:
    runs-on: ubuntu-24.04
    environment: production
    steps:
      - uses: actions/checkout@v7
      - name: Install the ScopeDB CLI
        run: |
          curl -fsSL "https://github.com/scopedb/scopedb-cli/releases/download/v<version>/scope_<version>_linux_amd64.tar.gz" | tar -xz -C "$RUNNER_TEMP"
          sudo install -m 0755 "$RUNNER_TEMP/scope" /usr/local/bin/scope
      - uses: scopedb/login-action@v1
        with:
          workspace-id: "0123456789ab"
      - run: scope catalog plan --file catalog.yaml --format json > plan.json
      - run: scope catalog apply --plan plan.json
```

`<version>` is a ScopeDB CLI release that supports OIDC sign-in, written without the leading `v`; see [Install](../README.md#install) for the release archives. The action only exports `SCOPEDB_WORKSPACE_ID` and `SCOPEDB_OIDC_TOKEN`; the job checks out the repository and installs the CLI itself.

Each `scope` invocation exchanges the token for a short-lived workspace credential. The CLI persists neither the token nor the exchanged credential; the action hands the token to later steps through the runner's `$GITHUB_ENV` file, masked in logs. A stored login takes precedence when one exists, and management commands such as `scope workspace` and `scope api-key` still require one. A workspace owner must first create an OpenID Connect trust policy in the Console matching the token's `sub` claim; on GitHub Actions the job's `environment` shapes that claim, so environment protection rules can gate the token before it is issued.

Outside GitHub Actions, arrange for `SCOPEDB_WORKSPACE_ID` and `SCOPEDB_OIDC_TOKEN` to be set in the job environment, with the token requested for the control-plane origin as its audience.

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
