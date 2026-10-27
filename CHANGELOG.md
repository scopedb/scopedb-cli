# CHANGELOG

All significant changes to this project will be documented in this file.

## Unreleased

### Breaking changes

* `scope auth status --format json` adds `auth_type` and reports `connection` for named connections. Update strict JSON schemas to accept these fields.
* A temporary API key connection cannot perform OAuth-only operations; select an OAuth connection with `--connection` for workspace administration, login, or logout.
* `scope auth login` no longer selects the first workspace when several are available. It keeps an accessible saved binding, selects the only eligible workspace, or prompts on an interactive terminal. Non-interactive login with multiple workspaces saves the login without a target; pass `--workspace <id>` or run `scope workspace use <id>` before workspace-dependent commands.
* `scope workspace use <id>` and `scope auth login --workspace <id>` now require a workspace ID. Display names are no longer accepted; use `scope workspace list` to find the ID and update commands and scripts that select workspaces by name.
* Rename the CLI configuration directory override from `SCOPEDB_CONFIG_DIR` to `SCOPEDB_HOME`. Set `SCOPEDB_HOME` to the same directory and remove the old variable from your environment. The CLI no longer reads the old name. Default storage locations and connection variable names are unchanged; existing logins migrate to connections as described below.

### New features

* Named connections support independent OAuth logins and stored or environment-referenced API keys. Use `scope auth login --connection <name>` or `scope connection add <name>`, inspect saved connections with `connection list`, and select the default with `connection set-default`. Precedence is `--connection` (`-c`), `SCOPEDB_CONNECTION`, a complete temporary endpoint/key environment pair, then the saved default. Explicit named connections ignore generic endpoint/key variables. Existing OAuth credentials migrate into `default` with their workspace and storage backend.
* `--workspace <id>` overrides the target of one OAuth workspace-scoped command without changing its saved default. OAuth discovers the data service endpoint for the selected workspace. API key connections save an endpoint and use the workspace authorized by their key, rejecting workspace overrides and control-plane operations. Multiple connections can share an endpoint with independent credentials.
* `scope connection remove <name>` removes local configuration and credentials, revoking an OAuth grant first while leaving service-side API keys intact. Revocation failures retain the connection for retry. Removal requires interactive confirmation or `--yes`, and removing the default clears its selection. OAuth logout keeps connection settings.
* `scope workspace use` without an ID offers an interactive picker showing workspace names and IDs. Workspace IDs and connection names support shell completion. Non-interactive workspace selection requires an explicit ID.

### Improvements

* Source installations require Go 1.27.3 or newer to include its certificate-validation security fix.
* Hide service URL override flags from command help and shell completion.

## v0.2.0 (2026-10-25)

### Breaking changes

* `scope api-key revoke` revokes by key ID. Use IDs from `scope api-key list` in scripts. Unique names remain accepted, ambiguous names are rejected, and ID matches take precedence. JSON results add `id` alongside `name` and `revoked`; update strict JSON schemas to accept the new field.

### Bug fixes

* `scope workspace get` and `scope auth status` keep their resolved login and workspace together if another process replaces the stored credentials during the command.

### Improvements

* `scope api-key list` shows each key's creator in the default table so workspace owners can distinguish members' keys with the same name.
* `scope auth login` shows the authorization outcome and return-to-terminal guidance in a browser page with light and dark appearances.

## v0.1.0 (2026-10-23)

### Breaking changes

* `credential_store` in `config.toml` and `SCOPEDB_CREDENTIAL_STORE` no longer select a storage backend. Existing credentials are discovered automatically; use `scope auth login --insecure-storage` to choose plaintext for a new login only.
* `scope auth login` approves a login in the ScopeDB Console instead of requesting an email verification code. `--email`, `--code`, and the interactive code prompt are gone, and the login no longer stores a browser session. For unattended access use `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`; `scope auth login --format json` reports the signed-in account and selected workspace.
* `scope workspace use` stores the workspace locally for the current login instead of rotating a credential, so it no longer changes the workspace of another machine or a Console session. `scope auth status` still reports the selected workspace.
* Authentication commands are grouped under `scope auth`: replace `scope login`, `scope logout`, and `scope status` with `scope auth login`, `scope auth logout`, and `scope auth status`. Replace `scope workspace show` with `scope workspace get`. The old command paths are not aliases.
* `-f` selects query input files. Replace every `-f <format>` with `--format <format>`; use `scope query -f <file>` as shorthand for `--file <file>`. In particular, `scope query -f json` reads a file named `json`.
* `scope query` writes results only to stdout; `--output` (`-o`) and `--force` are removed. Replace `--output results.csv` with shell redirection, such as `scope query -f report.scopeql --format csv > results.csv`. The shell controls overwriting and file permissions; use a temporary file and move it after success if an existing result must survive query failure.
* `scope auth status --format json` no longer reports `auth_mode`; `credential_source` identifies environment credentials or the login store. It adds `refresh_token_expires_at` and uses `email` instead of `user`, and omits deployment state. Read `provisioning.status` from `scope workspace get --format json` instead of `provisioning_state` from status. Workspace JSON uses `connection.endpoint` instead of `connection.api_base_url`.
* `scope console` replaces `scope open` and prints the Console URL by default. Replace `scope open [page]` with `scope console [page] --open` to launch the browser, or replace `scope open [page] --print` with `scope console [page]` to print the URL. Both modes print the URL to stdout.

### New features

* `scope catalog` lists resource names, exports YAML or JSON definitions, previews replacement changes, applies saved plans with version and connection checks, and drops selected resources. Interactive confirmation defaults to no; automation requires explicit authorization for data loss. Structured results go to stdout and diffs and warnings to stderr. `--request-timeout` limits each Catalog request to five minutes by default; `0` disables this limit.
* `scope auth login` opens a browser by default and completes the login through a loopback redirect on the same device. `--use-device-code` selects device authorization for approval from any device; `--no-browser` skips automatic browser opening in either flow. Both flows print an approval link before attempting to open the browser and keep waiting for approval if the launch fails. Device authorization rejects verification links that are not absolute HTTP(S) URLs. Device login also prints a verification code and shows a waiting message with the request's remaining lifetime until approval, denial, or expiry. A loopback response is accepted only when its `state` and issuer match the request, including error responses. Neither flow requires an interactive terminal. Login keeps the profile's existing workspace selection when the account still owns it and it is not scheduled for deletion. Otherwise, it selects the first available workspace by ID. `--workspace <id-or-name>` chooses one explicitly. The text and `--format json` results report the selected workspace name and ID; use `scope workspace use <id-or-name>` to switch afterwards. Login refuses to start while a renewable login is stored and asks you to run `scope auth logout` first; a stored login whose refresh token has expired is replaced. If another process completes login during authorization, the CLI preserves that login and attempts to revoke the unused authorization.
* The CLI login is renewed automatically before its access token expires, using a rotating refresh token that is shared safely between concurrent `scope` processes; every credential update is serialized under the file lock. Network failures, including interrupted response bodies, retry the same refresh token within the server's recovery window, with at most two retries. Credential renewal keeps each running command on its resolved workspace even if another process changes the selection.
* `scope auth logout` revokes the login in ScopeDB before removing local credentials, so a signed-out CLI cannot keep using its grant.
* `scope workspace list` shows whether each workspace is ready, still provisioning, or scheduled for deletion, and the CLI refuses to select a workspace that is scheduled for deletion.
* `scope auth login`, `auth logout`, `workspace use`, `api-key revoke`, `console`, and `version` support `--format json` for machine-readable action results. Logout reports whether it cleared an existing login with `changed`.
* `scope workspace list` and `api-key list` accept `--limit` to cap displayed results without changing the default of showing all items.

### Bug fixes

* Timeout errors no longer suggest increasing `--timeout` when the command has no such option or a different timeout caused the failure.
* `scope query` displays the server's failure reason and includes the statement ID when the server cancels execution.
* Table output reports write failures instead of returning success when the destination cannot accept the result.
* `scope console --open` reports browser-launch failures during startup instead of reporting that the browser opened successfully.
* `scope query` preserves the `.0` suffix for whole-number floats in table and CSV output, so they remain distinguishable from integers.
* If `scope query` cannot write its results to stdout after execution, the error reports that the query completed and includes its statement ID, so an output error does not prompt users to repeat a statement with side effects.
* `scope doctor` now verifies query access for a logged-in workspace, reporting provisioning, token exchange, and query failures that previously went unchecked.
* `scope doctor` uses `/livez` for the control-plane check, so it continues to work after the legacy `/healthz` endpoint is removed.
* Query timeout and Ctrl+C errors retain the statement ID and distinguish confirmed cancellation, completed statements, server failures, and unconfirmed outcomes. Completed statements include guidance to retrieve the result instead of repeating side effects; server failures preserve their original reason. Timeout still exits with code 5 and Ctrl+C with code 130. Ctrl+C also stops waiting for query input from stdin and stays quiet when no statement ID was received.
* `scope auth login` no longer saves endpoint settings before authentication succeeds; if the final configuration write fails, it revokes the new login and restores the previous valid credentials.
* `scope workspace list` no longer prints a "no workspace is selected" notice pointing back at itself when the account has workspaces to choose from; it now only reports setup guidance when there is nothing to list.

### Improvements

* `scope query` waits without an additional client-side time limit by default. Use `--timeout 5m` to retain the previous limit, or `--timeout 0` to disable it; server and network timeouts still apply.
* New logins prefer the OS keyring and automatically fall back to plaintext with a warning when keyring storage fails. Queries, refresh, and logout discover the existing login; refresh keeps its storage location. Switching stores clears old copies, and logout prevents inaccessible stale keyring entries from reappearing. `scope auth status` shows the actual credential source and, for plaintext, its file path.
* Report the underlying cause when the CLI renders an error, in the terminal output and in `scope doctor` details, so a failure such as a credential store problem explains itself.
* A login that ScopeDB rejects, expires, or revokes is removed from the credential store after a failed refresh, and the next command asks you to run `scope auth login` instead of failing with an opaque credential error.
* `scope workspace use` identifies the selected login workspace and warns when environment credentials override data commands or form an incomplete pair.
* `scope doctor` supports `--timeout` for slower connections and `--timeout 0` to disable per-check limits (individual control-plane requests retain a 15-second limit), includes recovery hints and request IDs in failed checks, and preserves exit code 130 when interrupted.
* `scope api-key list --format json` excludes one-time key material from its output.

## v0.1.0-rc.3 (2026-09-16)

### Breaking changes

* `scope workspace list` and `scope workspace show` no longer display a role or include `role` in JSON workspace objects. `scope workspace show --format json` also removes `provisioning.code`, `reason`, `retryable`, and `action`; use `provisioning.status` and `updated_at` for provisioning state.

### Bug fixes

* Preserve valid logins for accounts awaiting approval or without a workspace. `scope status` now includes `user_status` in JSON output, and status, workspace listing, and doctor checks guide users through approval, creation in the Console, and workspace selection without requiring another CLI login. Workspace-dependent commands report the missing setup step instead of treating the session as invalid.

## v0.1.0-rc.2 (2026-09-11)

### Bug fixes

* Ctrl+C now exits immediately when `scope login` or `scope api-key revoke` is waiting for input, without requiring Enter or printing an error.

## v0.1.0-rc.1 (2026-09-11)

* Initial release.
