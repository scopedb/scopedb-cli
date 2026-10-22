# CHANGELOG

All significant changes to this project will be documented in this file.

## Unreleased

### Breaking changes

* `scope auth login` approves a login in the ScopeDB Console instead of requesting an email verification code. `--email`, `--code`, and the interactive code prompt are gone, and the login no longer stores a browser session. For unattended access use `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`; `scope auth login --format json` reports the signed-in account and selected workspace.
* `scope workspace use` stores the workspace locally for the current login instead of rotating a credential, so it no longer changes the workspace of another machine or a Console session. `scope auth status` still reports the selected workspace.
* Authentication commands are grouped under `scope auth`: replace `scope login`, `scope logout`, and `scope status` with `scope auth login`, `scope auth logout`, and `scope auth status`. Replace `scope workspace show` with `scope workspace get`. The old command paths are not aliases.
* `-f` selects query input files. Replace every `-f <format>` with `--format <format>`; use `scope query -f <file>` as shorthand for `--file <file>`. In particular, `scope query -f json` reads a file named `json`.
* `scope auth status --format json` no longer reports `auth_mode`; `credential_source` identifies environment credentials or the login store. It adds `refresh_token_expires_at` and uses `email` instead of `user`, and omits deployment state. Read `provisioning.status` from `scope workspace get --format json` instead of `provisioning_state` from status. Workspace JSON uses `connection.endpoint` instead of `connection.api_base_url`.
* `scope console` replaces `scope open` and prints the Console URL by default. Replace `scope open [page]` with `scope console [page] --open` to launch the browser, or replace `scope open [page] --print` with `scope console [page]` to print the URL. Both modes print the URL to stdout.

### New features

* `scope auth login` opens a browser by default and completes the login through a loopback redirect on the same device. `--use-device-code` selects device authorization for approval from any device; `--no-browser` skips automatic browser opening in either flow. Both flows print an approval link before attempting to open the browser and keep waiting for approval if the launch fails. Device authorization rejects verification links that are not absolute HTTP(S) URLs. Device login also prints a verification code and shows a waiting message with the request's remaining lifetime until approval, denial, or expiry. A loopback response is accepted only when its `state` and issuer match the request, including error responses. Neither flow requires an interactive terminal. Login keeps the profile's existing workspace selection when the account still owns it and it is not scheduled for deletion. Otherwise, it selects the first available workspace by ID. `--workspace <id-or-name>` chooses one explicitly. The text and `--format json` results report the selected workspace name and ID; use `scope workspace use <id-or-name>` to switch afterwards. Login refuses to start while a renewable login is stored and asks you to run `scope auth logout` first; a stored login whose refresh token has expired is replaced. If another process completes login during authorization, the CLI preserves that login and attempts to revoke the unused authorization.
* The CLI login is renewed automatically before its access token expires, using a rotating refresh token that is shared safely between concurrent `scope` processes; every credential update is serialized under the file lock. Network failures, including interrupted response bodies, retry the same refresh token within the server's recovery window, with at most two retries. Credential renewal keeps each running command on its resolved workspace even if another process changes the selection.
* `scope auth logout` revokes the login in ScopeDB before removing local credentials, so a signed-out CLI cannot keep using its grant.
* `scope workspace list` shows whether each workspace is ready, still provisioning, or scheduled for deletion, and the CLI refuses to select a workspace that is scheduled for deletion.
* `scope auth login`, `auth logout`, `workspace use`, `api-key revoke`, `console`, and `version` support `--format json` for machine-readable action results. Logout reports whether it cleared an existing login with `changed`.
* `scope workspace list` and `api-key list` accept `--limit` to cap displayed results without changing the default of showing all items.

### Bug fixes

* On Windows, `scope query --output` preserves a destination created by another process while the query runs, unless `--force` explicitly allows replacing it.
* Table output reports write failures instead of returning success when the destination cannot accept the result.
* `scope console --open` reports browser-launch failures during startup instead of reporting that the browser opened successfully.
* `scope query` preserves the `.0` suffix for whole-number floats in table and CSV output, so they remain distinguishable from integers.
* `scope query --output` checks the destination and prepares a temporary file before submitting a statement. If writing the result fails after execution, the error reports that the query completed and includes its statement ID, so a file error does not prompt users to repeat a statement with side effects.
* `scope doctor` now verifies query access for a logged-in workspace, reporting provisioning, token exchange, and query failures that previously went unchecked.
* Query timeout and Ctrl+C errors retain the statement ID and report when server cancellation could not be confirmed, so users can check the outcome before retrying. Ctrl+C also stops waiting for query input from stdin, exits with code 130, and stays quiet when no statement ID was received.
* `scope auth login` no longer saves endpoint and credential-store settings before authentication succeeds; if the final configuration write fails, it revokes the new login and restores the previous valid credentials.
* `scope workspace list` no longer prints a "no workspace is selected" notice pointing back at itself when the account has workspaces to choose from; it now only reports setup guidance when there is nothing to list.

### Improvements

* Report the underlying cause when the CLI renders an error, in the terminal output and in `scope doctor` details, so a failure such as a credential store problem explains itself.
* A login that ScopeDB rejects, expires, or revokes is removed from the credential store after a failed refresh, and the next command asks you to run `scope auth login` instead of failing with an opaque credential error.
* `scope workspace use` identifies the selected login workspace and warns when environment credentials override data commands or form an incomplete pair.
* `scope doctor` supports `--timeout` for slower connections and `--timeout 0` to disable per-check limits (individual control-plane requests retain a 15-second limit), includes recovery hints and request IDs in failed checks, and preserves exit code 130 when interrupted.
* `scope api-key list --format json` excludes one-time key material from its output.
* `scope query --output` creates result files with permissions `0600` on Unix-like systems.

## v0.1.0-rc.3 (2026-09-16)

### Breaking changes

* Align workspace output with Platform v0.19.0: `scope workspace list` and `scope workspace show` no longer display a role or include `role` in JSON workspace objects. `scope workspace show --format json` also removes `provisioning.code`, `reason`, `retryable`, and `action`; use `provisioning.status` and `updated_at` for provisioning state.

### Bug fixes

* Preserve valid logins for accounts awaiting approval or without a workspace. `scope status` now includes `user_status` in JSON output, and status, workspace listing, and doctor checks guide users through approval, creation in the Console, and workspace selection without requiring another CLI login. Workspace-dependent commands report the missing setup step instead of treating the session as invalid.

## v0.1.0-rc.2 (2026-09-11)

### Bug fixes

* Ctrl+C now exits immediately when `scope login` or `scope api-key revoke` is waiting for input, without requiring Enter or printing an error.

## v0.1.0-rc.1 (2026-09-11)

* Initial release.
