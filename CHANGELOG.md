# CHANGELOG

All significant changes to this project will be documented in this file.

## Unreleased

### Breaking changes

* `scope auth login` approves a login in the ScopeDB Console instead of requesting an email verification code. `--email`, `--code`, the interactive code prompt, `--workspace`, `--device`, and `--format` are gone, and the login no longer stores a browser session. This release requires ScopeDB v0.23.0 or newer; an older deployment rejects login with that requirement, and the previous v1 browser-session credential is invalidated, so the first command after upgrading asks you to log in again. Login now requires an interactive terminal: it asks how to sign in — approve in a browser, or approve a device code from another device — and device login never opens a browser. For non-interactive access use `SCOPEDB_ENDPOINT` and `SCOPEDB_API_KEY`; machine-readable state is available from `scope auth status --format json` and `scope workspace list --format json`.
* `scope api-key` is removed. The CLI authenticates as a delegated client that cannot create, list, or revoke persistent API keys; manage them in the Console instead.
* `scope workspace use` stores the workspace locally for the current login instead of rotating a credential, so it no longer changes the workspace of another machine or a Console session. `scope auth status` still reports the selected workspace.
* Authentication commands are grouped under `scope auth`: replace `scope login`, `scope logout`, and `scope status` with `scope auth login`, `scope auth logout`, and `scope auth status`. Replace `scope workspace show` with `scope workspace get`. The old command paths are not aliases.
* `-f` selects query input files. Replace every `-f <format>` with `--format <format>`; use `scope query -f <file>` as shorthand for `--file <file>`. In particular, `scope query -f json` reads a file named `json`.
* `scope auth status --format json` reports `auth_mode` `oauth` for a CLI login, adds `login_expires_at`, and uses `email` instead of `user`; it includes `credential_source` and omits deployment state. Read `provisioning.status` from `scope workspace get --format json` instead of `provisioning_state` from status. Workspace JSON uses `connection.endpoint` instead of `connection.api_base_url`.
* `scope console` replaces `scope open` and prints the Console URL by default. Replace `scope open [page]` with `scope console [page] --open` to launch the browser, or replace `scope open [page] --print` with `scope console [page]` to print the URL. Both modes print the URL to stdout.

### New features

* `scope auth login` opens a browser and completes the login through a loopback redirect, or prints a prefilled verification link and code to approve from another device without opening a browser, and shows a waiting message with the request's remaining lifetime until the login is approved, denied, or expires. A loopback response is accepted only when its `state` and issuer match the request, including error responses. If the browser cannot be opened, the loopback flow prints the authorization URL and keeps waiting. The login selects the workspace for the session: the profile's existing selection is kept when the account still owns it and is not deleting it, an account with a single workspace selects it, and an account with several workspaces asks which one to use on stderr, with `Skip for now` to select later.
* The CLI login is renewed automatically before its access token expires, using a rotating refresh token that is shared safely between concurrent `scope` processes; every credential update is serialized under the file lock.
* `scope auth logout` revokes the login in ScopeDB before removing local credentials, so a signed-out CLI cannot keep using its grant.
* `scope workspace create` creates a workspace, defaulting to the deployment's default placement, and selects it when the login has no workspace selected yet. `scope workspace list` shows whether each workspace is ready, still provisioning, or scheduled for deletion, and the CLI refuses to select a workspace that is scheduled for deletion.
* `auth logout`, `workspace use`, `console`, and `version` support `--format json` for machine-readable action results. Logout reports whether it cleared an existing login with `changed`.
* `scope workspace list` accepts `--limit` to cap displayed results without changing the default of showing all items.

### Bug fixes

* `scope doctor` now verifies query access for a logged-in workspace, reporting provisioning, token exchange, and query failures that previously went unchecked.
* Query timeout errors retain the statement ID and report when server cancellation could not be confirmed, so users can check the outcome before retrying.
* `scope auth login` no longer saves endpoint and credential-store settings before authentication succeeds; if the final configuration write fails, it revokes the new login and restores the previous valid credentials.
* `scope workspace list` no longer prints a "no workspace is selected" notice pointing back at itself when the account has workspaces to choose from; it now only reports setup guidance when there is nothing to list.

### Improvements

* Report the underlying cause when the CLI renders an error, in the terminal output and in `scope doctor` details, so a failure such as a credential store problem explains itself.
* A login that ScopeDB rejects, expires, or revokes is removed from the credential store, and the next command asks you to run `scope auth login` instead of failing with an opaque credential error.
* `scope workspace use` identifies the selected login workspace and warns when environment credentials override data commands or form an incomplete pair.
* `scope doctor` supports `--timeout` for slower connections and `--timeout 0` to disable per-check limits (individual control-plane requests retain a 15-second limit), includes recovery hints and request IDs in failed checks, and preserves exit code 130 when interrupted.
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
