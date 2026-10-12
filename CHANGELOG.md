# CHANGELOG

All significant changes to this project will be documented in this file.

## Unreleased

### Breaking changes

* Authentication commands are grouped under `scope auth`: replace `scope login`, `scope logout`, and `scope status` with `scope auth login`, `scope auth logout`, and `scope auth status`. Replace `scope workspace show` with `scope workspace get`. The old command paths are not aliases.
* `-f` selects query input files. Replace every `-f <format>` with `--format <format>`; use `scope query -f <file>` as shorthand for `--file <file>`. In particular, `scope query -f json` reads a file named `json`.
* `scope auth status --format json` uses `email` instead of `user`, includes `credential_source`, and omits deployment state; read `provisioning.status` from `scope workspace get --format json` instead of `provisioning_state` from status. Workspace JSON uses `connection.endpoint` instead of `connection.api_base_url`.
* `scope console` replaces `scope open` and prints the Console URL by default. Replace `scope open [page]` with `scope console [page] --open` to launch the browser, or replace `scope open [page] --print` with `scope console [page]` to print the URL. Both modes print the URL to stdout.

### New features

* `scope auth login`, `auth logout`, `workspace use`, `api-key revoke`, `console`, and `version` support `--format json` for machine-readable action results. Logout reports whether it cleared an existing login with `changed`.
* `scope workspace list` and `api-key list` accept `--limit` to cap displayed results without changing the default of showing all items.

### Bug fixes

* `scope doctor` now verifies query access for a logged-in workspace, reporting provisioning, token exchange, and query failures that previously went unchecked.
* Query timeout errors retain the statement ID and report when server cancellation could not be confirmed, so users can check the outcome before retrying.
* `scope auth login` no longer saves endpoint and credential-store settings before authentication succeeds; if the final configuration write fails, it restores the previous valid credentials.
* `scope workspace list` no longer prints a "no workspace is selected" notice pointing back at itself when the account has workspaces to choose from; it now only reports setup guidance when there is nothing to list.

### Improvements

* Report the underlying cause when the CLI renders an error, in the terminal output and in `scope doctor` details, so a failure such as a credential store problem explains itself.
* `scope workspace use` identifies the selected login workspace and warns when environment credentials override data commands or form an incomplete pair.
* `scope doctor` supports `--timeout` for slower connections and `--timeout 0` to disable per-check limits (individual control-plane requests retain a 15-second limit), includes recovery hints and request IDs in failed checks, and preserves exit code 130 when interrupted.
* `scope auth login` hides verification codes entered at a terminal and warns that `--code` exposes the value in process arguments.
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
