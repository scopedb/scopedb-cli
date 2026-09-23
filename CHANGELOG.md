# CHANGELOG

All significant changes to this project will be documented in this file.

## Unreleased

### New features

* `scope login`, `logout`, `workspace use`, `api-key revoke`, `open`, and `version` now support `--format json` for machine-readable action results.

### Bug fixes

* `scope doctor` now verifies query access for a logged-in workspace, reporting provisioning, token exchange, and query failures that previously went unchecked.
* Query timeout errors retain the statement ID and report when server cancellation could not be confirmed, so users can check the outcome before retrying.
* `scope login` no longer saves endpoint and credential-store settings before authentication succeeds; if the final configuration write fails, it restores the previous credentials.

### Improvements

* `scope doctor` supports `--timeout` for slower connections, includes recovery hints and request IDs in failed checks, and preserves exit code 130 when interrupted.
* `scope login` hides verification codes entered at a terminal and warns that `--code` exposes the value in process arguments.
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
