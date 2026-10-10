# Changelog

## [Unreleased]

## [v0.1.6] - 2026-10-11

### Changed

- Rename the module, runtime identifiers and project references to the `cautem` namespace.

## [v0.1.0-beta.1] - 2026-10-10

### Changed

- Complete the cautem rebrand and pin the matching core source in CI.
- Align CI and module tooling with Go 1.27.2.
- Resolve `cautem-core` from published v0.1.0-beta.2.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Parse and validate the pinned OpenShell provider profile schema, including discovery, credential metadata, and explicit runtime capability diagnostics.
- Resolve sandbox-scoped credential bindings during provider policy composition, rejecting unresolved or ambiguous references.

### Changed

- Match OpenShell discovery behavior: use only declared discovery credentials, collect every non-empty environment alias, and treat an empty discovery list as no discovery.
- Preserve `source` and `scope` metadata while leaving catalog authority to the gateway.
- Reject profile endpoint bindings and unsupported token-grant combinations during validation.
- Correct the standalone module checksums after publishing the core dependency.
