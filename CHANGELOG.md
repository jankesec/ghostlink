# Changelog

All notable changes to Ghostlink are documented in this file. The project follows
[Semantic Versioning](https://semver.org/).

## [1.2.2] - 2026-11-06

### Added

- Added clear `-send-file` and `-output-dir` names for the authorized single-file
  transfer workflow while retaining the legacy flags as compatibility aliases.

### Fixed

- Replaced the diagnostic-only README recording with a real loopback server/client run.
  The demo now transfers synthetic data through the HTTP transport with a PSK and proves
  byte-for-byte and SHA-256 equality at the receiver.
- Updated single-file transfer logs and documentation to describe the actual workflow.

## [1.2.1] - 2026-11-06

### Fixed

- Re-recorded the README demo from the unified CLI so it now demonstrates `doctor`,
  `transports`, and the real offline pipeline instead of the legacy demo command.
- Removed the local filesystem path from doctor output to keep diagnostics deterministic
  and public recordings free of workstation-specific details.

## [1.2.0] - 2026-11-06

### Added

- Unified `ghostlink` operator CLI with offline `doctor`, `transports`, `demo`, and
  `version` commands plus JSON output for diagnostics and transport discovery.
- Read-only API health and build-information endpoints.
- Focused coverage for the CLI, operator catalog, API bind policy, and registry order.

### Changed

- Made the transport registry deterministic and safe for concurrent access.
- Restricted the optional control API to loopback and added HTTP/request-size limits.
- Required an explicit mutating method for the API session-kill action.
- Reused one demo implementation from both the compatibility binary and unified CLI.
- Added the unified binary to local and cross-platform release builds.

## [1.1.1] - 2026-11-06

### Changed

- Reframed the terminal demo as a clear input-to-verified-output story.
- Added explicit zero-network boundaries and explained what the result does not prove.
- Updated pinned GitHub Actions to their Node 24-based releases.

## [1.1.0] - 2026-11-06

### Added

- Network-free local pipeline validator and reproducible Termius-style demo.
- Build metadata package, `-version` flags, release archives, and checksums.
- Atomic owner-only file writer with focused unit tests.
- Checked protocol serialization and boundary tests.
- CI, race testing, CodeQL, contribution guidance, and security policy.

### Changed

- Rewrote the project documentation around verified behavior and explicit limits.
- Changed network-facing defaults to loopback addresses.
- Updated Go to 1.25 and `golang.org/x/net` to v0.55.0.

### Removed

- Removed the scripted demo that fabricated sessions and operational results.

[1.1.0]: https://github.com/jankesec/ghostlink/releases/tag/v1.1.0
[1.1.1]: https://github.com/jankesec/ghostlink/releases/tag/v1.1.1
[1.2.0]: https://github.com/jankesec/ghostlink/releases/tag/v1.2.0
[1.2.1]: https://github.com/jankesec/ghostlink/releases/tag/v1.2.1
[1.2.2]: https://github.com/jankesec/ghostlink/releases/tag/v1.2.2
