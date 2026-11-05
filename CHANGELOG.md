# Changelog

All notable changes to Ghostlink are documented in this file. The project follows
[Semantic Versioning](https://semver.org/).

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
