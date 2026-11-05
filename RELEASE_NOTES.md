## Ghostlink v1.1.1

This patch makes the safe offline demo understandable at a glance while retaining the
professional project and release baseline introduced in v1.1.0.

### Highlights

- A clear input → secure local pipeline → verified output story with an exact digest
  match and explicit statement of what the demo does and does not prove.
- Real offline validation of key agreement, compression, parity layout, protocol
  framing, authenticated encryption, and integrity recovery.
- Termius Pro-inspired terminal recording generated from the executable demo.
- Loopback-only defaults for the server, DNS bridge, local forwarding, and SOCKS.
- Atomic owner-only artifact writes and traversal-resistant local filenames.
- Checked protocol serialization for payload size boundaries.
- Build metadata embedded in every release binary and exposed through `-version`.
- Reproducible macOS and Linux archives with SHA-256 checksums.
- Race-enabled tests, vet, formatting enforcement, CI, and CodeQL analysis.
- Node 24-based GitHub Actions, pinned to immutable upstream commits.
- `golang.org/x/net` v0.55.0 with no open Dependabot alerts at publication time.

Ghostlink remains an authorized-lab research project. The release does not claim
production readiness, stealth, or suitability for third-party systems.
