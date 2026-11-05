## Ghostlink v1.1.0

This release replaces the simulated terminal presentation with a real, network-free
pipeline validator and establishes a safer, reproducible project baseline.

### Highlights

- Real offline validation of key agreement, compression, parity layout, protocol
  framing, authenticated encryption, and integrity recovery.
- Termius Pro-inspired terminal recording generated from the executable demo.
- Loopback-only defaults for the server, DNS bridge, local forwarding, and SOCKS.
- Atomic owner-only artifact writes and traversal-resistant local filenames.
- Checked protocol serialization for payload size boundaries.
- Build metadata embedded in every release binary and exposed through `-version`.
- Reproducible macOS and Linux archives with SHA-256 checksums.
- Race-enabled tests, vet, formatting enforcement, CI, and CodeQL analysis.
- `golang.org/x/net` updated to v0.55.0, resolving the open dependency advisories.

Ghostlink remains an authorized-lab research project. The release does not claim
production readiness, stealth, or suitability for third-party systems.
