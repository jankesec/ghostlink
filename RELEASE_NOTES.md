## Ghostlink v1.2.0

This release makes Ghostlink easier to understand and safer to operate in an authorized
lab. The new unified command puts discovery and diagnostics first while keeping every
network-facing action explicit.

### Highlights

- One `ghostlink` entry point for `doctor`, `transports`, `demo`, and `version`.
- Offline doctor with human-readable and JSON output; it opens no sockets and contacts no
  targets or external services.
- Deterministic transport inventory that clearly identifies user-space, raw-socket, and
  timing/packet-signal requirements.
- Existing real crypto/framing demo reused by the unified CLI with no simulated output.
- Thread-safe, sorted transport registration.
- Optional control API restricted to loopback, with bounded timeouts and request bodies.
- Session termination now rejects read-only HTTP requests instead of mutating state.
- Read-only `/healthz` and `/api/info` endpoints for local observability.
- macOS and Linux release archives for AMD64 and ARM64, each with checksums.

Ghostlink remains an authorized-lab transport research toolkit. It is not a TUN/VPN,
does not claim Ligolo-ng feature parity, and does not endorse unauthorized access,
persistence, evasion, or handling of third-party data.
