## Ghostlink v1.2.1

This patch aligns the public terminal recording with Ghostlink's unified operator workflow.
The Termius Pro-style demo now shows the actual offline diagnosis, compiled transport
inventory, and protected pipeline validation in sequence.

### Highlights

- Re-recorded `docs/demo.gif` and `docs/demo.mp4` in the black Termius Pro-inspired theme.
- The 21-second recording now demonstrates `ghostlink doctor`, `ghostlink transports`,
  and `ghostlink demo` rather than invoking the legacy standalone demo command.
- Every displayed result comes from the real compiled project; no output is scripted.
- Removed workstation-specific paths from doctor output and added regression coverage.
- macOS and Linux release archives for AMD64 and ARM64, each with checksums.

Ghostlink remains an authorized-lab transport research toolkit. It is not a TUN/VPN,
does not claim Ligolo-ng feature parity, and does not endorse unauthorized access,
persistence, evasion, or handling of third-party data.
