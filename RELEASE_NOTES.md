## Ghostlink v1.2.2

This patch replaces the diagnostic-only animation with a real application demonstration.

### What the demo now proves

- The actual `ghostlink-server` listens only on `127.0.0.1` using the HTTP transport.
- The actual `ghostlink-client` reads and transfers one synthetic authorized-lab file.
- The transfer uses the application's PSK-protected protocol path.
- The receiver writes the artifact with Ghostlink's owner-only file handling.
- `cmp` and SHA-256 verify the received bytes exactly match the sender.

The recording uses the clearer `-send-file` and `-output-dir` flags introduced in this
release. The previous `-exfil` and `-exfil-dir` names remain compatibility aliases.

The release includes checksummed macOS and Linux archives for AMD64 and ARM64. Ghostlink
remains an authorized-lab research toolkit and the demonstration contacts no external
system or service.
