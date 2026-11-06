<div align="center">

# ghostlink

**Authorized lab framework for studying resilient out-of-band transport pipelines**

[![CI](https://img.shields.io/github/actions/workflow/status/jankesec/ghostlink/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/jankesec/ghostlink/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25%2B-111?style=flat-square&logo=go)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/jankesec/ghostlink?style=flat-square&label=Release)](https://github.com/jankesec/ghostlink/releases)
[![License](https://img.shields.io/badge/License-MIT-111?style=flat-square)](LICENSE)

Ghostlink is a Go research project for examining framing, authenticated encryption,
parity layouts, and multiple transport implementations inside controlled environments.

<img src="docs/demo.gif" alt="Ghostlink offline pipeline validation in a Termius Pro-style terminal" width="100%">

<sub>The demo answers one question: can a synthetic record complete Ghostlink's local protected pipeline and return byte-for-byte intact? It opens no sockets and contacts no external service.</sub>

</div>

## Purpose and boundaries

Ghostlink combines a protocol layer, session encryption, framing, parity encoding, and
nine registered transport implementations. It is intended for:

- isolated red-team and blue-team labs;
- defensive detection engineering;
- protocol and traffic-analysis research;
- interoperability and resilience experiments on systems you control.

It is not a claim of stealth, production readiness, firewall bypass, or guaranteed data
recovery. Internal capability scores are routing heuristics, not independently measured
evasion ratings. Do not deploy Ghostlink on third-party systems or networks without
explicit written authorization.

## Start here

Ghostlink now has one safe discovery command. It does not start a listener or contact a
target unless you deliberately move to the separate server or client binaries.

```bash
make build
./bin/ghostlink doctor
./bin/ghostlink transports
./bin/ghostlink demo
```

`doctor` reports the build, platform, protocol version, compiled transport catalog, and
safe-default posture without opening a socket. Add `--json` to `doctor` or `transports`
for scripts and CI.

The operator model borrows the strongest usability idea from modern tunnel tools: one
obvious entry point, discoverable commands, and visible environment requirements. It does
not turn Ghostlink into a VPN/TUN interface or claim feature parity with Ligolo-ng.

## Understand the offline demo

The safest way to understand the project is the deterministic local validation command:

```bash
go run ./cmd/ghostlink demo
```

It exercises real project packages end to end:

1. P-256 ephemeral key agreement;
2. zlib compression;
3. XOR parity layout generation;
4. protocol v2 framing and sequencing;
5. AES-256-GCM authenticated encryption;
6. reassembly and SHA-256 integrity verification.

No DNS, HTTP, ICMP, raw-packet, webhook, or cloud connection is created by the demo.
Its final `EXACT MATCH` compares the recovered bytes and SHA-256 digest with the input;
it does not claim network reliability or stealth.

## Architecture

```text
Synthetic or authorized input
           │
           ▼
┌────────────────────────┐
│ Compression            │  zlib
├────────────────────────┤
│ Parity layout          │  XOR data/parity shards
├────────────────────────┤
│ Framing                │  sequence + total metadata
├────────────────────────┤
│ Protocol envelope      │  version + type + stream ID
├────────────────────────┤
│ Session protection     │  ECDHE/PSK + AES-256-GCM
└───────────┬────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────┐
│ Explicitly selected transport                               │
│ DNS · DoH · HTTP · WebSocket · ICMP · TCP ISN · IPv4 ID ·  │
│ timing · packet size                                        │
└───────────┬──────────────────────────────────────────────────┘
            │
            ▼
 Authorized receiver → decrypt → reassemble → verify
```

The network transports are separate from the encoding pipeline. A successful offline
pipeline test does not prove that a given transport will work, remain reliable, or evade
detection in a real network.

## Component inventory

| Component | Location | Responsibility |
| --- | --- | --- |
| Operator CLI | `cmd/ghostlink` | Offline doctor, transport discovery, demo, and version |
| Offline validator | `internal/demo`, `cmd/demo` | Reusable pipeline validation and compatibility wrapper |
| Receiver/operator | `cmd/server` | Session handling and authorized artifact receipt |
| Sender/client | `cmd/client` | Transport selection and protocol initiation |
| DNS bridge | `bridge` | Lab DNS query decoding for controlled SQL testing |
| Protocol | `pkg/protocol` | Versioned message envelope and stream identifiers |
| Cryptography | `pkg/crypto` | P-256 key agreement and AES-256-GCM sessions |
| Encoding | `pkg/encoder` | Compression, frames, checksums, and XOR parity layouts |
| Transports | `pkg/channel` | Registered channel implementations |
| Session services | `pkg/session`, `pkg/shell`, `pkg/socks`, `pkg/forward` | Interactive lab services |
| Wireshark helper | `tools/ghostlink.lua` | Protocol inspection during packet analysis |

## Transport inventory

| Transport | Implementation notes | Environment considerations |
| --- | --- | --- |
| DNS | UDP query framing | Use a dedicated loopback or lab port; port 53 may require privileges |
| DNS over HTTPS | HTTP client/server carrying DNS messages | External resolvers are contacted only when explicitly configured |
| HTTP | Header-based request/response framing | Prefer loopback for development |
| WebSocket | Persistent user-space transport | Requires an explicit listener and client endpoint |
| ICMP | Echo payload transport | Usually requires raw-socket privileges |
| TCP ISN | Raw TCP sequence-field experiment | OS and privilege dependent |
| IPv4 ID | Raw IPv4 identification-field experiment | IPv4 and privilege dependent |
| Timing | Inter-arrival timing experiment | Sensitive to scheduler and network jitter |
| Packet size | Length-modulation experiment | Sensitive to MTU, padding, and intermediaries |

Raw-packet and timing transports are experimental. Validate each one independently in an
isolated environment before drawing conclusions from it.

## Build and verify

Go 1.25 or newer is required.

```bash
git clone https://github.com/jankesec/ghostlink.git
cd ghostlink

make check
make build
```

Every executable supports `-version`. Release builds include the version, source
commit, and UTC build date:

```bash
./bin/ghostlink version
```

The binaries are written to `./bin/`:

```text
bin/ghostlink
bin/ghostlink-demo
bin/ghostlink-server
bin/ghostlink-client
bin/ghostlink-bridge
```

Equivalent Go commands:

```bash
gofmt -l .
go vet ./...
go test ./...
go build ./...
```

## Controlled loopback exercise

The following example stays on the local machine and transfers only a synthetic file.
Use two terminal windows.

Receiver:

```bash
mkdir -p ./lab-output
go run ./cmd/server \
  -channel http \
  -addr 127.0.0.1:18080 \
  -key lab-only-key \
  -exfil-dir ./lab-output
```

Sender:

```bash
printf 'synthetic authorized-lab record\n' > /tmp/ghostlink-lab.txt
go run ./cmd/client \
  -channel http \
  -addr 127.0.0.1:18080 \
  -key lab-only-key \
  -exfil /tmp/ghostlink-lab.txt
```

Received artifacts are created with owner-only permissions. The server, bridge, local
port-forward, and SOCKS listeners default to loopback; binding to another interface is an
explicit operator decision.

## Security model

### Cryptography

- `-ecdhe` performs P-256 ephemeral key agreement and derives a session key.
- `-key` derives a 256-bit session key from a pre-shared value.
- Session payloads use AES-256-GCM with a fresh random nonce.
- Plain mode remains available for protocol debugging and provides no confidentiality.

Use ECDHE or a strong unique pre-shared key for any authorized network exercise. Transport
obfuscation is not a substitute for authentication, encryption, segmentation, or logging.

### Local data handling

- Receiver output directories use mode `0700`.
- Received files use mode `0600`.
- Filenames are reduced to their base name before storage.
- Default service and proxy listeners bind to `127.0.0.1`.

### Known limitations

- XOR parity is a research implementation, not a Reed-Solomon guarantee. Recovery behavior
  must be tested for the exact shard-loss pattern being evaluated.
- Transport capability values are code-level heuristics and should not be published as
  measured stealth scores.
- Raw-socket behavior varies across operating systems and often needs elevated privileges.
- Dead-drop integrations contact third-party services and are outside the offline demo and
  default verification path.
- The project does not provide an authorization system for multi-user operator access.
- A clean run proves only the path exercised in that run.

## Command discovery

Review the exact flags available in the checked-out version:

```bash
go run ./cmd/ghostlink help
go run ./cmd/ghostlink doctor
go run ./cmd/ghostlink transports
go run ./cmd/server -h
go run ./cmd/client -h
```

High-level modes present in the repository include single-file and glob transfer,
interactive sessions, local forwarding, SOCKS, multi-transport experiments, dead-drop
adapters, and DNS bridge support. These modes are intentionally not presented as turnkey
deployment recipes; configure them only inside an approved exercise plan.

When enabled with `ghostlink-server -api 127.0.0.1:8888`, the control API is restricted
to loopback, applies bounded HTTP timeouts and request bodies, and exposes read-only
`/healthz` and `/api/info` endpoints. Non-loopback API binds fail closed.

## Defensive research context

Ghostlink can help defenders build and verify detections related to these MITRE ATT&CK
areas:

| Area | Reference | Defensive question |
| --- | --- | --- |
| Protocol tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Can monitoring identify unexpected encapsulation? |
| Encrypted channel | [T1573](https://attack.mitre.org/techniques/T1573/) | Are unknown encrypted sessions visible and attributable? |
| Application-layer DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Are unusual labels, rates, and destinations detected? |
| Alternative-protocol transfer | [T1048](https://attack.mitre.org/techniques/T1048/) | Are ICMP and raw-header anomalies inspected? |
| Web-service transfer | [T1567](https://attack.mitre.org/techniques/T1567/) | Are unsanctioned destinations and credentials controlled? |

The mapping provides detection context; it does not certify that every implementation is
complete, stealthy, or suitable for operational use.

## Demo maintenance

The README animation is generated from [`docs/demo.tape`](docs/demo.tape) and runs the
real offline validator:

```bash
make record-demo
```

Do not edit `docs/demo.gif` manually. Update the validator or tape, regenerate the asset,
and visually inspect a final frame.

## Releases

Tag builds are verified again before publication. Each release contains macOS and Linux
archives for AMD64 and ARM64 plus a SHA-256 checksum manifest. The process is reproducible
locally with:

```bash
make release-artifacts VERSION=v1.1.0
```

Release history is maintained in [`CHANGELOG.md`](CHANGELOG.md).

## Responsible use

Ghostlink is dual-use security research software. You are responsible for authorization,
scope, data handling, network impact, and applicable law. Use synthetic data where
possible, keep listeners on loopback or an isolated lab network, and retain evidence of
the system owner's approval.

The maintainers do not endorse unauthorized access, credential collection, persistence,
traffic evasion, or transfer of third-party data.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing code or demo changes. Report
security issues according to [`SECURITY.md`](SECURITY.md) and do not publish working
exploit details in a public issue.

## License

MIT License. See [`LICENSE`](LICENSE).
