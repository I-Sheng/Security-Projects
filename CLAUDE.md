# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a security research and education repository containing several independent modules. All top-level folder names follow `snake_case` convention.

- **`sniffing_and_spoofing/`** — Network packet sniffing and ICMP spoofing tools in C (using `libpcap`) and Python (using `scapy`). Compiled binaries (no extension) exist alongside their `.c` sources.
- **`ddos/`** — DoS attack simulation using `hping3` with MAC randomization via `macchanger`. Controlled via a `Makefile`.
- **`dns_lab/`** — Dockerized DNS lab with a BIND server (`named`) and client on an isolated `172.30.0.0/24` bridge network.
- **`dns_cache_poisoning/`** — DNS cache poisoning lab using Scapy to forge DNS responses against a local BIND resolver.
- **`firewall/`** — Linux firewall labs: Netfilter kernel modules, stateless and stateful `iptables` rules, rate limiting, and DNAT load balancing.
- **`ids_snort/`** — Intrusion detection lab using Snort for rule-based packet inspection and alerting.
- **`hex_tools/`** — Python scripts for XOR cipher operations (repeating-key XOR over raw bytes).
- **`win_linux_monitor_mapping_utility/`** — Reference scripts (`.sh`/`.bat` pairs) for cross-platform system/network diagnostics.

## Building and Running

### C tools (`sniffing_and_spoofing/`)

Each `.c` file compiles independently. Most require `libpcap` and root/`sudo`:

```bash
# Typical compile pattern (adjust filename):
gcc -o sniffer sniffer.c -lpcap
gcc -o sniff_spoof sniff_spoof.c -lpcap

# Run (requires root for raw sockets / pcap):
sudo ./sniff_spoof <iface>        # e.g., br-xxxx for a Docker network
sudo ./sniffer_icmp <iface>
```

### Python tools

```bash
# sniffing_and_spoofing — requires scapy + root
sudo python3 sniff_and_spoof.py
sudo python3 spoof.py
sudo python3 sniffer.py
sudo python3 traceroute.py

# hex_tools — no extra dependencies
python3 hex_tools/xor.py
```

### DDoS module

```bash
cd ddos
make          # runs hping3 flood + MAC rotation loop (requires hping3, macchanger, sudo)
make attack   # flood only
make hide     # MAC rotation loop only
```

### DNS Lab (Docker)

```bash
cd dns_lab
docker compose up -d --build      # build and start dns-server + dns-client
docker exec -it dns-client /bin/bash

# Inside client:
dig @172.30.0.2 example.com

# From host (port 53 is exposed):
dig @127.0.0.1 example.com

docker compose down               # stop
docker compose down --rmi local --volumes && docker compose up -d --build  # full reset
```

### Mouse mirroring (Windows only)

Compile `mouse_mirror.c` with a Windows toolchain (MinGW or MSVC) targeting `_WIN32_WINNT 0x0500`. Requires `winuser.h` / `windows.h`.

## Architecture Notes

- **C sniffers**: All follow the same pattern — open pcap handle on a named interface, compile a BPF filter, register a `got_packet` callback via `pcap_loop`. Spoofing replies use a raw socket with `IP_HDRINCL` and a manual ICMP checksum (`csum()`).
- **Python sniffers**: Thin wrappers around Scapy's `sniff()`/`send()`. The `spoof.py` script intercepts ICMP echo requests and replies with a crafted echo reply.
- **XOR tool**: `xor_cipher_repeating` in `hex_tools/xor.py` does repeating-key XOR. The single-byte shortcut is commented out above it.
- **DDoS Makefile** (`ddos/`): `make all` runs `attack` and `hide` in sequence (not in parallel); `hide` is an infinite loop that changes the MAC every 5 seconds.
