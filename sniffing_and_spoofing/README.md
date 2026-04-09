# Sniffing and Spoofing

This module contains tools and lab experiments for packet sniffing and ICMP/TCP spoofing, implemented in both Python (Scapy) and C (libpcap + raw sockets).

## Overview

- **Python tools** (`sniffer.py`, `sniff_and_spoof.py`, `spoof.py`, `traceroute.py`) — thin wrappers around Scapy's `sniff()` and `send()`.
- **C tools** (`sniffer.c`, `sniffer_icmp.c`, `sniffer_tcp.c`, `sniffer_telnet.c`, `sniff_spoof.c`, `spoof_icmp.c`, `spoof_length.c`, `q5_exp.c`) — use `libpcap` for capture and raw `SOCK_RAW` sockets for spoofing; all follow the same pattern of opening a pcap handle, compiling a BPF filter, and registering a callback via `pcap_loop`.

## Prerequisites

- `libpcap` (install via `apt install libpcap-dev`)
- Python 3 with `scapy` (`pip install scapy`)
- Root / `sudo` privileges (required for raw socket and pcap access)

## Build

Each C file compiles independently:

```bash
gcc -o sniffer sniffer.c -lpcap
gcc -o sniffer_icmp sniffer_icmp.c -lpcap
gcc -o sniffer_tcp sniffer_tcp.c -lpcap
gcc -o sniffer_telnet sniffer_telnet.c -lpcap
gcc -o sniff_spoof sniff_spoof.c -lpcap
gcc -o spoof_icmp spoof_icmp.c -lpcap
gcc -o spoof_length spoof_length.c -lpcap
```

Pre-compiled binaries are included alongside their `.c` sources (no file extension).

## Usage

```bash
# Python sniffers/spoofers (requires root)
sudo python3 sniffer.py
sudo python3 spoof.py
sudo python3 sniff_and_spoof.py
sudo python3 traceroute.py

# C sniffer/spoofer (requires root; supply your network interface)
sudo ./sniff_spoof <iface>          # e.g. br-xxxx for a Docker bridge network
sudo ./sniffer_icmp <iface>
```

To find the right interface name:
```bash
ip a        # list all interfaces
```

## Architecture

**C sniffer pattern:**
1. `pcap_open_live()` — open the interface handle.
2. `pcap_compile()` + `pcap_setfilter()` — compile and apply a BPF filter.
3. `pcap_loop()` — capture packets and invoke the `got_packet` callback.
4. `pcap_close()` — release the handle.

**Spoofing pattern:**  
Open a raw socket with `IP_HDRINCL`, manually construct IP + ICMP headers, compute the ICMP checksum with `csum()`, and call `sendto()`.

---

## Lab Experiments

The `experiment/` folder contains detailed lab notes and screenshots from hands-on exercises.

### Set 1 — Using Scapy

#### Task 1.1 — Sniffing Packets

Root privileges are required because sniffers need raw link-layer access. Without root, Scapy raises `PermissionError: [Errno 1] Operation not permitted`.

BPF filters demonstrated:
- `filter='icmp'` — capture ICMP only.
- `filter='tcp and host 10.9.0.6 and port 23'` — TCP from a specific host to port 23.
- `filter='net 142.250.0.0/16'` — traffic to or from a specific subnet.

#### Task 1.2 — Spoofing ICMP Packets

A spoofed ICMP echo request was crafted with an arbitrary source IP (`10.0.2.3`) and sent to a target host. Wireshark confirmed the spoofed request arrived and the target replied to the forged source.

#### Task 1.3 — Traceroute

A script sends ICMP packets with TTL values from 2 to 50 toward a destination (`128.119.245.12`). Each router along the path returns a "Time Exceeded" message, revealing the hop-by-hop route.

#### Task 1.4 — Sniff-and-Spoof

`sniff_and_spoof.py` monitors the network for ICMP echo requests and immediately replies with a forged echo reply. Key observations:
- Remote IPs (e.g., `1.2.3.4`, `8.8.8.8`) receive the forged reply successfully.
- A non-existent LAN host (e.g., `10.9.0.99`) receives no reply because ARP resolution fails — no packet reaches the sniffer in the first place.

---

### Set 2 — C / libpcap

#### Task 2.1A — Understanding the Sniffer Library Calls

The essential call sequence:
1. `pcap_open_live()` — connect to the interface.
2. `pcap_compile()` — convert a filter string to BPF pseudo-code.
3. `pcap_setfilter()` — apply the compiled filter.
4. `pcap_loop()` — enter the capture loop with a callback.
5. `pcap_close()` — clean up.

Without root, `pcap_open_live()` fails immediately with a permissions error.

**Promiscuous mode** (`pcap_open_live(..., 1, ...)`) allows capturing all frames on the wire, not just those addressed to the host. With it off, only frames destined for the local MAC are captured.

#### Task 2.1B — BPF Filters in C

| Goal | Filter expression |
|---|---|
| ICMP between two specific hosts | `icmp and host 10.9.0.5 and host 10.9.0.6` |
| TCP with destination port 10–100 | `tcp and dst portrange 10-100` |

#### Task 2.1C — Sniffing Telnet Passwords

Telnet sends data in plaintext over TCP port 23. Using the filter `tcp and port 23` and printing the data payload of each captured packet, the cleartext password typed by the user is visible in the captured traffic.

#### Task 2.2 — Spoofing with Raw Sockets

A C program opens a `SOCK_RAW` socket (`IPPROTO_RAW`) with `IP_HDRINCL` and manually populates the IP and ICMP headers. Findings:

- **IP length field:** The kernel recomputes `ip_len` — setting an arbitrary value is overridden on send.
- **IP checksum:** Setting `ip_sum = 0` still results in a valid packet because the kernel recalculates it.
- **Root requirement:** `socket(AF_INET, SOCK_RAW, ...)` fails with `Operation not permitted` without root.

#### Task 2.3 — Sniff-and-Spoof in C

The C implementation captures an ICMP echo request and immediately sends a spoofed echo reply. When pinging a real host (e.g., `8.8.8.8`) while the program runs, the sender receives duplicate (DUP) replies — one real and one forged — visible in `ping` output.
