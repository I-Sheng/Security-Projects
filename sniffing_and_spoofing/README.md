# Sniffing and Spoofing

This module implements packet sniffing and ICMP/TCP spoofing in both Python (Scapy) and C (libpcap + raw sockets). The goal is to understand how these two fundamental network threats work at the implementation level, not just as tools.

> **Source:** SEED Labs — Packet Sniffing and Spoofing Lab (Wenliang Du, 2006–2020)

## Overview

- **Python tools** (`sniffer.py`, `sniff_and_spoof.py`, `spoof.py`, `traceroute.py`) — thin wrappers around Scapy's `sniff()` and `send()`.
- **C tools** (`sniffer.c`, `sniffer_icmp.c`, `sniffer_tcp.c`, `sniffer_telnet.c`, `sniff_spoof.c`, `spoof_icmp.c`, `spoof_length.c`, `q5_exp.c`) — use `libpcap` for capture and raw `SOCK_RAW` sockets for spoofing.

## Prerequisites

- `libpcap` (`apt install libpcap-dev`)
- Python 3 with `scapy` (`pip install scapy`)
- Root / `sudo` privileges (required for raw socket and pcap access)

## Lab Environment

Three containers on a shared `10.9.0.0/24` LAN:

| Host | IP | Role |
|---|---|---|
| Attacker | `10.9.0.1` | Runs sniffers and spoofers (host network mode) |
| Host A | `10.9.0.5` | User machine |
| Host B | `10.9.0.6` | User machine |

The attacker container uses `network_mode: host` so it can see all LAN traffic — not just its own. The interface name is the Docker bridge: find it with `ifconfig` and look for the address `10.9.0.1` (typically `br-<network-id>`).

```bash
docker-compose up -d       # start lab containers
docker ps                  # list running containers
docker exec -it <id> bash  # open shell on a container
```

## Build

Each C file compiles independently:

```bash
gcc -o sniffer       sniffer.c       -lpcap
gcc -o sniffer_icmp  sniffer_icmp.c  -lpcap
gcc -o sniffer_tcp   sniffer_tcp.c   -lpcap
gcc -o sniffer_telnet sniffer_telnet.c -lpcap
gcc -o sniff_spoof   sniff_spoof.c   -lpcap
gcc -o spoof_icmp    spoof_icmp.c    -lpcap
gcc -o spoof_length  spoof_length.c  -lpcap
```

Pre-compiled binaries are included alongside their `.c` sources (no file extension).

## Architecture

**C sniffer pattern:**
1. `pcap_open_live()` — open the interface handle.
2. `pcap_compile()` + `pcap_setfilter()` — compile and apply a BPF filter.
3. `pcap_loop()` — capture packets and invoke the `got_packet` callback.
4. `pcap_close()` — release the handle.

**Spoofing pattern:**  
Open a raw socket with `IP_HDRINCL`, manually construct IP + ICMP headers, compute the ICMP checksum with `csum()`, and call `sendto()`.

---

## Task Set 1 — Using Scapy

### Task 1.1 — Sniffing Packets

The objective is to use Scapy's `sniff()` to capture packets in Python. A basic sniffer:

```python
#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-c93733e9f913', filter='icmp', prn=print_pkt)
```

**Task 1.1A** — Run the sniffer with root privilege, then again without it.

```bash
chmod a+x sniffer.py
sudo ./sniffer.py        # as root
su seed && ./sniffer.py  # without root
```

*Observation:* Root is required because sniffers need raw link-layer access. Without it, Scapy raises `PermissionError: [Errno 1] Operation not permitted`.

**Task 1.1B** — Set each BPF filter separately and demonstrate the results:

1. `filter='icmp'` — capture ICMP packets only.
2. `filter='tcp and host 10.9.0.6 and port 23'` — TCP from a specific host to port 23.
3. `filter='net 128.230.0.0/16'` — packets to/from a subnet (do not use the VM's own subnet).

---

### Task 1.2 — Spoofing ICMP Packets

Scapy lets you set any field of an IP packet to an arbitrary value. Spoof an ICMP echo request with a fake source IP and send it to a host on the same network. Use Wireshark to confirm the receiver accepts the packet and replies to the spoofed source.

```python
from scapy.all import *
a = IP()
a.dst = '10.9.0.5'
a.src = '10.0.2.3'   # arbitrary spoofed source
b = ICMP()
send(a / b)
```

*Observation:* The target replied to the forged source IP, confirming the spoofed request was accepted.

---

### Task 1.3 — Traceroute

Write a script that sends ICMP packets with increasing TTL (from 1 upward) toward a destination, recording the IP of each router that returns a "Time Exceeded" message.

```python
from scapy.all import *
dst = '128.119.245.12'
for ttl in range(1, 50):
    pkt = IP(dst=dst, ttl=ttl) / ICMP()
    reply = sr1(pkt, timeout=1, verbose=0)
    if reply is None:
        print(f"{ttl}: *")
    elif reply.type == 11:
        print(f"{ttl}: {reply.src}")
    else:
        print(f"{ttl}: {reply.src} (destination reached)")
        break
```

*Observation:* Each router along the path returned a Time Exceeded message, revealing the hop-by-hop route to the destination.

---

### Task 1.4 — Sniff-and-Spoof

Write a program that monitors ICMP echo requests and immediately sends a spoofed echo reply for every request it sees — making even non-existent hosts appear alive.

Ping each address from the user container and explain the results:

```bash
ping 1.2.3.4    # non-existing host on the Internet
ping 10.9.0.99  # non-existing host on the LAN
ping 8.8.8.8    # existing host on the Internet
```

*Observations:*
- `1.2.3.4` (remote, non-existing): the forged reply is received successfully — ping gets a response.
- `10.9.0.99` (LAN, non-existing): no reply, because ARP resolution fails. Before any ICMP packet is sent, the kernel broadcasts an ARP request to find the MAC address of `10.9.0.99`. Since the host doesn't exist, ARP gets no reply and the ICMP packet is never sent — the sniffer never sees it.
- `8.8.8.8` (remote, existing): both a real reply and a forged reply arrive — ping reports `DUP!` on the duplicate.

> **Hint:** Use `ip route get 1.2.3.4` to understand routing decisions.

---

## Task Set 2 — C / libpcap and Raw Sockets

### Task 2.1A — Understanding the Sniffer Library Calls

Write a C sniffer that prints source and destination IPs for each captured packet.

**Q1.** What is the essential sequence of library calls?
1. `pcap_open_live()` — connect to the interface.
2. `pcap_compile()` — convert a BPF filter string to pseudo-code.
3. `pcap_setfilter()` — apply the compiled filter.
4. `pcap_loop()` — enter the capture loop, invoking the callback per packet.
5. `pcap_close()` — clean up.

**Q2.** Why does the sniffer require root? At which call does it fail?  
`pcap_open_live()` fails immediately with a permissions error if run without root, because opening a raw socket on a network interface requires elevated privileges.

**Q3.** Demonstrate the difference between promiscuous mode on (`pcap_open_live(..., 1, ...)`) and off (`0`).  
Promiscuous mode allows capturing all frames on the wire, not just those addressed to the host's MAC. Verify with `ip -d link show dev <iface>` — look for `promiscuity 1`.

---

### Task 2.1B — Writing Filters

Write BPF filter expressions and demonstrate each:

| Goal | Filter expression |
|---|---|
| ICMP between two specific hosts | `icmp and host 10.9.0.5 and host 10.9.0.6` |
| TCP with destination port 10–100 | `tcp and dst portrange 10-100` |

---

### Task 2.1C — Sniffing Telnet Passwords

Modify your sniffer to print the data payload of captured TCP packets. Use the filter `tcp and port 23`.

*Observation:* Telnet sends data in plaintext. Each keystroke appears as a small payload in the captured packets, revealing the cleartext password typed by the user.

---

### Task 2.2 — Spoofing with Raw Sockets

Write a C program that opens a `SOCK_RAW` socket (`IPPROTO_RAW`) with `IP_HDRINCL` and manually fills in the IP and ICMP headers.

**Task 2.2A** — Provide Wireshark evidence that the spoofed packet is transmitted.

**Task 2.2B** — Spoof an ICMP echo request from another machine's IP to a live Internet host. Capture the echo reply in Wireshark to confirm success.

**Q4.** Can you set the IP length field to an arbitrary value regardless of actual packet size?  
No — the kernel overrides `ip_len` on send.

**Q5.** Do you need to manually calculate the IP checksum?  
No — setting `ip_sum = 0` still results in a valid packet; the kernel recomputes it automatically.

**Q6.** Why does using raw sockets require root?  
`socket(AF_INET, SOCK_RAW, ...)` fails with `Operation not permitted` without root.

---

### Task 2.3 — Sniff-and-Spoof in C

Re-implement the sniff-and-spoof logic in C using `libpcap` and raw sockets. When pinging a real host (e.g., `8.8.8.8`) while the program runs, the sender should receive duplicate (DUP) replies — one real and one forged.

*Observation:* The `ping` output shows `DUP!` on forged replies, confirming the C implementation successfully races a spoofed reply before or alongside the legitimate response.

---
