# Security Code

A collection of hands-on security research and education labs covering network attacks, intrusion detection, firewalls, and cryptographic tools. Each module is self-contained with its own build instructions, lab write-ups, and experiment notes.

## Modules

| Module | Topic | Language / Tools |
|---|---|---|
| [`sniffing_and_spoofing/`](#sniffing_and_spoofing) | Packet sniffing and ICMP/TCP spoofing | C (libpcap), Python (Scapy) |
| [`ddos/`](#ddos) | DoS flood simulation with MAC randomization | hping3, macchanger, Make |
| [`dns_lab/`](#dns_lab) | Dockerized DNS exploration and security analysis | Docker, BIND, dig |
| [`dns_cache_poisoning/`](#dns_cache_poisoning) | DNS cache poisoning via forged responses | Python (Scapy) |
| [`firewall/`](#firewall) | Linux firewall implementation from kernel to iptables | C (Netfilter), iptables, conntrack |
| [`ids_snort/`](#ids_snort) | Intrusion detection with rule-based packet inspection | Snort |
| [`hex_tools/`](#hex_tools) | XOR cipher operations on raw bytes | Python |
| [`win_linux_monitor_mapping_utility/`](#win_linux_monitor_mapping_utility) | Cross-platform system/network diagnostics reference | Bash, Batch |

---

## sniffing_and_spoofing

**Topic:** Capturing and forging network packets at the link and IP layer.

Tools: C with `libpcap` for raw packet capture, Python with `Scapy` for flexible crafting and sending. Covers BPF filters, promiscuous mode, ICMP spoofing, raw socket programming, and sniff-then-spoof patterns.

→ [Module README](sniffing_and_spoofing/README.md) · [Lab Notes](sniffing_and_spoofing/experiment/README.md)

---

## ddos

**Topic:** Simulated denial-of-service flooding with source obfuscation.

Uses `hping3` to flood a target with raw IP packets at maximum rate while continuously rotating the MAC address via `macchanger` to hinder filtering and tracing.

→ [Module README](ddos/README.md)

---

## dns_lab

**Topic:** DNS resolution internals and security properties.

A Dockerized lab (BIND server + client on a `172.30.0.0/24` bridge) for exploring the DNS query chain, capturing DNS traffic, observing DNSSEC validation, and understanding the threat model around recursive resolvers.

→ [Module README](dns_lab/README.md) · [Lab Notes](dns_lab/experiment/README.md)

---

## dns_cache_poisoning

**Topic:** Attacking a local BIND resolver with forged DNS responses.

Using Scapy to race crafted DNS replies — poisoning A records, NS records (same zone and cross-zone), and Additional section glue records — against a running resolver to observe what gets cached and what gets rejected.

→ [Module README](dns_cache_poisoning/README.md) · [Lab Notes](dns_cache_poisoning/experiment/README.md)

---

## firewall

**Topic:** Linux firewall implementation from the kernel up.

Five progressive labs: writing a hello-world kernel module, registering Netfilter hooks to inspect and drop packets, configuring stateless `iptables` rules, upgrading to stateful `conntrack`-based rules, adding rate limiting, and implementing round-robin / random DNAT load balancing.

→ [Module README](firewall/README.md) · [Lab Notes](firewall/experiment/README.md)

---

## ids_snort

**Topic:** Network intrusion detection with Snort.

Covers Snort's three operating modes, writing custom detection rules (ICMP, TCP, content matching), and testing them against live traffic or pcap files.

→ [Module README](ids_snort/README.md)

---

## hex_tools

**Topic:** XOR cipher for raw byte data.

A Python utility implementing repeating-key XOR — useful for decoding obfuscated shellcode or simple XOR-encrypted payloads.

→ [Module README](hex_tools/README.md)

---

## win_linux_monitor_mapping_utility

**Topic:** Cross-platform diagnostics command reference.

Paired `.sh`/`.bat` scripts and comparison tables mapping Windows CLI tools (`netstat`, `tasklist`, `wevtutil`, `net user`, etc.) to their Linux equivalents (`ss`, `ps`, `journalctl`, `getent`, etc.).

→ [Module README](win_linux_monitor_mapping_utility/README.md)

---

## Repository Structure

```
security-code/
├── sniffing_and_spoofing/
│   ├── README.md           ← build & usage guide
│   ├── *.c / *.py          ← source code
│   ├── experiment/
│   │   ├── README.md       ← detailed lab write-up
│   │   └── images/         ← lab screenshots
│   └── local/              ← course lab sheet (PDF)
├── ddos/
├── dns_lab/
├── dns_cache_poisoning/
├── firewall/
├── ids_snort/
├── hex_tools/
└── win_linux_monitor_mapping_utility/
```

Each module follows the same layout: a top-level `README.md` for build/usage, an `experiment/` folder with a detailed lab `README.md` and `images/`, and a `local/` folder with the original course materials (PDFs).
