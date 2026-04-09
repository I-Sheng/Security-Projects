# IDS — Snort

This module covers intrusion detection using Snort, an open-source network-based IDS/IPS. Labs focus on installing and configuring Snort, writing detection rules, and analyzing alerts.

## What Is Snort?

Snort is a packet-inspection engine that operates in three modes:

- **Sniffer mode** — prints packet headers to the console.
- **Packet logger mode** — writes packets to disk for later analysis.
- **Intrusion Detection / Prevention mode** — matches traffic against a rule set and generates alerts (IDS) or drops packets (IPS).

## Prerequisites

- Linux host with root/`sudo` access
- Snort 2.x or 3.x (`apt install snort` on Debian/Ubuntu)
- `libpcap`

## Installation

```bash
sudo apt update
sudo apt install snort -y
snort --version
```

## Modes of Operation

```bash
# Sniffer mode — print packet summaries
sudo snort -v -i eth0

# Packet logger mode — log to /var/log/snort
sudo snort -dev -l /var/log/snort -i eth0

# IDS mode — use a rule file and log alerts
sudo snort -A console -q -i eth0 -c /etc/snort/snort.conf
```

## Writing Rules

A Snort rule has two parts: a **header** and **options**.

```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

Examples:

```snort
# Alert on any ICMP traffic
alert icmp any any -> any any (msg:"ICMP Detected"; sid:1000001; rev:1;)

# Alert on Telnet connections (cleartext protocol)
alert tcp any any -> any 23 (msg:"Telnet Connection Attempt"; sid:1000002; rev:1;)

# Detect an HTTP GET request containing "passwd"
alert tcp any any -> any 80 (msg:"HTTP passwd access"; content:"GET"; content:"/passwd"; sid:1000003; rev:1;)
```

## Rule Fields Reference

| Field | Description |
|---|---|
| `action` | `alert`, `log`, `pass`, `drop`, `reject` |
| `protocol` | `tcp`, `udp`, `icmp`, `ip` |
| `src/dst ip` | IP address, CIDR notation, or `any` |
| `src/dst port` | Port number, range, or `any` |
| `direction` | `->` (unidirectional) or `<>` (bidirectional) |
| `msg` | Human-readable alert message |
| `content` | Payload pattern match |
| `sid` | Unique rule identifier (local rules start at 1000000+) |
| `rev` | Rule revision number |

## Viewing Alerts

```bash
# Real-time console alerts
sudo snort -A console -q -i eth0 -c /etc/snort/snort.conf

# Inspect logged alerts
cat /var/log/snort/alert

# Read a saved pcap file instead of live traffic
sudo snort -r capture.pcap -c /etc/snort/snort.conf -A console
```

## Testing Rules

Use `ping`, `curl`, or `nc` from another host to generate traffic and verify that alerts fire as expected:

```bash
# Trigger the ICMP rule
ping <snort-host-ip>

# Trigger the Telnet rule
telnet <snort-host-ip> 23

# Trigger an HTTP content rule
curl http://<snort-host-ip>/passwd
```

## Reference Files

- `local/` — Course lab sheet (`Lab3_snort.pdf`) and a Snort quick-reference cheatsheet (`Snort_Cheatsheet_-_TryHackMe.pdf`).
- `Lab3_SNORT_Intrusion_Detection_System.pdf` — Full lab instructions.
