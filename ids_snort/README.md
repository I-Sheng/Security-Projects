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

---

## Original Assignment

*CSS 537 Lab3: SNORT Intrusion Detection System*

### Lab Objectives

- Become familiar with Snort as a packet sniffer and intrusion detection system.
- Create custom rules to detect various attacks such as ping scans and port scans.
- Test custom rules and analyze Snort log files.

### Lab Environment

| Role | Machine | Notes |
|---|---|---|
| Defender | Kali Linux (Snort 3.x) | Runs Snort; monitored interface `eth0` |
| Attacker | Metasploitable 2 | Generates attack traffic |
| Network | Same subnet | Host-Only or Internal Network recommended |

**Snort file locations:**

| Purpose | Path |
|---|---|
| Main config | `/etc/snort/snort.lua` |
| Custom rules | `/etc/snort/rules/lab3.rules` |
| Logs | `/var/log/snort/lab3/` |

---

### Task 0 – Install and Verify Snort 3

```bash
sudo apt update
sudo apt install -y snort
snort -V   # Expected: Snort++ 3.x.x.x

sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort/lab3
```

---

### Task 1 – Use Snort as a Packet Sniffer

Demonstrate how Snort can be used as a packet sniffer. Ping a different IP address and observe the Snort output.

```bash
# On Defender — start sniffer mode
sudo snort -v -d -e -i eth0

# On Attacker — trigger traffic
ping <KALI_IP>
```

Expected result: Snort displays packet statistics showing ICMP packets captured.

---

### Task 2 – Detect Ping Scans with a Custom IDS Rule

Write a custom rule to detect ICMP ping scans, load it in IDS mode, and verify alerts.

```bash
# Step 2.1 — Create rule
sudo nano /etc/snort/rules/lab3.rules
```

```snort
alert icmp any any -> $HOME_NET any (msg:"LAB3 ICMP ping scan detected"; itype:8; detection_filter:track by_src, count 3, seconds 10; sid:1000001; rev:2;)
```

```bash
# Step 2.2 — Run Snort in IDS mode
sudo snort -c /etc/snort/snort.lua \
           -R /etc/snort/rules/lab3.rules \
           -i eth0 -A alert_fast \
           -l /var/log/snort/lab3

# Step 2.3 — Trigger attack from Attacker
ping -i 0.2 -c 10 <KALI_IP>
```

---

### Task 3 – Detect Port Scans

Write and test rules for three Nmap scan types. For each: launch the scan, add a detection rule, restart Snort, and verify the alert.

**Step 1 — SYN scan**
```bash
# Attacker
nmap -sS <KALI_IP>
```

**Step 2 — FIN scan**

In a FIN scan the attacker searches for open ports using only the FIN flag. A closed port returns RST; an open port returns no response.

```bash
nmap -sF <KALI_IP>
```

**Step 3 — XMAS scan**

An XMAS scan uses the FIN, PSH, and URG flags simultaneously. Same open/closed response behaviour as FIN scan.

```bash
nmap -sX <KALI_IP>
```

After adding rules for all three scans, restart Snort and confirm each alert fires.

---

### Task 4 – Custom Rule for Any Other Attack

Write your own custom Snort rule to detect **any** attack of your choice against the victim machine. Demonstrate the attack and show how Snort detects it. Document the rule and results in your lab report.

---

### Task 5 – Detect Browsing to facebook.com

Write a rule that fires when the machine running Snort makes an outbound TCP request to `facebook.com`. The rule should look for the hostname in the payload, not just an IP address.

---

### Task 6 – Questions

**Q1.** Explain how each of the following real Snort rules works:

```snort
alert icmp any any -> any any (msg:"ICMP Source Quench"; itype:4; icode:0;)
```

```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"WEB-CGI view-source access"; flags:A+; content:"/view-source?../../../../../../../etc/passwd"; nocase; reference:cve,CVE-1999-0174;)
```

**Q2.** Develop your own Snort signature to capture DNS queries directed at a host you connect to via HTTPS. The rule must reference DNS data (the queried hostname), not just the server's IP address.
