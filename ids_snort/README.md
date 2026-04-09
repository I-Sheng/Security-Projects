# IDS — Snort

This module covers intrusion detection using Snort 3, an open-source network-based IDS/IPS. Labs focus on installing Snort, writing custom detection rules, and analyzing alerts for ping scans, port scans, and other attacks.

> **Source:** CSS 537 Lab3 — SNORT Intrusion Detection System

## What Is Snort?

Snort's architecture consists of four components working in a pipeline: the **sniffer** captures packets from the interface; the **preprocessor** checks for anomalies (IP fragmentation, etc.); the **detection engine** matches packets against a rule set; and the **alert processor** logs or notifies when a match is found.

Snort rules have two parts: a **header** (action, protocol, source/destination addresses and ports, direction) and **options** (message, content patterns, detection filters, SID, etc.):

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

Snort operates in three modes:

- **Sniffer mode** — prints packet headers/payloads to the console.
- **Packet logger mode** — writes captured packets to disk.
- **IDS/IPS mode** — matches traffic against rules, generates alerts (IDS) or drops packets (IPS).

## Lab Environment

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

## Task 0 — Install and Verify Snort 3

```bash
sudo apt update
sudo apt install -y snort
snort -V    # Expected output: Snort++ 3.x.x.x

# Create directories if missing
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort/lab3
```

---

## Task 1 — Use Snort as a Packet Sniffer

Demonstrate how Snort can be used as a standalone packet sniffer. Start Snort in sniffer mode on the defender, then generate traffic from the attacker and observe the output.

```bash
# Defender — sniffer mode (shows data layer + link layer headers)
sudo snort -v -d -e -i eth0

# Attacker — trigger ICMP traffic
ping <KALI_IP>
```

*Expected result:* Snort displays packet summaries including protocol, source/destination, and ICMP statistics.

---

## Task 2 — Detect Ping Scans with a Custom IDS Rule

Write a custom rule to detect ICMP ping scans, run Snort in IDS mode, and verify that alerts fire when the scan threshold is exceeded.

**Step 2.1 — Create the rule file:**

```bash
sudo nano /etc/snort/rules/lab3.rules
```

Add:

```snort
alert icmp any any -> $HOME_NET any (msg:"LAB3 ICMP ping scan detected"; itype:8; detection_filter:track by_src, count 3, seconds 10; sid:1000001; rev:2;)
```

The `detection_filter` suppresses alerts until the source sends more than 3 ICMP echo requests within 10 seconds — distinguishing a scan from a single ping.

**Step 2.2 — Run Snort in IDS mode:**

```bash
sudo snort -c /etc/snort/snort.lua \
           -R /etc/snort/rules/lab3.rules \
           -i eth0 \
           -A alert_fast \
           -l /var/log/snort/lab3
```

**Step 2.3 — Trigger the attack from the attacker:**

```bash
ping -i 0.2 -c 10 <KALI_IP>
```

Check `/var/log/snort/lab3/` for alert output.

---

## Task 3 — Detect Port Scans

Write and test rules for three Nmap scan types. For each: launch the scan from the attacker, write a detection rule on the defender, reload Snort, and verify the alert fires.

**SYN Scan** — sends a SYN packet; if the port is open the target responds with SYN-ACK. The attacker never completes the handshake.

```bash
# Attacker
nmap -sS <KALI_IP>
```

Example rule:
```snort
alert tcp any any -> $HOME_NET any (msg:"LAB3 SYN scan detected"; flags:S; detection_filter:track by_src, count 20, seconds 5; sid:1000002; rev:1;)
```

**FIN Scan** — sends only the FIN flag. A closed port returns RST; an open port returns no response (the host is searching for open ports by looking for non-responses).

```bash
nmap -sF <KALI_IP>
```

**XMAS Scan** — sets the FIN, PSH, and URG flags simultaneously (the packet is "lit up like a Christmas tree"). Same open/closed behavior as FIN scan.

```bash
nmap -sX <KALI_IP>
```

Add rules for all three scan types, restart Snort, and confirm each alert fires independently.

---

## Task 4 — Custom Rule for Any Other Attack

Write your own custom Snort rule to detect **any** attack of your choice against the victim machine. Demonstrate the attack, show how Snort detects it, and document the rule and results in your lab report.

Example starting points: Telnet brute-force, HTTP directory traversal, FTP login attempts, or a vulnerability scanner.

---

## Task 5 — Detect Browsing to facebook.com

Write a rule that fires when the machine running Snort makes an outbound TCP request to `facebook.com`. The rule must look for the hostname in the packet payload, not just an IP address — IP addresses for CDN-backed sites change frequently.

```snort
alert tcp $HOME_NET any -> any 80 (msg:"LAB3 HTTP request to facebook.com"; content:"Host: www.facebook.com"; nocase; sid:1000010; rev:1;)
```

Test by browsing to `http://www.facebook.com` from the defender machine and verifying the alert appears in the log.

---

## Task 6 — Rule Analysis Questions

**Q1.** Explain how each of the following real Snort rules from the Snort home page works:

```snort
alert icmp any any -> any any (msg:"ICMP Source Quench"; itype:4; icode:0;)
```

*Explanation:* Alerts on any ICMP packet of type 4, code 0 — an "ICMP Source Quench" message, which is a legacy congestion control signal asking the sender to slow down. The rule catches any host sending this message from or to any IP, generating an alert with the message "ICMP Source Quench."

```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"WEB-CGI view-source access"; flags:A+; content:"/view-source?../../../../../../../etc/passwd"; nocase; reference:cve,CVE-1999-0174;)
```

*Explanation:* Alerts on a TCP ACK packet (established connection) from any external host to an HTTP server on port 80 whose payload contains the path `/view-source?../../../../../../../etc/passwd` (case-insensitive). This is a classic CGI directory traversal exploit (CVE-1999-0174) that attempts to read `/etc/passwd` through a vulnerable web server.

**Q2.** Develop your own Snort signature to capture DNS queries directed at a host you connect to via HTTPS. The rule must reference DNS data (the queried hostname), not just the server's IP address.

```snort
alert udp any any -> any 53 (msg:"LAB3 DNS query for secure.example.com"; content:"|07|example|03|com"; nocase; sid:1000020; rev:1;)
```

The rule matches UDP packets to port 53 whose payload contains the DNS-encoded representation of the hostname (length-prefixed labels in DNS wire format), ensuring it triggers on domain name lookups rather than IP-based connections.

---

## Rule Fields Reference

| Field | Description |
|---|---|
| `action` | `alert`, `log`, `pass`, `drop`, `reject` |
| `protocol` | `tcp`, `udp`, `icmp`, `ip` |
| `src/dst ip` | IP address, CIDR notation, variable (e.g., `$HOME_NET`), or `any` |
| `src/dst port` | Port number, range (`1:1024`), or `any` |
| `direction` | `->` unidirectional or `<>` bidirectional |
| `msg` | Human-readable alert message |
| `content` | Payload pattern match (supports hex `|xx xx|` notation) |
| `itype` / `icode` | ICMP type and code |
| `flags` | TCP flag matching (`S`, `A`, `F`, `R`, `U`, `P`) |
| `detection_filter` | Rate-based suppression (`track by_src/by_dst, count N, seconds N`) |
| `sid` | Unique rule ID (local rules start at `1000000+`) |
| `rev` | Rule revision number |
| `nocase` | Case-insensitive content match |
| `reference` | Link to CVE or external advisory |

---
