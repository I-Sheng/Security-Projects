# DNS Lab

A Dockerized DNS lab with a BIND server and an interactive client on an isolated bridge network. Use it to explore DNS resolution, traffic analysis, DNSSEC validation, and security concepts.

> **Source:** Lab 4 — DNS Security Lab: Attacks and Defenses

## Learning Objectives

- Describe the DNS resolution process and identify security-critical steps.
- Observe how DNS traffic can be intercepted or spoofed.
- Explain DNS cache poisoning at a conceptual and practical level.
- Evaluate the role of DNSSEC in securing DNS responses.
- Identify best practices for secure DNS configuration.

## Prerequisites

- Docker and Docker Compose (v2 / `version: "3.8"` compatible)

```bash
git clone https://github.com/I-Sheng/security-code.git
cd security-code/dns_lab
```

## Files

| File | Description |
|---|---|
| `docker-compose.yaml` | Defines `dns-server` and `dns-client` services and the `dns-net` bridge (`172.30.0.0/24`) |
| `Dockerfile.dns` | DNS server image — runs BIND (`named`) |
| `Dockerfile.client` | DNS client image — interactive Bash shell with `dig`, `tcpdump`, etc. |

## Network and Services

| Container | IP | Role |
|---|---|---|
| `dns-server` | `172.30.0.2` | BIND resolver; ports `53/udp` and `53/tcp` exposed to host |
| `dns-client` | `172.30.0.3` | Interactive client; resolver configured to `172.30.0.2` |

## Build and Run

```bash
# Build and start in the background
docker compose up -d --build

# Verify containers are running
docker ps

# Open a shell on the client
docker exec -it dns-client /bin/bash

# Stop and clean up
docker compose down

# Full reset (remove images and volumes, then rebuild)
docker compose down --rmi local --volumes && docker compose up -d --build
```

---

## Part 1 — DNS Resolution Basics

### Task 1.1 — Exploring DNS Queries

Run `dig` with the `+trace` flag to follow the full resolution path for a domain:

```bash
dig example.com
dig example.com +trace
```

Answer the following:

1. Which DNS servers are contacted during resolution?
2. What information is returned in a DNS response?
3. At which points could an attacker interfere with the process?

*Observations:*
- The `+trace` flag reveals the full chain: local resolver (`172.30.0.2`) → root servers (e.g., `c.root-servers.net`) → TLD servers (e.g., `l.gtld-servers.net`) → authoritative nameserver.
- Each DNS response contains resource records with: the queried name, record type (A, NS, etc.), class, TTL, and the resolved value (IP address or nameserver name).
- An attacker can interfere at any hop in the chain since DNS uses UDP without authentication — spoofing and cache poisoning are possible at every level.

---

## Part 2 — Observing DNS Traffic and Spoofing Risk

### Task 2.1 — Capturing DNS Traffic

Start a packet capture, then issue a DNS query from another terminal:

```bash
tcpdump -i eth0 udp port 53
# In another terminal:
dig example.com
```

You can also query directly from the host (port 53 is exposed):

```bash
dig @127.0.0.1 example.com
```

Answer the following:

1. Is DNS using TCP or UDP by default?
2. What fields appear in a DNS query and response?
3. Why might DNS traffic be vulnerable to spoofing?

*Observations:*
- DNS uses **UDP** by default (confirmed by the `udp` flag in captured packets).
- A DNS packet contains: a HEADER (opcode, status, ID, flags, record counts), an OPT PSEUDOSECTION (EDNS, cookie), a QUESTION SECTION, and an ANSWER SECTION (name, type, IP).
- The resolver responds to any source IP without verifying the requester's identity, making it susceptible to spoofing. An attacker who observes the query ID and source port can race a forged reply back before the legitimate answer arrives.

---

## Part 3 — DNS Cache Poisoning (Controlled Simulation)

### Task 3.1 — Query the Local DNS Server

Query a non-existent domain to observe resolver behavior:

```bash
dig @172.30.0.2 nonexistent.local
dig www.example-bank.com @localhost
```

Answer the following:

1. Is the response what you would expect?
2. Why is recursive DNS resolution risky if misconfigured?
3. What security assumptions does cache poisoning break?

*Observations:*
- A query for a non-existent domain returns `status: NXDOMAIN` — the domain does not exist.
- An open or weakly protected recursive resolver can be abused as a pivot for cache poisoning, a DDoS amplifier (DNS reflection), and a channel for leaking internal hostnames.
- Cache poisoning breaks the implicit trust that a recursive resolver's cache accurately reflects the DNS hierarchy — poisoned records cause all users of that resolver to be silently misdirected.

---

## Part 4 — DNSSEC as a Defense

### Task 4.1 — Testing DNSSEC Validation

Query a DNSSEC-signed domain and observe the `ad` (Authenticated Data) flag:

```bash
dig @172.30.0.2 +dnssec sigok.verteiltesysteme.net
dig dnssec-failed.org
dig cloudflare.com +dnssec
```

Answer the following:

1. What happens when DNSSEC validation fails?
2. How does DNSSEC change the trust model of DNS?
3. What types of attacks does DNSSEC prevent?

*Observations:*
- When DNSSEC validation fails, a validating resolver returns `status: SERVFAIL` instead of the A record — the query effectively fails rather than returning a forged answer.
- DNSSEC adds cryptographic authentication on top of the hierarchical DNS protocol. Each record set is signed with an RRSIG record, and the resolver verifies the signature chain up to the trust anchor at the root.
- DNSSEC prevents DNS response forgery and cache poisoning — an attacker cannot inject fake records because they cannot forge the cryptographic signatures without the zone's private key.

---

## Reflection Questions

**Why is DNS an attractive target for attackers?**  
DNS uses UDP (connectionless, no handshake) and carries no authentication by default. It is used by virtually every internet connection. Compromising DNS can silently redirect users to malicious infrastructure at scale, affecting everyone who trusts the poisoned resolver.

**Why is DNS security often overlooked in system design?**  
DNS is treated as basic infrastructure that "just works." Designers focus on securing application layers while delegating DNS to default ISP or cloud resolvers, overlooking misconfiguration risks like open recursion, missing DNSSEC, and insufficient logging.

**Would you recommend running an in-house DNS server for an enterprise?**  
Generally no — unless the team has strong networking and security expertise to handle patching, monitoring, and hardening (DNSSEC, query logging, rate limiting). The attack surface and operational overhead usually outweigh the benefits over using a well-managed external or dedicated DNS provider.

---
