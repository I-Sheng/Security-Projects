# DNS Lab

A Dockerized DNS lab with a BIND server and an interactive client on an isolated bridge network. Use it to explore DNS resolution, traffic analysis, DNSSEC validation, and security concepts.

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
```

## Using the DNS Client

```bash
docker exec -it dns-client /bin/bash

# Inside the client:
dig @172.30.0.2 example.com
dig @172.30.0.2 example.com A
dig @172.30.0.2 example.com NS
```

## Testing from the Host

Because port 53 is exposed, you can query the server directly from your machine:

```bash
dig @127.0.0.1 example.com
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com NS
```

## Stopping and Cleaning Up

```bash
# Stop containers
docker compose down

# Full reset (remove images and volumes, then rebuild)
docker compose down --rmi local --volumes && docker compose up -d --build
```

---

## Lab Experiments

The `experiment/` folder contains screenshots and notes from the hands-on tasks below.

### Task 1.1 — Exploring DNS Queries

Run `dig` with the `+trace` flag to follow the full resolution path for a domain:

```bash
dig +trace example.com
```

**Observed resolution chain:** local resolver (`172.30.0.2`) → root servers (e.g., `c.root-servers.net`) → TLD servers (e.g., `l.gtld-servers.net`) → authoritative nameserver.

Key questions answered:
- **What is returned?** Resource records containing: queried name, type (A, NS, etc.), class, TTL, and the resolved value (IP address or nameserver name).
- **Where can an attacker interfere?** DNS uses UDP without authentication, so any hop in the chain can be targeted for spoofing or cache poisoning.

---

### Task 2.1 — Capturing DNS Traffic

Capture DNS traffic with `tcpdump` or Wireshark while running `dig`:

```bash
tcpdump -i eth0 udp port 53
```

**Key findings:**
- DNS uses **UDP** by default (confirmed by the `udp` flag in captured packets).
- DNS packets contain: a HEADER (opcode, status, ID, flags, record counts), an OPT PSEUDOSECTION (EDNS, cookie), a QUESTION SECTION, and an ANSWER SECTION (name, type, IP).
- **Vulnerability:** The resolver responds to any source IP without verifying whether the requester is who it claims to be, making it susceptible to spoofing.

---

### Task 3.1 — Querying the Local DNS Server

Query a non-existent domain to observe resolver behavior:

```bash
dig @172.30.0.2 nonexistent.local
```

**Expected result:** `status: NXDOMAIN` — the domain does not exist.

**Why recursive resolution is risky when misconfigured:** An open or weakly protected recursive resolver can be abused as a pivot for cache poisoning, a DDoS amplifier (DNS reflection), and a channel for leaking internal hostnames.

**What cache poisoning breaks:** The implicit trust that a recursive resolver's cache accurately reflects the DNS hierarchy.

---

### Task 4.1 — Testing DNSSEC Validation

Query a DNSSEC-signed domain and observe the `ad` (Authenticated Data) flag:

```bash
dig @172.30.0.2 +dnssec sigok.verteiltesysteme.net
```

**What happens on validation failure:** A validating resolver returns `status: SERVFAIL` instead of the A record.

**How DNSSEC changes the trust model:** Each DNS record is signed with an RRSIG record. The resolver verifies the signature chain up to the root, adding cryptographic authentication on top of the hierarchical DNS protocol.

**Attacks DNSSEC prevents:** DNS response forgery and cache poisoning — an attacker cannot inject fake records because they cannot forge the cryptographic signatures.

---

## Reflection Questions

**Why is DNS an attractive target?**  
DNS uses UDP (connectionless, no handshake), carries no authentication by default, and is used by virtually every internet connection. Compromising it can silently redirect users to malicious infrastructure at scale.

**Why is DNS security often overlooked?**  
DNS is treated as basic infrastructure that "just works." Designers focus on securing application layers while delegating DNS to default ISP or cloud resolvers, overlooking misconfiguration risks like open recursion, missing DNSSEC, and insufficient logging.

**Would you recommend running an in-house DNS server for an enterprise?**  
Generally no — unless the team has strong networking and security expertise to handle patching, monitoring, and hardening (DNSSEC, query logging, rate limiting). The attack surface and operational overhead usually outweigh the benefits over using a well-managed external or dedicated DNS provider.

---

## Original Assignment

> Source: *Lab 4 — DNS Security Lab: Attacks and Defenses*

### Learning Objectives

- Describe the DNS resolution process and identify security-critical steps.
- Observe how DNS traffic can be intercepted or spoofed.
- Explain DNS cache poisoning at a conceptual and practical level.
- Evaluate the role of DNSSEC in securing DNS responses.
- Identify best practices for secure DNS configuration.

### Lab Environment

Two VMs on the same Host-only network (Kali as client, Ubuntu as DNS server running BIND9), or the provided Docker setup with `dns-server` at `172.30.0.2` and `dns-client` at `172.30.0.3`.

---

### Part 1 — DNS Resolution Basics

#### Task 1.1: Exploring DNS Queries

```bash
dig example.com
dig example.com +trace
```

Answer the following:

1. Which DNS servers are contacted during resolution?
2. What information is returned in a DNS response?
3. At which points could an attacker interfere with the process?

---

### Part 2 — Observing DNS Traffic and Spoofing Risk

#### Task 2.1: Capturing DNS Traffic

Start a packet capture, then issue a DNS query:

```bash
sudo tcpdump -n port 53
# In another terminal:
dig example.com
```

Answer the following:

1. Is DNS using TCP or UDP by default?
2. What fields appear in a DNS query and response?
3. Why might DNS traffic be vulnerable to spoofing?

---

### Part 3 — DNS Cache Poisoning (Controlled Simulation)

#### Task 3.1: Query the Local DNS Server

```bash
dig www.example-bank.com @localhost
```

Answer the following:

1. Is the response what you would expect?
2. Why is recursive DNS resolution risky if misconfigured?
3. What security assumptions does cache poisoning break?

---

### Part 4 — DNSSEC as a Defense

#### Task 4.1: Testing DNSSEC Validation

```bash
dig dnssec-failed.org
dig cloudflare.com +dnssec
```

Answer the following:

1. What happens when DNSSEC validation fails?
2. How does DNSSEC change the trust model of DNS?
3. What types of attacks does DNSSEC prevent?

---

### Reflection Questions

1. Why is DNS an attractive target for attackers?
2. Why is DNS security often overlooked in system design?
3. Would you recommend running an in-house DNS server for an enterprise? Why or why not?

### Deliverables

- Short lab report answering all questions above.
- Screenshots or command output demonstrating each experiment.
