- DNS Lab with Docker Compose This lab provides a simple DNS server and DNS client running in a custom Docker network so you can practice DNS configuration and query analysis.

## Prerequisites

- Docker installed and running on your machine. - Docker Compose (v2 or compatible with `version: "3.8"`).
- Clone this repository and switch to the `dns_lab` directory:

```
git clone https://github.com/I-Sheng/security-code.git cd security-code/dns_lab
```

## Files

- `docker-compose.yaml`: Defines `dns-server` and `dns-client` services and the `dns-net` bridge network (subnet `172.30.0.0/24`).
- `Dockerfile.dns`: Build context for the DNS server container (runs `named`).
- `Dockerfile.client`: Build context for the DNS client container (interactive Bash environment with DNS tools).

## Network and Services

- Network: `dns-net` (bridge), subnet `172.30.0.0/24`.
- `dns-server`:
    - IP: `172.30.0.2` (on `dns-net`).
    - Ports exposed: `53/udp`, `53/tcp` mapped to host.
    - Command: `/usr/sbin/named -f -g`.
- `dns-client`:
    - IP: `172.30.0.3` (on `dns-net`).
    - DNS resolver: points to `172.30.0.2` (the `dns-server` container).
    - Starts with `/bin/bash` and has TTY enabled for interactive use.

## Build and Run

From the `dns_lab` directory:

```bash
# Build and start containers in the background
docker compose up -d --build
```

To see running containers:


`docker ps`

You should see `dns-server` and `dns-client` containers.

## Using the DNS Client

Attach to the client container:



`docker exec -it dns-client /bin/bash`

Inside the client, you can run DNS queries against the server:



`# Example using dig dig @172.30.0.2 example.com # Or, if /etc/resolv.conf is configured to use 172.30.0.2, simply: dig example.com nslookup example.com`

Adjust the domain names above to match the zones and records configured in your `named` configuration inside the server image.

## Testing from the Host

Because port 53 is exposed, you can also query the DNS server directly from the host:



`dig @127.0.0.1 example.com dig @127.0.0.1 example.com A dig @127.0.0.1 example.com NS`

Replace `example.com` with whatever zone you configured.

## Stopping and Cleaning Up

To stop the lab:
`docker compose down`

To remove containers and rebuild from scratch (if needed):
`docker compose down --rmi local --volumes docker compose up -d --build`
