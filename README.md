# Packet-Web-Analyzer
A web based packet analyzer that captures network traffic in transit.

# 🖥 Packet Analyzer

Real-time network packet analyzer dashboard built with **Go**, **HTMX**, and **Chart.js**.

![CI](https://github.com/12sub/packet-analyzer/actions/workflows/ci.yml/badge.svg)
![Docker](https://github.com/12sub/packet-analyzer/actions/workflows/docker.yml/badge.svg)

## Features
- Live packet feed via Server-Sent Events (SSE)
- Protocol breakdown (TCP, UDP, DNS, ICMP, HTTP)
- Rolling 30-second traffic chart
- Top source IP table
- BPF filter input — apply expressions like `tcp port 443` live

## Quick start

### Docker (recommended)
\`\`\`bash
docker compose up --build -d
# open http://localhost:8080
\`\`\`

### Pull from GHCR
\`\`\`bash
docker pull ghcr.io/12sub/packet-analyzer:main
\`\`\`

### Run locally (requires libpcap)
\`\`\`bash
# macOS
brew install libpcap

# Ubuntu/Debian
sudo apt install libpcap-dev

go run .
\`\`\`

> Raw capture requires elevated privileges.  
> On Linux: `sudo go run .`  
> On Windows: run `run-elevated.ps1` as Administrator (requires [Npcap](https://npcap.com))

## BPF filter examples

| Goal | Expression |
|---|---|
| HTTPS only | `tcp port 443` |
| DNS only | `udp port 53` |
| Specific host | `host 192.168.0.10` |
| Exclude host | `not host 10.0.1.1` |
| Large packets | `greater 1000` |

## License
MIT