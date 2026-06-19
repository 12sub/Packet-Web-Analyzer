# 🖥 Packet Web Analyzer

A real-time, web-based network packet analyzer that captures traffic in transit and visualizes it through an interactive dashboard. Built with **Go**, **HTMX**, and **Chart.js**.

![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)

---

## ✨ Features

- **Live Packet Feed** — Real-time packet capture streamed via Server-Sent Events (SSE)
- **Protocol Breakdown** — Visualize traffic by protocol: TCP, UDP, DNS, ICMP, HTTP
- **Rolling Traffic Chart** — 30-second rolling window of network activity
- **Top Source IPs** — Table view of the busiest source addresses
- **BPF Filters** — Apply live Berkeley Packet Filter expressions (e.g., `tcp port 443`)
- **GeoIP Support** — Optional MaxMind GeoLite2 integration for geolocation
- **JWT Authentication** — Secure login with token-based auth
- **Export Capabilities** — Save captured data for offline analysis

---

## 🏗 Architecture

```
┌─────────────┐     SSE      ┌─────────────────┐
│   Browser   │◄─────────────│  Go Backend     │
│  (HTMX +    │              │  • gopacket     │
│   Chart.js) │              │  • libpcap      │
└─────────────┘              │  • SQLite       │
                             └─────────────────┘
```

| Component | Technology |
|-----------|------------|
| Backend | Go 1.26 |
| Packet Capture | `gopacket` / `libpcap` |
| Frontend | HTMX, Chart.js |
| Database | SQLite (modernc) |
| Auth | JWT (`golang-jwt/jwt/v5`) |
| GeoIP | MaxMind GeoIP2 (optional) |

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/12sub/Packet-Web-Analyzer.git
cd Packet-Web-Analyzer

# 2. Set your JWT secret
export JWT_SECRET="your-secret-key-here"

# 3. Build and run
docker compose up --build -d

# 4. Open the dashboard
open http://localhost:8080
```

> **Note:** The container runs with `network_mode: host` and adds only `NET_RAW` and `NET_ADMIN` capabilities — no `privileged: true` required.

### Pull from GHCR

```bash
docker pull ghcr.io/12sub/packet-analyzer:main
```

### Run Locally (Requires libpcap)

**macOS**
```bash
brew install libpcap
```

**Ubuntu/Debian**
```bash
sudo apt install libpcap-dev
```

**Run**
```bash
# Raw capture requires elevated privileges
sudo go run .
```

**Windows** (run as Administrator with Npcap installed):
```powershell
.\run-elevated.ps1
```

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `IFACE` | *(auto)* | Network interface to capture on |
| `LOG_LEVEL` | `info` | Logging verbosity |
| `MOCK_GEO` | `false` | Use mock geolocation data |
| `JWT_SECRET` | *(required)* | Secret key for JWT signing |

Create a `.env` file or pass variables directly to Docker Compose.

---

## 📊 BPF Filter Examples

Apply filters directly in the web UI to focus on specific traffic:

| Goal | Expression |
|------|------------|
| HTTPS only | `tcp port 443` |
| DNS only | `udp port 53` |
| Specific host | `host 192.168.0.10` |
| Exclude host | `not host 10.0.1.1` |
| Large packets | `greater 1000` |

---

## 🔒 Security

- **Capability-based access** — Only `NET_RAW` and `NET_ADMIN` are granted; all other capabilities are dropped
- **Read-only filesystem** — Container runs with `read_only: true`
- **Non-root user** — Binary drops to an unprivileged user at runtime
- **JWT authentication** — All endpoints protected by token-based auth
- **No privileged mode** — Designed to run without `--privileged`

---

## 📁 Project Structure

```
Packet-Web-Analyzer/
├── main.go              # Application entry point
├── go.mod / go.sum      # Go module definitions
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Production-ready compose
├── run-elevated.ps1     # Windows elevated runner
├── templates/           # HTML templates (HTMX + Chart.js)
└── exports/             # Data export directory (volume)
```

---

## 🛠 Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build binary
go build -o packet-analyser .
```

---

## 📦 Dependencies

- [gopacket](https://github.com/google/gopacket) — Packet decoding and capture
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) — JWT authentication
- [geoip2-golang](https://github.com/oschwald/geoip2-golang) — GeoIP lookups
- [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) — Pure Go SQLite driver
- [HTMX](https://htmx.org/) — Frontend interactivity
- [Chart.js](https://www.chartjs.org/) — Data visualization

---

## 📝 License

[MIT](LICENSE) © 12sub
