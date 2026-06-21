# Server Setup Guide

This guide covers deploying the Packet Web Analyzer with Tailscale Funnel for secure public access.

---

## Prerequisites

- A Linux server or VM (Ubuntu/Debian recommended)
- Docker and Docker Compose installed
- Tailscale account (free tier works)

---

## Step 1: Install Tailscale

```bash
# Ubuntu/Debian
curl -fsSL https://tailscale.com/install.sh | sh

# macOS
brew install tailscale
```

Authenticate:
```bash
sudo tailscale up
```

Follow the link to sign in via your browser.

---

## Step 2: Clone the Project

```bash
git clone https://github.com/12sub/Packet-Web-Analyzer.git
cd Packet-Web-Analyzer
```

---

## Step 3: Configure Environment

Create a `.env` file in the project root:

```bash
# Required: generate a secure random secret
JWT_SECRET=$(openssl rand -hex 32)
echo "JWT_SECRET=$JWT_SECRET" > .env
```

Optional variables:
```bash
# Pin to a specific network interface
IFACE=eth0

# Use mock geolocation data (no MaxMind DB needed)
MOCK_GEO=true

# Logging verbosity: debug, info, warn, error
LOG_LEVEL=info
```

---

## Step 4: Start the Application

```bash
docker compose up -d
```

Verify the container is healthy:
```bash
docker ps
```

Check logs if needed:
```bash
docker logs packet-analyser
```

Test locally:
```bash
curl http://localhost:8080/login
```

---

## Step 5: Expose via Tailscale Funnel

```bash
tailscale funnel 8080
```

Your public URL will be:
```
https://<machine-name>.<tailnet>.ts.net
```

Test from another device:
```bash
curl https://<machine-name>.<tailnet>.ts.net/login
```

---

## Step 6: Run Funnel Persistently

For production, run funnel as a background service.

### Option A: systemd Service

Create `/etc/systemd/system/tailscale-funnel.service`:

```ini
[Unit]
Description=Tailscale Funnel for Packet Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/tailscale funnel 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable tailscale-funnel
sudo systemctl start tailscale-funnel
```

### Option B: Docker Compose Integration

Add a `restart: unless-stopped` policy to your compose service and run funnel via a separate container or host-level service.

---

## Step 7: Verify & Monitor

| Check | Command |
|-------|---------|
| Container status | `docker ps` |
| Application logs | `docker logs -f packet-analyser` |
| Tailscale status | `tailscale status` |
| Funnel status | `tailscale funnel status` |
| Local health | `curl http://localhost:8080/login` |
| Public health | `curl https://<your-domain>/login` |

---

## Updating

Pull latest changes and rebuild:
```bash
git pull
docker compose up -d --build
```

---

## Troubleshooting

### 502 Bad Gateway

1. Ensure the container is running: `docker ps`
2. Check the app is listening on all interfaces (not just 127.0.0.1)
3. Verify `JWT_SECRET` is set in `.env`
4. Confirm Tailscale is connected: `tailscale status`

### Connection Refused

- The application may not be fully started yet. Wait 10-15 seconds and retry.
- Check `docker logs packet-analyser` for startup errors.

### Certificate Warnings

Tailscale handles HTTPS automatically. If you see cert errors, ensure you're accessing the `.ts.net` URL, not an IP address.

---

## Security Notes

- Keep your `JWT_SECRET` private. Never commit it to version control.
- The container runs with minimal capabilities (`NET_RAW`, `NET_ADMIN` only) and drops all others.
- The filesystem is read-only except for `/tmp`.
- Tailscale Funnel encrypts all traffic end-to-end.
- No port forwarding or firewall rules are required on the host.
