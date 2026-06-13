# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.26-bookworm AS builder

WORKDIR /app

# Install libpcap headers needed to compile gopacket/pcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a statically-linked binary
COPY . .
RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /packet-analyser .


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /app

# Only the shared libpcap library is needed at runtime (no headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

# Copy binary and HTML templates
COPY --from=builder /packet-analyser .
COPY templates/ templates/

EXPOSE 8080

# Drop to a non-root user — capabilities are granted by compose, not by root
RUN useradd -r -s /bin/false appuser
USER appuser

ENTRYPOINT ["./packet-analyser"]