package capture

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"example.com/packet-analyser/internal/metrics"
	"example.com/packet-analyser/internal/stats"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var protos = []string{"TCP", "UDP", "DNS", "ICMP", "HTTP"}

// Router/Network Device MAC Vendors
var routerVendors = map[string]string{
	"00:00:0c": "Cisco Router", "00:1b:0d": "Cisco Router", "00:1a:2b": "Cisco Router",
	"44:d9:e7": "Ubiquiti Router", "00:15:6d": "Ubiquiti Router",
	"b8:27:eb": "Raspberry Pi / Router", "dc:a6:32": "Raspberry Pi / Router",
	"00:0c:29": "VMware Virtual Router", "00:50:56": "VMware Virtual Router",
	"00:1e:8c": "ASUSTek Router", "00:22:6b": "ASUSTek Router",
	"00:18:39": "Cisco-Linksys Router", "00:25:9c": "Cisco-Linksys Router",
	"c0:a0:bb": "D-Link Router", "00:1e:58": "D-Link Router",
	"00:14:bf": "Netgear Router", "00:0f:b5": "Netgear Router",
	"00:1d:68": "MikroTik Router", "4c:5e:0c": "MikroTik Router",
}

func getRouterInfo(mac string) string {
	if len(mac) >= 8 {
		prefix := strings.ToLower(mac[:8])
		if vendor, ok := routerVendors[prefix]; ok {
			return fmt.Sprintf("%s (MAC: %s)", vendor, mac)
		}
	}
	return ""
}

// Capturer holds the live pcap handle so filters can be updated at runtime.
type Capturer struct {
	mu     sync.Mutex
	handle *pcap.Handle // nil when running in mock mode
	mock   bool
	filter string
}

// Start tries real capture; falls back to mock if no suitable interface.
func Start(store *stats.Store) *Capturer {
	c := &Capturer{}
	iface, err := defaultIface()
	if err != nil {
		log.Println("[capture] no interface found, using mock:", err)
		c.mock = true
		go c.runMock(store)
		return c
	}
	log.Println("[capture] starting on interface:", iface)
	go c.runReal(store, iface)
	return c
}

// SetFilter applies a BPF expression to the live handle.
func (c *Capturer) SetFilter(expr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mock {
		c.filter = expr
		log.Printf("[capture] mock mode — BPF filter stored: %q", expr)
		return nil
	}
	if c.handle == nil {
		return fmt.Errorf("capture handle not ready")
	}
	if err := c.handle.SetBPFFilter(expr); err != nil {
		return fmt.Errorf("invalid BPF expression: %w", err)
	}
	c.filter = expr
	log.Printf("[capture] BPF filter applied: %q", expr)
	return nil
}

// ActiveFilter returns the currently applied BPF expression.
func (c *Capturer) ActiveFilter() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.filter
}

func defaultIface() (string, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range ifaces {
		if len(d.Addresses) > 0 {
			return d.Name, nil
		}
	}
	return "", fmt.Errorf("no active interface")
}

func (c *Capturer) runReal(store *stats.Store, iface string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Println("[capture] OpenLive failed, falling back to mock:", err)
		c.mock = true
		c.runMock(store)
		return
	}

	// Track active real captures
	metrics.ActiveCaptures.Inc()
	defer metrics.ActiveCaptures.Dec()

	c.mu.Lock()
	c.handle = handle
	c.mu.Unlock()
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		// Increment Prometheus Counters for real packets
		metrics.PacketsCaptured.Inc()
		metrics.BytesCaptured.Add(float64(len(pkt.Data())))

		store.Add(parseAdvancedPacket(pkt))
	}

	// Record dropped packets when the capture loop exits
	if netStats, err := handle.Stats(); err == nil {
		metrics.PacketsDropped.Add(float64(netStats.PacketsDropped))
	}
}

// parseAdvancedPacket performs deep inspection for flagged packets
func parseAdvancedPacket(pkt gopacket.Packet) stats.Packet {
	p := stats.Packet{Proto: "TCP", Size: len(pkt.Data()), Time: time.Now()}

	// Basic IP Extraction
	if nl := pkt.NetworkLayer(); nl != nil {
		f, t := nl.NetworkFlow().Endpoints()
		p.SrcIP = f.String()
		p.DstIP = t.String()
	}

	// Basic Protocol Detection
	if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		p.Proto = "ICMP"
	}
	if pkt.Layer(layers.LayerTypeUDP) != nil {
		p.Proto = "UDP"
	}
	if pkt.Layer(layers.LayerTypeDNS) != nil {
		p.Proto = "DNS"
	}
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		if t.DstPort == 80 || t.SrcPort == 80 {
			p.Proto = "HTTP"
		}
	}

	// Simulate Flagging (In production, replace this with your anomaly detection logic)
	p.Flagged = rand.Float32() < 0.05

	// IF FLAGGED, PERFORM DEEP FORENSICS
	if p.Flagged {
		intel := &stats.ThreatIntel{}
		intel.CapturedIPs = fmt.Sprintf("%s -> %s", p.SrcIP, p.DstIP)

		// 1. Router Info (MAC OUI)
		if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			if info := getRouterInfo(eth.SrcMAC.String()); info != "" {
				intel.RouterInfo = fmt.Sprintf("Source: %s", info)
			} else if info := getRouterInfo(eth.DstMAC.String()); info != "" {
				intel.RouterInfo = fmt.Sprintf("Destination: %s", info)
			} else {
				intel.RouterInfo = "Standard Endpoint (Not a known router MAC)"
			}
		}

		// 2. Application Layer Inspection (Domain, Service Version, Severity)
		if appLayer := pkt.ApplicationLayer(); appLayer != nil {
			payload := string(appLayer.Payload())
			lowerPayload := strings.ToLower(payload)

			// Extract Domain (HTTP Host or DNS)
			if strings.HasPrefix(lowerPayload, "get ") || strings.HasPrefix(lowerPayload, "post ") {
				lines := strings.Split(payload, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						intel.Domain = strings.TrimSpace(line[5:])
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "server:") {
						intel.ServiceVersion = strings.TrimSpace(line[7:])
					}
				}
			} else if pkt.Layer(layers.LayerTypeDNS) != nil {
				dns := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)
				if len(dns.Questions) > 0 {
					intel.Domain = string(dns.Questions[0].Name)
				}
			} else if strings.HasPrefix(payload, "SSH-") {
				// SSH Banner Grabbing
				intel.ServiceVersion = strings.Split(payload, "\r\n")[0]
			}

			// 3. Calculate Severity & Reason
			intel.Severity, intel.Reason = calculateThreatSeverity(pkt, payload)
		} else {
			intel.Severity, intel.Reason = calculateThreatSeverity(pkt, "")
		}

		// Packet Info Summary
		var flags []string
		if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
			t := tcp.(*layers.TCP)
			if t.SYN {
				flags = append(flags, "SYN")
			}
			if t.ACK {
				flags = append(flags, "ACK")
			}
			if t.FIN {
				flags = append(flags, "FIN")
			}
			if t.RST {
				flags = append(flags, "RST")
			}
		}
		intel.PacketInfo = fmt.Sprintf("Proto: %s | Size: %d bytes | Flags: [%s]", p.Proto, p.Size, strings.Join(flags, ","))

		p.Intel = intel
	}

	return p
}

// calculateThreatSeverity is a basic rule engine for scoring packets
func calculateThreatSeverity(pkt gopacket.Packet, payload string) (string, string) {
	lowerPayload := strings.ToLower(payload)

	// CRITICAL: Known Attack Signatures
	if strings.Contains(lowerPayload, "union select") || strings.Contains(lowerPayload, "<script>") {
		return "Critical", "Potential SQL Injection or XSS Payload Detected"
	}

	// HIGH: Sensitive Ports & Cleartext Protocols
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		if t.DstPort == 23 { // Telnet
			return "High", "Cleartext Telnet Session Detected"
		}
		if t.DstPort == 21 { // FTP
			return "High", "Cleartext FTP Session Detected"
		}
		if t.DstPort == 445 || t.DstPort == 139 { // SMB
			return "High", "SMB/NetBIOS Traffic (Potential Lateral Movement)"
		}
	}

	// MEDIUM: Anomalous HTTP or DNS
	if strings.Contains(lowerPayload, "user-agent: sqlmap") || strings.Contains(lowerPayload, "user-agent: nikto") {
		return "High", "Malicious Scanner User-Agent Detected"
	}
	if strings.HasPrefix(lowerPayload, "get ") && len(payload) > 1000 {
		return "Medium", "Abnormally Large HTTP Request (Potential Buffer Overflow)"
	}

	// LOW: Default Flagged
	return "Low", "General Anomaly / Heuristic Trigger"
}

func (c *Capturer) runMock(store *stats.Store) {
	// Track active mock captures
	metrics.ActiveCaptures.Inc()
	defer metrics.ActiveCaptures.Dec()

	subnets := []string{"10.0.1", "192.168.0", "172.16.4", "10.0.2"}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	tick := time.NewTicker(150 * time.Millisecond)

	for range tick.C {
		for i := 0; i < r.Intn(4)+1; i++ {
			pktSize := r.Intn(1440) + 40

			// Increment Prometheus Counters for mock packets
			metrics.PacketsCaptured.Inc()
			metrics.BytesCaptured.Add(float64(pktSize))

			p := stats.Packet{
				SrcIP:   fmt.Sprintf("%s.%d", subnets[r.Intn(len(subnets))], r.Intn(253)+1),
				DstIP:   fmt.Sprintf("%s.%d", subnets[r.Intn(len(subnets))], r.Intn(253)+1),
				Proto:   protos[r.Intn(len(protos))],
				Size:    pktSize,
				Flagged: r.Float32() < 0.04,
				Time:    time.Now(),
			}

			if p.Flagged {
				p.Intel = &stats.ThreatIntel{
					CapturedIPs: p.SrcIP + " -> " + p.DstIP,
					RouterInfo:  "Mock Router (MAC: 00:00:0c:11:22:33)",
					Domain:      "mock-domain.local",
					PacketInfo:  "Proto: TCP | Size: 1200 bytes | Flags: [SYN,ACK]",
					Severity:    "Medium",
					Reason:      "Mock Anomaly Triggered",
				}
			}
			store.Add(p)
		}
	}
}

func init() { _ = net.IPv4(0, 0, 0, 0) }