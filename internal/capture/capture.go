package capture

import (
    "fmt"
    "log"
    "math/rand"
    "net"
    "sync"
    "time"

    "example.com/packet-analyser/internal/stats"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var protos = []string{"TCP", "UDP", "DNS", "ICMP", "HTTP"}

// Capturer holds the live pcap handle so filters can be updated at runtime.
type Capturer struct {
    mu     sync.Mutex
    handle *pcap.Handle  // nil when running in mock mode
    mock   bool
    filter string
}

// Start tries real capture; falls back to mock if no suitable interface.
// Returns a *Capturer so the caller can call SetFilter later.
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
// Pass an empty string to clear the filter.
// Returns an error if the expression is invalid.
func (c *Capturer) SetFilter(expr string) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.mock {
        // In mock mode we just store the filter for display purposes;
        // real BPF validation isn't possible without a handle.
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
    if err != nil { return "", err }
    for _, d := range ifaces {
        if len(d.Addresses) > 0 { return d.Name, nil }
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
    c.mu.Lock()
    c.handle = handle
    c.mu.Unlock()
    defer handle.Close()

    src := gopacket.NewPacketSource(handle, handle.LinkType())
    for pkt := range src.Packets() {
        store.Add(parsePacket(pkt))
    }
}

func parsePacket(pkt gopacket.Packet) stats.Packet {
    p := stats.Packet{Proto: "TCP", Size: len(pkt.Data()), Time: time.Now()}
    if nl := pkt.NetworkLayer(); nl != nil {
        f, t := nl.NetworkFlow().Endpoints()
        p.SrcIP = f.String()
        p.DstIP = t.String()
    }
    if pkt.Layer(layers.LayerTypeICMPv4) != nil { p.Proto = "ICMP" }
    if pkt.Layer(layers.LayerTypeUDP) != nil    { p.Proto = "UDP" }
    if pkt.Layer(layers.LayerTypeDNS) != nil    { p.Proto = "DNS" }
    if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
        t := tcp.(*layers.TCP)
        if t.DstPort == 80 || t.SrcPort == 80 { p.Proto = "HTTP" }
    }
    p.Flagged = rand.Float32() < 0.03
    return p
}

func (c *Capturer) runMock(store *stats.Store) {
    subnets := []string{"10.0.1", "192.168.0", "172.16.4", "10.0.2"}
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    tick := time.NewTicker(150 * time.Millisecond)
    for range tick.C {
        for i := 0; i < r.Intn(4)+1; i++ {
            store.Add(stats.Packet{
                SrcIP:   fmt.Sprintf("%s.%d", subnets[r.Intn(len(subnets))], r.Intn(253)+1),
                DstIP:   fmt.Sprintf("%s.%d", subnets[r.Intn(len(subnets))], r.Intn(253)+1),
                Proto:   protos[r.Intn(len(protos))],
                Size:    r.Intn(1440) + 40,
                Flagged: r.Float32() < 0.04,
                Time:    time.Now(),
            })
        }
    }
}

func init() { _ = net.IPv4(0, 0, 0, 0) }