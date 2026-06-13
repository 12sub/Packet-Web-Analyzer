package stats

import (
	"sort"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type Packet struct {
	SrcIP   string    `json:"src_ip"`
	DstIP   string    `json:"dst_ip"`
	Proto   string    `json:"proto"`
	Size    int       `json:"size"`
	Flagged bool      `json:"flagged"`
	Time    time.Time `json:"time"`
}

type IPEntry struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Count int    `json:"count"`
}

type ConnEntry struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Count int    `json:"count"`
}

type Snapshot struct {
	TotalPkts    int            `json:"total_pkts"`
	TotalBytes   int64          `json:"total_bytes"`
	Flagged      int            `json:"flagged"`
	Connections  int            `json:"connections"`
	Protos       map[string]int `json:"protos"`
	Traffic      []int          `json:"traffic"`
	TopIPs       []IPEntry      `json:"top_ips"`
	Bandwidth    []int64        `json:"bandwidth"`
	CurBandwidth int64          `json:"cur_bandwidth"`
	TopConns     []ConnEntry    `json:"top_conns"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────────────────────

type Store struct {
	mu sync.RWMutex

	// totals
	totalPkts  int
	totalBytes int64
	flagged    int

	// per-protocol counts
	protoCounts map[string]int

	// per-IP counts (keyed by src IP)
	ipCounts map[string]*IPEntry

	// src|dst connection counts
	connections map[string]*ConnEntry

	// rolling 30-second windows
	trafficSecs   []int   // packets per second
	bandwidthSecs []int64 // bytes per second

	// current-second accumulators (reset each tick)
	curSecPkts  int
	curSecBytes int64

	// SSE subscribers
	subscribers []chan Packet
}

func New() *Store {
	return &Store{
		protoCounts:   map[string]int{"TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0, "HTTP": 0},
		ipCounts:      map[string]*IPEntry{},
		connections:   map[string]*ConnEntry{},
		trafficSecs:   make([]int, 30),
		bandwidthSecs: make([]int64, 30),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Write path
// ─────────────────────────────────────────────────────────────────────────────

func (s *Store) Add(p Packet) {
	s.mu.Lock()

	s.totalPkts++
	s.totalBytes += int64(p.Size)
	s.curSecPkts++
	s.curSecBytes += int64(p.Size)

	if p.Flagged {
		s.flagged++
	}

	// protocol counts
	s.protoCounts[p.Proto]++

	// top source IPs
	if e, ok := s.ipCounts[p.SrcIP]; ok {
		e.Count++
	} else {
		s.ipCounts[p.SrcIP] = &IPEntry{IP: p.SrcIP, Count: 1}
	}

	// connection pairs
	ck := p.SrcIP + "|" + p.DstIP
	if c, ok := s.connections[ck]; ok {
		c.Count++
	} else {
		s.connections[ck] = &ConnEntry{Src: p.SrcIP, Dst: p.DstIP, Count: 1}
	}

	// snapshot subscribers before unlocking
	subs := make([]chan Packet, len(s.subscribers))
	copy(subs, s.subscribers)
	s.mu.Unlock()

	// fan-out to SSE subscribers (non-blocking)
	for _, ch := range subs {
		select {
		case ch <- p:
		default:
		}
	}
}

// TickSecond advances both rolling windows by one second.
// Call this from a time.Ticker goroutine every second.
func (s *Store) TickSecond() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// shift windows left, append current-second value
	s.trafficSecs   = append(s.trafficSecs[1:],   s.curSecPkts)
	s.bandwidthSecs = append(s.bandwidthSecs[1:],  s.curSecBytes)

	// reset accumulators
	s.curSecPkts  = 0
	s.curSecBytes = 0
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE pub/sub
// ─────────────────────────────────────────────────────────────────────────────

func (s *Store) Subscribe() chan Packet {
	ch := make(chan Packet, 64)
	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.subscribers {
		if c == ch {
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Read path — Snapshot
// ─────────────────────────────────────────────────────────────────────────────

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// --- protocol counts (deep copy) ---
	protos := make(map[string]int, len(s.protoCounts))
	for k, v := range s.protoCounts {
		protos[k] = v
	}

	// --- rolling traffic window (deep copy) ---
	traffic := make([]int, len(s.trafficSecs))
	copy(traffic, s.trafficSecs)

	// --- rolling bandwidth window (deep copy) ---
	bandwidth := make([]int64, len(s.bandwidthSecs))
	copy(bandwidth, s.bandwidthSecs)

	// current bandwidth is the last completed second
	curBW := s.bandwidthSecs[len(s.bandwidthSecs)-1]

	// --- top source IPs (sorted, top 6) ---
	ips := make([]IPEntry, 0, len(s.ipCounts))
	for _, e := range s.ipCounts {
		ips = append(ips, *e)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Count > ips[j].Count })
	if len(ips) > 6 {
		ips = ips[:6]
	}

	// --- top connections (sorted, top 25) ---
	conns := make([]ConnEntry, 0, len(s.connections))
	for _, c := range s.connections {
		conns = append(conns, *c)
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].Count > conns[j].Count })
	if len(conns) > 25 {
		conns = conns[:25]
	}

	return Snapshot{
		TotalPkts:    s.totalPkts,
		TotalBytes:   s.totalBytes,
		Flagged:      s.flagged,
		Connections:  len(s.connections),
		Protos:       protos,
		Traffic:      traffic,
		TopIPs:       ips,
		Bandwidth:    bandwidth,
		CurBandwidth: curBW,
		TopConns:     conns,
	}
}