package stats

import (
    "sync"
    "time"
)

type Packet struct {
    SrcIP    string    `json:"src_ip"`
    DstIP    string    `json:"dst_ip"`
    Proto    string    `json:"proto"`
    Size     int       `json:"size"`
    Flagged  bool      `json:"flagged"`
    Time     time.Time `json:"time"`
}

type IPEntry struct {
    IP    string `json:"ip"`
    Port  int    `json:"port"`
    Count int    `json:"count"`
}

type Store struct {
    mu          sync.RWMutex
    TotalPkts   int
    TotalBytes  int64
    Flagged     int
    ProtoCounts map[string]int
    IPCounts    map[string]*IPEntry
    TrafficSecs []int         // rolling 30s window
    curSecPkts  int
    Subscribers []chan Packet
}

func New() *Store {
    return &Store{
        ProtoCounts: map[string]int{"TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0, "HTTP": 0},
        IPCounts:    map[string]*IPEntry{},
        TrafficSecs: make([]int, 30),
    }
}

func (s *Store) Add(p Packet) {
    s.mu.Lock()
    s.TotalPkts++
    s.TotalBytes += int64(p.Size)
    if p.Flagged { s.Flagged++ }
    s.ProtoCounts[p.Proto]++
    s.curSecPkts++
    key := p.SrcIP
    if e, ok := s.IPCounts[key]; ok {
        e.Count++
    } else {
        s.IPCounts[key] = &IPEntry{IP: p.SrcIP, Count: 1}
    }
    subs := make([]chan Packet, len(s.Subscribers))
    copy(subs, s.Subscribers)
    s.mu.Unlock()

    for _, ch := range subs {
        select {
        case ch <- p:
        default:
        }
    }
}

func (s *Store) TickSecond() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.TrafficSecs = append(s.TrafficSecs[1:], s.curSecPkts)
    s.curSecPkts = 0
}

func (s *Store) Subscribe() chan Packet {
    ch := make(chan Packet, 64)
    s.mu.Lock()
    s.Subscribers = append(s.Subscribers, ch)
    s.mu.Unlock()
    return ch
}

func (s *Store) Unsubscribe(ch chan Packet) {
    s.mu.Lock()
    defer s.mu.Unlock()
    for i, c := range s.Subscribers {
        if c == ch {
            s.Subscribers = append(s.Subscribers[:i], s.Subscribers[i+1:]...)
            close(ch)
            return
        }
    }
}

type Snapshot struct {
    TotalPkts  int            `json:"total_pkts"`
    TotalBytes int64          `json:"total_bytes"`
    Flagged    int            `json:"flagged"`
    Conns      int            `json:"connections"`
    Protos     map[string]int `json:"protos"`
    Traffic    []int          `json:"traffic"`
    TopIPs     []IPEntry      `json:"top_ips"`
}

func (s *Store) Snapshot() Snapshot {
    s.mu.RLock()
    defer s.mu.RUnlock()

    protos := map[string]int{}
    for k, v := range s.ProtoCounts { protos[k] = v }

    traffic := make([]int, 30)
    copy(traffic, s.TrafficSecs)

    // top 6 IPs by count (simple selection sort)
    entries := make([]IPEntry, 0, len(s.IPCounts))
    for _, e := range s.IPCounts { entries = append(entries, *e) }
    for i := 0; i < len(entries) && i < 6; i++ {
        max := i
        for j := i + 1; j < len(entries); j++ {
            if entries[j].Count > entries[max].Count { max = j }
        }
        entries[i], entries[max] = entries[max], entries[i]
    }
    top := entries
    if len(top) > 6 { top = top[:6] }

    return Snapshot{
        TotalPkts:  s.TotalPkts,
        TotalBytes: s.TotalBytes,
        Flagged:    s.Flagged,
        Conns:      len(s.IPCounts),
        Protos:     protos,
        Traffic:    traffic,
        TopIPs:     top,
    }
}