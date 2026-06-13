package handlers

import (
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "sort"
    "strings"
    "time"

    "example.com/packet-analyser/internal/capture"
    "example.com/packet-analyser/internal/stats"
    "example.com/packet-analyser/internal/geo"
)

type Handler struct {
    store     *stats.Store
    capturer  *capture.Capturer
    tmpl      *template.Template
    geo      *geo.Lookup
}

func New(store *stats.Store, c *capture.Capturer, g *geo.Lookup) *Handler {
    tmpl := template.Must(template.ParseFiles("templates/index.html"))
    return &Handler{store: store, capturer: c, geo: g, tmpl: tmpl}
}

func (h *Handler) Register(mux *http.ServeMux) {
    mux.HandleFunc("GET /", h.index)
    mux.HandleFunc("GET /sse/packets", h.ssePackets)
    mux.HandleFunc("GET /api/stats", h.apiStats)
    mux.HandleFunc("GET /api/topips", h.apiTopIPs)
    mux.HandleFunc("POST /capture/filter", h.setFilter)
    mux.HandleFunc("GET /api/connections", h.apiConnections)
    mux.HandleFunc("GET /api/geoips",      h.apiGeoIPs)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
    data := map[string]string{"ActiveFilter": h.capturer.ActiveFilter()}
    h.tmpl.Execute(w, data)
}

// setFilter accepts a BPF expression and applies it to the live capture handle.
// Responds with an HTMX-friendly HTML fragment: a success badge or an error message.
func (h *Handler) setFilter(w http.ResponseWriter, r *http.Request) {
    expr := strings.TrimSpace(r.FormValue("filter"))

    if err := h.capturer.SetFilter(expr); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        fmt.Fprintf(w,
            `<span id="filter-status" class="filter-err">✗ %s</span>`,
            template.HTMLEscapeString(err.Error()),
        )
        return
    }

    label := "filter cleared"
    if expr != "" { label = fmt.Sprintf("filter applied: %s", expr) }
    fmt.Fprintf(w,
        `<span id="filter-status" class="filter-ok">✓ %s</span>`,
        template.HTMLEscapeString(label),
    )
}

// ssePackets streams each packet as an HTMX-compatible SSE event.
// ssePackets streams each packet as an HTMX-compatible SSE event.
func (h *Handler) ssePackets(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok { 
		http.Error(w, "SSE not supported", 500)
		return 
	}
	
	// FIX 1: Removed trailing spaces in header keys and values
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.store.Subscribe()
	defer h.store.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case pkt, ok := <-ch:
			if !ok { 
				return 
			}
			
			flagClass := ""
			if pkt.Flagged { 
				flagClass = " flagged" 
			}
			
			// FIX 2: Cleaned up the HTML string (removed random spaces inside tags)
			html := fmt.Sprintf(
				`<tr class="pkt-row%s"><td>%s</td><td>%s</td>`+
				`<td><span class="ptag%s">%s</span></td>`+
				`<td>%dB</td><td>%s</td></tr>`,
				flagClass,
				pkt.SrcIP, pkt.DstIP,
				" "+pkt.Proto, pkt.Proto, // Adds a space before the protocol for the CSS class
				pkt.Size,
				pkt.Time.Format("15:04:05.000"), // FIX 3: Removed trailing space in time format
			)
			
			// FIX 4: Removed the trailing space after \n\n. 
			// SSE strictly requires exactly \n\n to separate events.
			fmt.Fprintf(w, "event: packet\ndata: %s\n\n", html)
			flusher.Flush()
		}
	}
}
// apiStats returns a JSON snapshot for cards + charts.
func (h *Handler) apiStats(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    snap := h.store.Snapshot()
    json.NewEncoder(w).Encode(snap)
}

// apiTopIPs returns top source IPs sorted by packet count.
func (h *Handler) apiTopIPs(w http.ResponseWriter, r *http.Request) {
    snap := h.store.Snapshot()
    sort.Slice(snap.TopIPs, func(i, j int) bool {
        return snap.TopIPs[i].Count > snap.TopIPs[j].Count
    })
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(snap.TopIPs)
}

// SecondTicker drives the rolling traffic window.
func SecondTicker(store *stats.Store) {
    t := time.NewTicker(time.Second)
    for range t.C { store.TickSecond() }
}

func Log(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s", r.Method, r.URL.Path)
        next.ServeHTTP(w, r)
    })
}

// apiConnections returns a D3-ready {nodes, links} graph of top connections.
func (h *Handler) apiConnections(w http.ResponseWriter, r *http.Request) {
    snap := h.store.Snapshot()

    type Node struct {
        ID      string `json:"id"`
        Packets int    `json:"packets"`
    }
    type Link struct {
        Source string `json:"source"`
        Target string `json:"target"`
        Count  int    `json:"count"`
    }
    type Graph struct {
        Nodes []Node `json:"nodes"`
        Links []Link `json:"links"`
    }

    nodeMap := map[string]int{}
    links   := make([]Link, 0, len(snap.TopConns))

    for _, c := range snap.TopConns {
        nodeMap[c.Src] += c.Count
        nodeMap[c.Dst] += c.Count
        links = append(links, Link{Source: c.Src, Target: c.Dst, Count: c.Count})
    }

    nodes := make([]Node, 0, len(nodeMap))
    for id, pkts := range nodeMap {
        nodes = append(nodes, Node{ID: id, Packets: pkts})
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(Graph{Nodes: nodes, Links: links})
}

// apiGeoIPs resolves top source IPs to geographic locations.
func (h *Handler) apiGeoIPs(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if h.geo == nil {
        json.NewEncoder(w).Encode([]struct{}{})
        return
    }
    snap := h.store.Snapshot()

    // aggregate packet count per unique source IP
    ipCount := map[string]int{}
    for _, c := range snap.TopConns {
        ipCount[c.Src] += c.Count
    }

    locs := make([]geo.Location, 0)
    for ip, count := range ipCount {
        loc, err := h.geo.Locate(ip, count)
        if err != nil { continue }
        locs = append(locs, *loc)
    }

    json.NewEncoder(w).Encode(locs)
}