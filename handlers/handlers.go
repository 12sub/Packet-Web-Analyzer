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
)

type Handler struct {
    store     *stats.Store
    capturer  *capture.Capturer
    tmpl      *template.Template
}

func New(store *stats.Store, c *capture.Capturer) *Handler {
    tmpl := template.Must(template.ParseFiles("templates/index.html"))
    return &Handler{store: store, capturer: c, tmpl: tmpl}
}

func (h *Handler) Register(mux *http.ServeMux) {
    mux.HandleFunc("GET /", h.index)
    mux.HandleFunc("GET /sse/packets", h.ssePackets)
    mux.HandleFunc("GET /api/stats", h.apiStats)
    mux.HandleFunc("GET /api/topips", h.apiTopIPs)
    mux.HandleFunc("POST /capture/filter", h.setFilter)
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
func (h *Handler) ssePackets(w http.ResponseWriter, r *http.Request) {
    flusher, ok := w.(http.Flusher)
    if !ok { http.Error(w, "SSE not supported", 500); return }

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
            if !ok { return }
            flagClass := ""
            if pkt.Flagged { flagClass = " flagged" }
            html := fmt.Sprintf(
                `<tr class="pkt-row%s"><td>%s</td><td>%s</td>`+
                `<td><span class="ptag %s">%s</span></td>`+
                `<td>%dB</td><td>%s</td></tr>`,
                flagClass,
                pkt.SrcIP, pkt.DstIP,
                pkt.Proto, pkt.Proto,
                pkt.Size,
                pkt.Time.Format("15:04:05.000"),
            )
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