package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"example.com/packet-analyser/internal/capture"
	"example.com/packet-analyser/internal/db"
	"example.com/packet-analyser/internal/export"
	"example.com/packet-analyser/internal/geo"
	"example.com/packet-analyser/internal/stats"
)

type Handler struct {
	store    *stats.Store
	capturer *capture.Capturer
	tmpl     *template.Template
	geo      *geo.Lookup
    exporter *export.Exporter   // ← new
    database *db.DB 
}

func New(store *stats.Store, c *capture.Capturer, g *geo.Lookup, ex *export.Exporter, database *db.DB) *Handler {
	tmpl := template.Must(template.ParseGlob("templates/*.html"))
	return &Handler{store: store, capturer: c, geo: g, tmpl: tmpl, exporter: ex, database: database}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /sse/packets", h.ssePackets)
	mux.HandleFunc("GET /api/stats", h.apiStats)
	mux.HandleFunc("GET /api/topips", h.apiTopIPs)
	mux.HandleFunc("POST /capture/filter", h.setFilter)
	mux.HandleFunc("GET /api/connections", h.apiConnections)
	mux.HandleFunc("GET /api/geoips", h.apiGeoIPs)
     mux.HandleFunc("GET  /exports", h.exportsPage)
    mux.HandleFunc("GET  /exports/files",            h.exportFileList)
    mux.HandleFunc("POST /exports/start-pcap",       h.startPCAP)
    mux.HandleFunc("POST /exports/stop-pcap",        h.stopPCAP)
    mux.HandleFunc("POST /exports/csv",              h.exportCSV)
    mux.HandleFunc("POST /exports/json",             h.exportJSON)
    mux.HandleFunc("GET  /exports/download/{file}",  h.download)
    mux.HandleFunc("POST /exports/delete/{file}",    h.deleteFile)
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
	if expr != "" {
		label = fmt.Sprintf("filter applied: %s", expr)
	}
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
            // persist to SQLite
            h.database.Insert(db.Row{
                SrcIP: pkt.SrcIP, DstIP: pkt.DstIP,
                Proto: pkt.Proto, Size: pkt.Size,
                Flagged: pkt.Flagged, CapturedAt: pkt.Time,
            })

            // write to PCAP if recording
            h.exporter.WritePacket(pkt)

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
	for range t.C {
		store.TickSecond()
	}
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
	links := make([]Link, 0, len(snap.TopConns))

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
		if err != nil {
			continue
		}
		locs = append(locs, *loc)
	}

	json.NewEncoder(w).Encode(locs)
}
func (h *Handler) exportsPage(w http.ResponseWriter, r *http.Request) {
    h.tmpl.ExecuteTemplate(w, "exports.html", map[string]any{
        "Recording": h.exporter.IsRecording(),
    })
}

// exportFileList returns an HTMX HTML fragment of available files.
func (h *Handler) exportFileList(w http.ResponseWriter, r *http.Request) {
    files, err := export.ListFiles()
    if err != nil {
        http.Error(w, "could not list files", 500)
        return
    }
    count, _ := h.database.Count()

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, `<p class="db-count">%d packets stored in session DB</p>`, count)

    if len(files) == 0 {
        fmt.Fprint(w, `<p class="empty">No exports yet. Use the buttons above to generate one.</p>`)
        return
    }

    for _, f := range files {
        icon := map[string]string{"pcap":"📦","csv":"📄","json":"🗂"}[f.Kind]
        fmt.Fprintf(w, `
        <div class="file-row">
          <span class="file-icon">%s</span>
          <span class="file-name">%s</span>
          <span class="file-meta">%s · %s</span>
          <div class="file-actions">
            <a class="btn-dl" href="/exports/download/%s" download>Download</a>
            <button class="btn-del"
              hx-post="/exports/delete/%s"
              hx-confirm="Delete %s?"
              hx-target="#file-list"
              hx-swap="innerHTML">Delete</button>
          </div>
        </div>`, icon, f.Name, f.Kind,
            humanSize(f.Size), f.Name, f.Name, f.Name)
    }
}

func (h *Handler) startPCAP(w http.ResponseWriter, r *http.Request) {
    name, err := h.exporter.StartPCAP()
    if err != nil {
        http.Error(w, err.Error(), 400); return
    }
    fmt.Fprintf(w,
        `<span class="status-ok">● Recording → %s</span>`+
        `<button hx-post="/exports/stop-pcap" hx-target="#pcap-status" hx-swap="innerHTML" class="btn-stop">Stop</button>`,
        name)
}

func (h *Handler) stopPCAP(w http.ResponseWriter, r *http.Request) {
    if err := h.exporter.StopPCAP(); err != nil {
        http.Error(w, err.Error(), 400); return
    }
    fmt.Fprint(w,
        `<span class="status-idle">● Idle</span>`+
        `<button hx-post="/exports/start-pcap" hx-target="#pcap-status" hx-swap="innerHTML" class="btn-start">Start recording</button>`)
}

func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
    name, err := export.ExportCSV(h.database, 50000)
    if err != nil { http.Error(w, err.Error(), 500); return }
    fmt.Fprintf(w, `<span class="status-ok">✓ %s created</span>`, name)
}

func (h *Handler) exportJSON(w http.ResponseWriter, r *http.Request) {
    snap := h.store.Snapshot()
    name, err := export.ExportJSON(snap)
    if err != nil { http.Error(w, err.Error(), 500); return }
    fmt.Fprintf(w, `<span class="status-ok">✓ %s created</span>`, name)
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
    name := filepath.Base(r.PathValue("file"))
    path := filepath.Join(export.ExportDir, name)

    f, err := os.Open(path)
    if err != nil { http.NotFound(w, r); return }
    defer f.Close()

    info, _ := f.Stat()
    ext := filepath.Ext(name)
    ct := mime.TypeByExtension(ext)
    if ct == "" { ct = "application/octet-stream" }

    w.Header().Set("Content-Disposition", "attachment; filename="+name)
    w.Header().Set("Content-Type", ct)
    w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
    io.Copy(w, f)
}

func (h *Handler) deleteFile(w http.ResponseWriter, r *http.Request) {
    name := r.PathValue("file")
    export.DeleteFile(name)
    // re-render file list
    h.exportFileList(w, r)
}

func humanSize(b int64) string {
    switch {
    case b >= 1<<20: return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
    case b >= 1<<10: return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
    default:         return fmt.Sprintf("%d B", b)
    }
}
