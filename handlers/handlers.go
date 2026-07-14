package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"

	// "net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"example.com/packet-analyser/internal/alerts"
	"example.com/packet-analyser/internal/audit"
	"example.com/packet-analyser/internal/auth"
	"example.com/packet-analyser/internal/capture"
	"example.com/packet-analyser/internal/db"
	"example.com/packet-analyser/internal/enrich"
	"example.com/packet-analyser/internal/export"
	"example.com/packet-analyser/internal/geo"
	"example.com/packet-analyser/internal/metrics"
	"example.com/packet-analyser/internal/stats"
	"example.com/packet-analyser/internal/userstore"
)

type Handler struct {
	store    *stats.Store
	capturer *capture.Capturer
	tmpl     *template.Template
	geo      *geo.Lookup
	exporter *export.Exporter
	database *db.DB
	authSvc  *auth.Service
	users    *userstore.Store
	audit    *audit.Store
	alerts   *alerts.Store
	enricher *enrich.Service
}

func New(store *stats.Store, c *capture.Capturer, g *geo.Lookup, ex *export.Exporter, database *db.DB, authSvc *auth.Service, users *userstore.Store, audit *audit.Store, alerts *alerts.Store, enricher *enrich.Service) *Handler {
	// FIX: Added the missing '*' to parse ALL html files in the templates directory
	tmpl := template.Must(template.ParseGlob("templates/*.html"))

	return &Handler{
		store: store, capturer: c, geo: g, tmpl: tmpl,
		exporter: ex, database: database, authSvc: authSvc, users: users,
		audit:    audit,
		alerts:   alerts,
		enricher: enricher,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	// ── Public ───────────────────────────────────────────────────────────────
	mux.HandleFunc("GET  /login", h.loginPage)
	mux.HandleFunc("POST /auth/login", h.login)
	mux.HandleFunc("POST /auth/logout", h.logout)

	// ── Middleware shortcuts ──────────────────────────────────────────────────
	user := h.authSvc.RequireRole(auth.RoleUser)
	editor := h.authSvc.RequireRole(auth.RoleEditor)
	admin := h.authSvc.RequireRole(auth.RoleAdmin)

	// ── User (view only) ──────────────────────────────────────────────────────
	mux.Handle("GET /", user(http.HandlerFunc(h.index)))
	mux.Handle("GET /sse/packets", user(http.HandlerFunc(h.ssePackets)))
	mux.Handle("GET /api/stats", user(http.HandlerFunc(h.apiStats)))
	mux.Handle("GET /api/connections", user(http.HandlerFunc(h.apiConnections)))
	mux.Handle("GET /api/geoips", user(http.HandlerFunc(h.apiGeoIPs)))
	mux.Handle("GET /api/topips", user(http.HandlerFunc(h.apiTopIPs)))

	// ── Editor (view + filter) ────────────────────────────────────────────────
	mux.Handle("POST /capture/filter", editor(http.HandlerFunc(h.setFilter)))

	// ── Admin (full access) ───────────────────────────────────────────────────
	mux.Handle("GET  /exports", admin(http.HandlerFunc(h.exportsPage)))
	mux.Handle("GET  /exports/files", admin(http.HandlerFunc(h.exportFileList)))
	mux.Handle("POST /exports/start-pcap", admin(http.HandlerFunc(h.startPCAP)))
	mux.Handle("POST /exports/stop-pcap", admin(http.HandlerFunc(h.stopPCAP)))
	mux.Handle("POST /exports/csv", admin(http.HandlerFunc(h.exportCSV)))
	mux.Handle("POST /exports/json", admin(http.HandlerFunc(h.exportJSON)))
	mux.Handle("GET  /exports/download/{file}", admin(http.HandlerFunc(h.download)))
	mux.Handle("POST /exports/delete/{file}", admin(http.HandlerFunc(h.deleteFile)))
	mux.Handle("GET  /admin", admin(http.HandlerFunc(h.adminPage)))
	mux.Handle("GET  /admin/users", admin(http.HandlerFunc(h.adminUserList)))
	mux.Handle("POST /admin/users/create", admin(http.HandlerFunc(h.adminCreateUser)))
	mux.Handle("POST /admin/users/{id}/role", admin(http.HandlerFunc(h.adminChangeRole)))
	mux.Handle("POST /admin/users/{id}/delete", admin(http.HandlerFunc(h.adminDeleteUser)))
	mux.Handle("POST /admin/users/{id}/password", admin(http.HandlerFunc(h.adminResetPassword)))
	mux.Handle("GET /admin/audit", admin(http.HandlerFunc(h.auditPage)))
	mux.Handle("GET /admin/alerts", admin(http.HandlerFunc(h.adminAlertsPage)))
	mux.Handle("POST /admin/alerts/create", admin(http.HandlerFunc(h.adminAlertsCreate)))
	mux.Handle("POST /admin/alerts/{id}/delete", admin(http.HandlerFunc(h.adminAlertsDelete)))
	mux.Handle("GET  /admin/flagged", admin(http.HandlerFunc(h.flaggedPage)))
	mux.Handle("GET  /admin/flagged/list", admin(http.HandlerFunc(h.flaggedList)))
	mux.Handle("POST /admin/flagged/quarantine", admin(http.HandlerFunc(h.quarantineFlagged)))
	mux.Handle("POST /admin/flagged/delete", admin(http.HandlerFunc(h.deleteFlagged)))
	mux.Handle("GET /admin/flagged/yara", admin(http.HandlerFunc(h.generateYara)))

	// --- Static files (CSS, JS, images) ------------------------------------
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	// Extract the user from the context (assuming your auth middleware sets it)
	claims := auth.ClaimsFromContext(r.Context())

	// Prepare the data map for the template
	data := map[string]any{
		"CurrentUser": claims, // This is crucial for the sidebar logic!
		// ... add your other data like Stats, Packets, etc. ...
	}

	// Execute the template
	if err := h.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *Handler) setFilter(w http.ResponseWriter, r *http.Request) {
	expr := strings.TrimSpace(r.FormValue("filter"))
	claims := auth.ClaimsFromContext(r.Context())

	if err := h.capturer.SetFilter(expr); err != nil {
		if claims != nil {
			h.audit.Log(audit.Event{
				Timestamp: time.Now(),
				UserID:    claims.UserID,
				Username:  claims.Username,
				Action:    "SET_FILTER_FAILURE",
				Details:   fmt.Sprintf("Filter: %s | Error: %s", expr, err.Error()),
				IPAddress: r.RemoteAddr,
			})
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<span id="filter-status" class="filter-err">✗ %s</span>`, template.HTMLEscapeString(err.Error()))
		return
	}

	if claims != nil {
		h.audit.Log(audit.Event{
			Timestamp: time.Now(),
			UserID:    claims.UserID,
			Username:  claims.Username,
			Action:    "SET_FILTER_SUCCESS",
			Details:   expr,
			IPAddress: r.RemoteAddr,
		})
	}

	label := "filter cleared"
	if expr != "" {
		label = fmt.Sprintf("filter applied: %s", expr)
	}
	fmt.Fprintf(w, `<span id="filter-status" class="filter-ok">✓ %s</span>`, template.HTMLEscapeString(label))
}

func (h *Handler) ssePackets(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// ── Critical headers for SSE behind reverse proxies / Tailscale ──
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disables nginx / proxy buffering
	w.WriteHeader(http.StatusOK)

	// Flush immediately so the client gets headers and establishes the connection
	flusher.Flush()

	ch := h.store.Subscribe()
	defer h.store.Unsubscribe(ch)

	// Heartbeat prevents Tailscale / NAT / firewalls from closing idle TCP sockets
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-heartbeat.C:
			// SSE comment (ignored by client) — keeps connection alive
			fmt.Fprintf(w, ":heartbeat\n\n")
			flusher.Flush()

		case pkt, ok := <-ch:
			if !ok {
				return
			}

			// Enrich with geo, vendor, OS, hostname
			h.enricher.Enrich(&pkt)

			// flagClass := ""
			// Generate ThreatIntel for flagged packets
			if pkt.Flagged && pkt.Intel == nil {
				pkt.Intel = &stats.ThreatIntel{
					ServiceVersion: "Unknown",
					RouterInfo:     "Standard Gateway",
					CapturedIPs:    pkt.SrcIP + ", " + pkt.DstIP,
					Domain:         "Suspicious Activity",
					PacketInfo:     fmt.Sprintf("%s packet, %d bytes", pkt.Proto, pkt.Size),
					Severity:       "High",
					Reason:         "Anomalous traffic pattern detected",
				}
			}

			jsonBytes, _ := json.Marshal(pkt)
			// Send JSON to client (NOT HTML)
			jsonBytes, err := json.Marshal(pkt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", jsonBytes)
			flusher.Flush()

			// jsonStr := html.EscapeString(string(jsonBytes))

			// html := fmt.Sprintf(
			// 	`<tr class="pkt-row%s" data-packet="%s" onclick="showPacketDetail(this)"><td>%s</td><td>%s</td>`+
			// 		`<td><span class="ptag%s">%s</span></td>`+
			// 		`<td>%dB</td><td>%s</td></tr>`,
			// 	flagClass,
			// 	jsonStr, // HTML-escaped JSON packet data
			// 	pkt.SrcIP, pkt.DstIP,
			// 	" "+pkt.Proto, pkt.Proto,
			// 	pkt.Size,
			// 	pkt.Time.Format("15:04:05.000"),
			// )

			srcGeo, dstGeo := "", ""
			if pkt.SrcLocation != nil {
				b, _ := json.Marshal(pkt.SrcLocation)
				srcGeo = string(b)
			}
			if pkt.DstLocation != nil {
				b, _ := json.Marshal(pkt.DstLocation)
				dstGeo = string(b)
			}

			dpiJSON := ""
			if pkt.DPI != nil {
				if b, err := json.Marshal(pkt.DPI); err == nil {
					dpiJSON = string(b)
				}
			}

			h.database.Insert(db.Row{
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				Proto:       pkt.Proto,
				Size:        pkt.Size,
				Flagged:     pkt.Flagged,
				CapturedAt:  pkt.Time,
				SrcMAC:      pkt.SrcMAC,
				DstMAC:      pkt.DstMAC,
				SrcVendor:   pkt.SrcVendor,
				DstVendor:   pkt.DstVendor,
				TTL:         pkt.TTL,
				SrcGeo:      srcGeo,
				DstGeo:      dstGeo,
				SrcHost:     pkt.SrcHost,
				DstHost:     pkt.DstHost,
				Quarantined: false,
				DPIData:     dpiJSON,
			})

			h.exporter.WritePacket(pkt)

			fmt.Fprintf(w, "event: packet\ndata: %s\n\n", jsonBytes)
			flusher.Flush()
		}
	}
}
func (h *Handler) apiStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	snap := h.store.Snapshot()
	json.NewEncoder(w).Encode(snap)
}

func (h *Handler) apiTopIPs(w http.ResponseWriter, r *http.Request) {
	snap := h.store.Snapshot()
	sort.Slice(snap.TopIPs, func(i, j int) bool {
		return snap.TopIPs[i].Count > snap.TopIPs[j].Count
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap.TopIPs)
}

func SecondTicker(store *stats.Store) {
	t := time.NewTicker(time.Second)
	for range t.C {
		store.TickSecond()
	}
}

// Add this handler to display the logs
func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	events, err := h.audit.Recent(100)
	if err != nil {
		http.Error(w, "Failed to load audit logs", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"CurrentUser": claims,
		"Events":      events,
	}
	h.tmpl.ExecuteTemplate(w, "audit.html", data)
}

func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

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
		// FIX: Removed stray space in "append"
		links = append(links, Link{Source: c.Src, Target: c.Dst, Count: c.Count})
	}

	nodes := make([]Node, 0, len(nodeMap))
	for id, pkts := range nodeMap {
		nodes = append(nodes, Node{ID: id, Packets: pkts})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Graph{Nodes: nodes, Links: links})
}

func (h *Handler) apiGeoIPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.geo == nil {
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}
	snap := h.store.Snapshot()

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

func (h *Handler) flaggedPage(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	count, _ := h.database.CountFlagged()
	h.tmpl.ExecuteTemplate(w, "flagged.html", map[string]any{
		"CurrentUser":  claims,
		"FlaggedCount": count,
	})
}

func (h *Handler) flaggedList(w http.ResponseWriter, r *http.Request) {
	packets, err := h.database.QueryFlagged(100)
	if err != nil {
		http.Error(w, "could not load flagged packets", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if len(packets) == 0 {
		fmt.Fprint(w, `<p class="empty">No flagged packets found.</p>`)
		return
	}

	for _, p := range packets {
		status := ""
		if p.Quarantined {
			status = `<span class="badge-q">🔒 Quarantined</span>`
		} else {
			status = `<span class="badge-open">⚠️ Active</span>`
		}

		fmt.Fprintf(w, `
		<div class="flagged-row">
			<div class="flagged-main">
				<span class="flagged-time">%s</span>
				<span class="flagged-ips">%s → %s</span>
				<span class="flagged-proto"><span class="ptag %s">%s</span></span>
				<span class="flagged-size">%d B</span>
				%s
			</div>
			<div class="flagged-detail">
				<span>MAC: %s → %s</span>
				<span>Vendor: %s / %s</span>
				<span>Host: %s / %s</span>
				<span>TTL: %d | OS: %s</span>
			</div>
		</div>`,
			p.CapturedAt.Format("2006-01-02 15:04:05"),
			p.SrcIP, p.DstIP,
			p.Proto, p.Proto,
			p.Size,
			status,
			p.SrcMAC, p.DstMAC,
			p.SrcVendor, p.DstVendor,
			p.SrcHost, p.DstHost,
			p.TTL, GuessOS(p.TTL),
		)
	}
}

func (h *Handler) quarantineFlagged(w http.ResponseWriter, r *http.Request) {
	count, err := h.database.QuarantineFlagged()
	if err != nil {
		http.Error(w, fmt.Sprintf("Quarantine failed: %v", err), 500)
		return
	}
	fmt.Fprintf(w, `<span class="msg-ok">✓ %d packet(s) quarantined</span>`, count)
}

func (h *Handler) deleteFlagged(w http.ResponseWriter, r *http.Request) {
	count, err := h.database.DeleteAllFlagged()
	if err != nil {
		http.Error(w, fmt.Sprintf("Delete failed: %v", err), 500)
		return
	}
	fmt.Fprintf(w, `<span class="msg-ok">✓ %d flagged packet(s) deleted</span>`, count)
}

func (h *Handler) generateYara(w http.ResponseWriter, r *http.Request) {
	rule, err := h.database.GenerateYaraRule()
	if err != nil {
		http.Error(w, fmt.Sprintf("YARA generation failed: %v", err), 500)
		return
	}

	// Return as downloadable file
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", `attachment; filename="flagged_traffic.yar"`)
	w.Write([]byte(rule))
}

func GuessOS(ttl int) string {
	switch {
	case ttl == 0:
		return "Unknown"
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	default:
		return "BSD/iOS/Mac"
	}
}

func (h *Handler) exportsPage(w http.ResponseWriter, r *http.Request) {
	h.tmpl.ExecuteTemplate(w, "exports.html", map[string]any{
		"Recording": h.exporter.IsRecording(),
	})
}

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
		icon := map[string]string{"pcap": "📦", "csv": "📄", "json": "🗂"}[f.Kind]
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
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w,
		`<span class="status-ok">● Recording → %s</span>`+
			`<button hx-post="/exports/stop-pcap" hx-target="#pcap-status" hx-swap="innerHTML" class="btn-stop">Stop</button>`,
		name)
}

func (h *Handler) stopPCAP(w http.ResponseWriter, r *http.Request) {
	if err := h.exporter.StopPCAP(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprint(w,
		`<span class="status-idle">● Idle</span>`+
			`<button hx-post="/exports/start-pcap" hx-target="#pcap-status" hx-swap="innerHTML" class="btn-start">Start recording</button>`)
}

func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	name, err := export.ExportCSV(h.database, 50000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `<span class="status-ok">✓ %s created</span>`, name)
}

func (h *Handler) exportJSON(w http.ResponseWriter, r *http.Request) {
	snap := h.store.Snapshot()
	name, err := export.ExportJSON(snap)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `<span class="status-ok">✓ %s created</span>`, name)
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("file"))
	path := filepath.Join(export.ExportDir, name)
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	ext := filepath.Ext(name)
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		ct = "application/octet-stream"
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
	io.Copy(w, f)
}

func (h *Handler) deleteFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	export.DeleteFile(name)
	h.exportFileList(w, r)
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	// already logged in → skip login page
	if claims, err := h.authSvc.TokenFromRequest(r); err == nil && claims != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
		"Next":  r.URL.Query().Get("next"),
	})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := r.FormValue("next")
	if next == "" {
		next = "/"
	}

	user, err := h.users.GetByUsername(username)
	if err != nil || !h.authSvc.CheckPassword(user.PasswordHash, password) {
		// --- NEW: Track failed login ---
		metrics.LoginAttempts.WithLabelValues("failure").Inc()
		h.audit.Log(audit.Event{
			Timestamp: time.Now(),
			Username:  username,
			Action:    "LOGIN_FAILURE",
			Details:   "Invalid credentials",
			IPAddress: r.RemoteAddr,
		})
		http.Redirect(w, r,
			"/login?error=Invalid+username+or+password&next="+next,
			http.StatusSeeOther)
		return
	}
	token, err := h.authSvc.IssueToken(user.ID, user.Username, user.Role)
	if err != nil {
		http.Error(w, "token error", 500)
		return
	}

	h.authSvc.SetCookie(w, token)
	// --- NEW: Track successful login ---
	metrics.LoginAttempts.WithLabelValues("success").Inc()
	h.audit.Log(audit.Event{
		Timestamp: time.Now(),
		Username:  user.Username,
		Action:    "LOGIN_SUCCESS",
		Details:   "User logged in successfully",
		IPAddress: r.RemoteAddr,
	})
	h.authSvc.SetCookie(w, token)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims != nil {
		h.audit.Log(audit.Event{
			Timestamp: time.Now(),
			UserID:    claims.UserID,
			Username:  claims.Username,
			Action:    "LOGOUT",
			IPAddress: r.RemoteAddr,
		})
	}
	h.authSvc.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) adminPage(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	h.tmpl.ExecuteTemplate(w, "admin.html", map[string]any{
		"CurrentUser": claims,
	})
}

func (h *Handler) adminUserList(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	users, err := h.users.List()
	if err != nil {
		http.Error(w, "could not list users", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	for _, u := range users {
		isSelf := u.ID == claims.UserID
		selfTag := ""
		if isSelf {
			selfTag = `<span class="self-tag">you</span>`
		}

		fmt.Fprintf(w, `
        <tr>
          <td class="mono">%d</td>
          <td>%s %s</td>
          <td>
            <select class="role-select"
              name="role"
              hx-post="/admin/users/%d/role"
              hx-trigger="change"
              hx-target="#user-list"
              hx-swap="innerHTML"
              %s>
              <option value="user"   %s>User</option>
              <option value="editor" %s>Editor</option>
              <option value="admin"  %s>Admin</option>
            </select>
          </td>
          <td class="mono text-muted">%s</td>
          <td class="actions">
            <button class="btn-sm btn-warn"
              hx-post="/admin/users/%d/password"
              hx-prompt="Enter new password (min 8 chars):"
              hx-target="#admin-msg"
              hx-swap="innerHTML">Reset pw</button>
            %s
          </td>
        </tr>`,
			u.ID, u.Username, selfTag,
			u.ID,
			ifStr(isSelf, "disabled", ""),
			ifStr(u.Role == "user", "selected", ""),
			ifStr(u.Role == "editor", "selected", ""),
			ifStr(u.Role == "admin", "selected", ""),
			u.CreatedAt.Format("2006-01-02 15:04"),
			u.ID,
			deleteBtn(u.ID, u.Username, isSelf),
		)
	}
}

func (h *Handler) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")

	switch {
	case username == "" || password == "":
		fmt.Fprint(w, `<span class="msg-err">Username and password are required</span>`)
		return
	case len(password) < 8:
		fmt.Fprint(w, `<span class="msg-err">Password must be at least 8 characters</span>`)
		return
	case role != auth.RoleUser && role != auth.RoleEditor && role != auth.RoleAdmin:
		fmt.Fprint(w, `<span class="msg-err">Invalid role</span>`)
		return
	}

	hash, err := h.authSvc.HashPassword(password)
	if err != nil {
		fmt.Fprint(w, `<span class="msg-err">Internal error</span>`)
		return
	}

	if _, err := h.users.Create(username, hash, role); err != nil {
		fmt.Fprintf(w, `<span class="msg-err">Could not create user: username may already exist</span>`)
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	h.audit.Log(audit.Event{
		Timestamp: time.Now(),
		UserID:    claims.UserID,
		Username:  claims.Username,
		Action:    "CREATE_USER",
		Details:   fmt.Sprintf("Created user '%s' with role '%s'", username, role),
		IPAddress: r.RemoteAddr,
	})
	fmt.Fprintf(w, `<span class="msg-ok">✓ User "%s" created as %s</span>`, username, role)
}

func (h *Handler) adminChangeRole(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	role := r.FormValue("role")

	if id == claims.UserID {
		http.Error(w, "cannot change your own role", http.StatusBadRequest)
		return
	}
	if err := h.users.UpdateRole(id, role); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h.adminUserList(w, r)
}

func (h *Handler) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)

	if id == claims.UserID {
		http.Error(w, "cannot delete yourself", http.StatusBadRequest)
		return
	}
	h.users.Delete(id)
	h.adminUserList(w, r)
}

func (h *Handler) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	newPass := r.Header.Get("HX-Prompt")
	idInt, _ := strconv.ParseInt(id, 10, 64)

	if len(newPass) < 8 {
		fmt.Fprint(w, `<span class="msg-err">Password must be at least 8 characters</span>`)
		return
	}
	hash, _ := h.authSvc.HashPassword(newPass)
	h.users.UpdatePassword(idInt, hash)
	fmt.Fprint(w, `<span class="msg-ok">✓ Password updated</span>`)
}

// helpers
func ifStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func deleteBtn(id int64, username string, isSelf bool) string {
	if isSelf {
		return ""
	}
	return fmt.Sprintf(`
        <button class="btn-sm btn-danger"
          hx-post="/admin/users/%d/delete"
          hx-confirm="Delete user '%s'? This cannot be undone."
          hx-target="#user-list"
          hx-swap="innerHTML">Delete</button>`, id, username)
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// // GetRealIP extracts the client's true IP address from reverse proxy headers.
// func GetRealIP(r *http.Request) string {
//     // Check X-Forwarded-For (used by Caddy, Nginx, AWS ALB)
//     if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
//         parts := strings.Split(xff, ",")
//         return strings.TrimSpace(parts[0])
//     }
//     // Check X-Real-IP (used by Nginx)
//     if xri := r.Header.Get("X-Real-IP"); xri != "" {
//         return xri
//     }
//     // Fallback to RemoteAddr (strip the port number)
//     ip, _, err := net.SplitHostPort(r.RemoteAddr)
//     if err != nil {
//         return r.RemoteAddr
//     }
//     return ip
// }
