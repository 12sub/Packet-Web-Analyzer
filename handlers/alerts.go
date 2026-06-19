// handlers/alerts.go
package handlers

import (
	"net/http"
	"strconv"
	"example.com/packet-analyser/internal/alerts"
	"example.com/packet-analyser/internal/auth"
)

func (h *Handler) adminAlertsPage(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	rules, err := h.alerts.List()
	if err != nil {
		http.Error(w, "Failed to load rules", 500)
		return
	}

	data := map[string]any{
		"CurrentUser": claims,
		"Rules":       rules,
	}
	h.tmpl.ExecuteTemplate(w, "alerts.html", data)
}

func (h *Handler) adminAlertsCreate(w http.ResponseWriter, r *http.Request) {
	rule := alerts.Rule{
		Name:         r.FormValue("name"),
		Type:         r.FormValue("type"),
		Target:       r.FormValue("target"),
		WebhookURL:   r.FormValue("webhook_url"),
		Enabled:      true,
	}
	
	rule.Threshold, _ = strconv.Atoi(r.FormValue("threshold"))
	rule.WindowSecs, _ = strconv.Atoi(r.FormValue("window_secs"))
	rule.CooldownSecs, _ = strconv.Atoi(r.FormValue("cooldown_secs"))

	if rule.CooldownSecs == 0 { rule.CooldownSecs = 300 } // Default 5 mins

	h.alerts.Create(rule)
	http.Redirect(w, r, "/admin/alerts", http.StatusSeeOther)
}

func (h *Handler) adminAlertsDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	h.alerts.Delete(id)
	http.Redirect(w, r, "/admin/alerts", http.StatusSeeOther)
}