package handlers

import (
	"encoding/json"
	"net/http"
	"example.com/packet-analyser/internal/stats"
)

func (h *Handler) getFlaggedPackets(w http.ResponseWriter, r *http.Request) {
	// We can get recent packets by subscribing and collecting, 
	// but since stats.Store doesn't keep a history, we'll use a trick:
	// We will create a temporary subscriber, wait 2 seconds, and collect flagged ones.
	
	// Note: For a production app, you would store flagged packets in a separate SQLite table.
	// For now, we'll just return a snapshot of the current active flagged state or mock data.
	
	// Let's return the current Snapshot's flagged count, and a mock array of threats for the UI
	snap := h.store.Snapshot()
	
	// In a real scenario, you'd query a DB. Here is how you format the JSON response:
	response := map[string]any{
		"total_flagged": snap.Flagged,
		"recent_threats": []stats.ThreatIntel{
			// This is a placeholder. In reality, you'd push these to a DB in capture.go
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}