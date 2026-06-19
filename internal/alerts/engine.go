package alerts

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"example.com/packet-analyser/internal/stats"
)

type Engine struct {
	store *Store
	statStore *stats.Store

	mu      sync.Mutex
	packets []stats.Packet
}

func NewEngine(store *Store, statsInfo *stats.Store) *Engine {
	return &Engine{
		store:   store,
		statStore:   statsInfo,
		packets: make([]stats.Packet, 0, 10000),
	}
}

func (e *Engine) Start() {
	log.Println("[alerts] engine started, subscribing to live packet feed")
	ch := e.statStore.Subscribe()
	go e.ingest(ch)
	go e.run()
}

func (e *Engine) ingest(ch chan stats.Packet) {
	for p := range ch {
		e.mu.Lock()
		e.packets = append(e.packets, p)
		if len(e.packets) > 10000 {
			e.packets = e.packets[len(e.packets)-5000:]
		}
		e.mu.Unlock()
	}
}
func (e *Engine) run() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		e.evaluate()
	}
}

func (e *Engine) evaluate() {
	rules, err := e.store.List()
	if err != nil {
		log.Println("[alerts] failed to list rules:", err)
		return
	}

	e.mu.Lock()
	currentPackets := make([]stats.Packet, len(e.packets))
	copy(currentPackets, e.packets)
	e.mu.Unlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !rule.LastTriggered.IsZero() && time.Since(rule.LastTriggered) < time.Duration(rule.CooldownSecs)*time.Second {
			continue
		}

		windowCutoff := time.Now().Add(-time.Duration(rule.WindowSecs) * time.Second)
		var count int
		for _, p := range currentPackets {
			if p.Time.Before(windowCutoff) {
				continue
			}
			switch rule.Type {
			case "traffic_spike":
				count++
			case "ip_threshold":
				if p.SrcIP == rule.Target || p.DstIP == rule.Target {
					count++
				}
			case "anomaly":
				if p.Flagged {
					count++
				}
			}
		}

		if count > rule.Threshold {
			e.fireWebhook(rule, count)
			e.store.UpdateLastTriggered(rule.ID)
		}
	}
}

func (e *Engine) fireWebhook(rule Rule, count int) {
	payload := map[string]any{
		"alert_name":    rule.Name,
		"rule_type":     rule.Type,
		"message":       "Threshold exceeded in the monitored window",
		"current_value": count,
		"threshold":     rule.Threshold,
		"target":        rule.Target,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(rule.WebhookURL, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[alerts] webhook failed for %s: %v", rule.Name, err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[alerts] 🔥 FIRED webhook for '%s' (status: %d, count: %d)", rule.Name, resp.StatusCode, count)
}