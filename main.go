package main

import (
	"log"
	"net/http"
	"os"

	"example.com/packet-analyser/handlers"
	"example.com/packet-analyser/internal/auth"
	"example.com/packet-analyser/internal/capture"
	"example.com/packet-analyser/internal/db"
	"example.com/packet-analyser/internal/export"
	"example.com/packet-analyser/internal/geo"
	"example.com/packet-analyser/internal/stats"
	"example.com/packet-analyser/internal/userstore"
	"example.com/packet-analyser/internal/audit"
	"example.com/packet-analyser/internal/metrics" 
)

func main() {
	store := stats.New()
	cap := capture.Start(store)
	go handlers.SecondTicker(store)

	// Geo lookup
	g, err := geo.New("GeoLite2-City.mmdb")
	if err != nil {
		log.Println("[geo] disabled:", err)
	} else {
		log.Println("[geo] GeoLite2 database loaded")
		defer g.Close()
	}

	// SQLite session history
	database, err := db.Open("./exports/session.db")
	if err != nil {
		log.Fatal("[db] ", err)
	}
	defer database.Close()

	// Export manager
	ex, err := export.New()
	if err != nil {
		log.Fatal("[export] ", err)
	}

	// ── NEW: Initialize User Store ──────────────────────────────────────────
	users, err := userstore.Open("./exports/users.db")
	if err != nil {
		log.Fatal("[userstore] ", err)
	}
	defer users.Close()

	// ── NEW: Initialize Auth Service ────────────────────────────────────────
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-dev-key-change-in-production"
		log.Println("[auth] warning: using default JWT_SECRET")
	}
	authSvc := auth.NewService(jwtSecret)

	// ── NEW: Seed a default admin user if the database is empty ─────────────
	count, _ := users.Count()
	if count == 0 {
		hash, err := authSvc.HashPassword("admin123")
		if err == nil {
			users.Create("admin", hash, auth.RoleAdmin)
			log.Println("[auth] created default admin user: username='admin', password='admin123'")
		}
	}
	// ── NEW: Initialize Audit Store ─────────────────────────────────────────
    auditStore, err := audit.Open("./exports/audit.db")
    if err != nil {
        log.Fatal("[audit] ", err)
    }
    defer auditStore.Close()

	// ── Wire everything together ────────────────────────────────────────────
	h := handlers.New(store, cap, g, ex, database, authSvc, users, auditStore)
	
	mux := http.NewServeMux()
	h.Register(mux)

	mux.Handle("GET /metrics", promhttp.Handler())

    // ── NEW: Wrap the mux with Prometheus HTTP Middleware ───────────────────
    // This tracks request counts and durations for ALL routes
    finalHandler := metrics.Middleware(mux)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", handlers.Log(mux)); err != nil {
		log.Fatal(err)
	}
}