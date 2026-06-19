package main

import (
	"log"
	"net/http"
	"os"

	"example.com/packet-analyser/handlers"
	"example.com/packet-analyser/internal/alerts"
	"example.com/packet-analyser/internal/audit"
	"example.com/packet-analyser/internal/auth"
	"example.com/packet-analyser/internal/capture"
	"example.com/packet-analyser/internal/db"
	"example.com/packet-analyser/internal/export"
	"example.com/packet-analyser/internal/geo"
	"example.com/packet-analyser/internal/metrics"
	"example.com/packet-analyser/internal/stats"
	"example.com/packet-analyser/internal/userstore"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	store := stats.New()
	cap := capture.Start(store)
	go handlers.SecondTicker(store)

	g, err := geo.New("GeoLite2-City.mmdb")
	if err != nil {
		log.Println("[geo] disabled:", err)
	} else {
		log.Println("[geo] GeoLite2 database loaded")
		defer g.Close()
	}

	database, err := db.Open("./exports/session.db")
	if err != nil {
		log.Fatal("[db] ", err)
	}
	defer database.Close()

	ex, err := export.New()
	if err != nil {
		log.Fatal("[export] ", err)
	}

	users, err := userstore.Open("./exports/users.db")
	if err != nil {
		log.Fatal("[userstore] ", err)
	}
	defer users.Close()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-dev-key-change-in-production"
		log.Println("[auth] warning: using default JWT_SECRET")
	}
	authSvc := auth.NewService(jwtSecret)

	count, _ := users.Count()
	if count == 0 {
		hash, err := authSvc.HashPassword("admin123")
		if err == nil {
			users.Create("admin", hash, auth.RoleAdmin)
			log.Println("[auth] created default admin user: username='admin', password='admin123'")
		}
	}

	auditStore, err := audit.Open("./exports/audit.db")
	if err != nil {
		log.Fatal("[audit] ", err)
	}
	defer auditStore.Close()

	alertStore, err := alerts.Open("./exports/alerts.db")
	if err != nil {
		log.Fatal("[alerts] ", err)
	}
	defer alertStore.Close()

	alertEngine := alerts.NewEngine(alertStore, store)
	alertEngine.Start()

	h := handlers.New(store, cap, g, ex, database, authSvc, users, auditStore, alertStore)

	mux := http.NewServeMux()
	h.Register(mux)

	mux.Handle("GET /metrics", promhttp.Handler())

	finalHandler := metrics.Middleware(mux)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", finalHandler); err != nil {
		log.Fatal(err)
	}
}