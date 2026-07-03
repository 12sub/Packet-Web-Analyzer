package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	"example.com/packet-analyser/internal/enrich"

	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	enricher := enrich.New(g)

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

	// Initialize User Store
	users, err := userstore.Open("./exports/users.db")
	if err != nil {
		log.Fatal("[userstore] ", err)
	}
	defer users.Close()

	// Initialize Auth Service
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-dev-key-change-in-production"
		log.Println("[auth] warning: using default JWT_SECRET")
	}
	authSvc := auth.NewService(jwtSecret)

	// Seed a default admin user if the database is empty
	count, _ := users.Count()
	if count == 0 {
		hash, err := authSvc.HashPassword("admin123")
		if err == nil {
			users.Create("admin", hash, auth.RoleAdmin)
			log.Println("[auth] created default admin user: username='admin', password='admin123'")
		}
	}

	// Initialize Audit Store
	auditStore, err := audit.Open("./exports/audit.db")
	if err != nil {
		log.Fatal("[audit] ", err)
	}
	defer auditStore.Close()

	// Initialize Alert Store & Engine
	alertStore, err := alerts.Open("./exports/alerts.db")
	if err != nil {
		log.Fatal("[alerts] ", err)
	}
	defer alertStore.Close()

	alertEngine := alerts.NewEngine(alertStore, store)
	alertEngine.Start()

	// Wire everything together
	h := handlers.New(store, cap, g, ex, database, authSvc, users, auditStore, alertStore, enricher)

	mux := http.NewServeMux()
	h.Register(mux)

	mux.Handle("GET /metrics", promhttp.Handler())

	finalHandler := metrics.Middleware(mux)

	// ── Production-Ready HTTP Server Setup ────────────────────────────
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      finalHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start Server in a Goroutine
	go func() {
		log.Println("listening on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// ── Graceful Shutdown Logic ───────────────────────────────────────
	// Wait for interrupt signal (Ctrl+C) or SIGTERM (from Docker)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown signal received, draining connections...")

	// Give outstanding requests 10 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting. Closing databases and capture handles...")
	// Note: Because we used `defer database.Close()` etc. earlier in main(), 
	// they will automatically execute as main() exits here!
}