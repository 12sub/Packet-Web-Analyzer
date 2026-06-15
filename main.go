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
)

func main() {
    // ── JWT secret ───────────────────────────────────────────────────────────
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        jwtSecret = "change-me-in-production"
        log.Println("[auth] ⚠️  JWT_SECRET not set — using insecure default. Set it in .env!")
    }
    authSvc := auth.NewService(jwtSecret)

    // ── User store ───────────────────────────────────────────────────────────
    users, err := userstore.Open("./exports/users.db")
    if err != nil { log.Fatal("[userstore]", err) }
    defer users.Close()

    // Bootstrap: create default admin if no users exist
    if count, _ := users.Count(); count == 0 {
        hash, _ := authSvc.HashPassword("admin123")
        users.Create("admin", hash, auth.RoleAdmin)
        log.Println("[auth] ⚠️  Default admin created — username: admin  password: admin123")
        log.Println("[auth] ⚠️  CHANGE THIS PASSWORD IMMEDIATELY via the /admin panel")
    }

    // ── Packet capture ───────────────────────────────────────────────────────
    store := stats.New()
    cap   := capture.Start(store)
    go handlers.SecondTicker(store)

    // ── Geo lookup ───────────────────────────────────────────────────────────
    g, err := geo.New("GeoLite2-City.mmdb")
    if err != nil { log.Println("[geo] disabled:", err) } else { defer g.Close() }

    // ── Session DB + exporter ────────────────────────────────────────────────
    database, err := db.Open("./exports/session.db")
    if err != nil { log.Fatal("[db]", err) }
    defer database.Close()

    ex, err := export.New()
    if err != nil { log.Fatal("[export]", err) }

    // ── HTTP server ──────────────────────────────────────────────────────────
    h := handlers.New(store, cap, g, ex, database, authSvc, users)
    mux := http.NewServeMux()
    h.Register(mux)

    log.Println("[server] listening on :8080")
    if err := http.ListenAndServe(":8080", handlers.Log(mux)); err != nil {
        log.Fatal(err)
    }
}