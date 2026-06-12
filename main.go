package main

import (
    "log"
    "net/http"

    "example.com/packet-analyser/handlers"
    "example.com/packet-analyser/internal/capture"
    "example.com/packet-analyser/internal/stats"
    "example.com/packet-analyser/internal/geo"
)

func main() {
    store := stats.New()
    cap   := capture.Start(store)
    go handlers.SecondTicker(store)

    // Geo lookup — gracefully disabled if DB file is absent
    g, err := geo.New("GeoLite2-City.mmdb")
    if err != nil {
        log.Println("[geo] disabled:", err)
    } else {
        log.Println("[geo] GeoLite2 database loaded")
        defer g.Close()
    }

    h := handlers.New(store, cap, g)
    mux := http.NewServeMux()
    h.Register(mux)

    log.Println("listening on :8080")
    if err := http.ListenAndServe(":8080", handlers.Log(mux)); err != nil {
        log.Fatal(err)
    }
}