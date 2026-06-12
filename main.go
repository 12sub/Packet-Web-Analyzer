package main

import (
    "log"
    "net/http"

    "example.com/packet-analyser/handlers"
    "example.com/packet-analyser/internal/capture"
    "example.com/packet-analyser/internal/stats"
)

func main() {
    store := stats.New()

    // start packet capture (real or mock); keep handle for filter updates
    cap := capture.Start(store)

    // drive the rolling 1s traffic window
    go handlers.SecondTicker(store)

    h := handlers.New(store, cap)
    mux := http.NewServeMux()
    h.Register(mux)

    log.Println("listening on :8080")
    if err := http.ListenAndServe(":8080", handlers.Log(mux)); err != nil {
        log.Fatal(err)
    }
}