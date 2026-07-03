// internal/metrics/metrics.go
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// --- Capture Metrics ---
	PacketsCaptured = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "packet_analyzer_packets_captured_total",
		Help: "Total number of packets successfully captured",
	})
	BytesCaptured = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "packet_analyzer_bytes_captured_total",
		Help: "Total number of bytes captured",
	})
	PacketsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "packet_analyzer_packets_dropped_total",
		Help: "Total number of packets dropped by the kernel or interface",
	})
	ActiveCaptures = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "packet_analyzer_active_captures",
		Help: "Number of currently active packet capture sessions",
	})

	// --- Business/Auth Metrics ---
	LoginAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_analyzer_login_attempts_total",
		Help: "Total number of login attempts",
	}, []string{"status"}) // status will be "success" or "failure"

	FilterChanges = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "packet_analyzer_filter_changes_total",
		Help: "Total number of BPF filter changes",
	})

	// --- HTTP Metrics ---
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_analyzer_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packet_analyzer_http_request_duration_seconds",
		Help:    "Duration of HTTP requests in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

func init() {
	// Register all metrics with the default Prometheus registry
	prometheus.MustRegister(
		PacketsCaptured, BytesCaptured, PacketsDropped, ActiveCaptures,
		LoginAttempts, FilterChanges,
		HTTPRequests, HTTPDuration,
	)
}

// Middleware wraps an http.Handler to record HTTP metrics
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap the ResponseWriter to capture the status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		// Record metrics
		HTTPDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
		HTTPRequests.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(wrapped.statusCode)).Inc()
	})
}

// responseWriter is a wrapper to capture the HTTP status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher so SSE works through this middleware.
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap allows middlewares further up the chain to access the original writer.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}