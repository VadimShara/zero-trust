package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler returns the Prometheus HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}

// NewCounter creates a labelled counter (use WithLabelValues to record).
func NewCounter(name, help string, labels ...string) *prometheus.CounterVec {
	return promauto.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

// NewCounterSimple creates a counter without labels.
func NewCounterSimple(name, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
}

// NewHistogram creates a labelled histogram.
func NewHistogram(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	return promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: name, Help: help, Buckets: buckets,
	}, labels)
}

// NewHistogramSimple creates a histogram without labels.
func NewHistogramSimple(name, help string, buckets []float64) prometheus.Histogram {
	return promauto.NewHistogram(prometheus.HistogramOpts{
		Name: name, Help: help, Buckets: buckets,
	})
}

// NewGauge creates a labelled gauge.
func NewGauge(name, help string, labels ...string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

// TrustScoreBuckets are buckets aligned with decision thresholds:
// DENY<0.30, STEP_UP<0.50, MFA_REQUIRED<0.70, ALLOW≥0.70
var TrustScoreBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
