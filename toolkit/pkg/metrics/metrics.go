package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Handler() http.Handler {
	return promhttp.Handler()
}

func NewCounter(name, help string, labels ...string) *prometheus.CounterVec {
	return promauto.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

func NewCounterSimple(name, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
}

func NewHistogram(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	return promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: name, Help: help, Buckets: buckets,
	}, labels)
}

func NewHistogramSimple(name, help string, buckets []float64) prometheus.Histogram {
	return promauto.NewHistogram(prometheus.HistogramOpts{
		Name: name, Help: help, Buckets: buckets,
	})
}

func NewGauge(name, help string, labels ...string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

var TrustScoreBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
