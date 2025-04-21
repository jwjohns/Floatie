package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Read latency metrics
	ReadLatencyHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "floatie_overlayfs_read_latency_us",
		Help:    "OverlayFS read latency in microseconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 20), // Cover from 1µs to ~1s
	})

	// Write latency metrics
	WriteLatencyHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "floatie_overlayfs_write_latency_us",
		Help:    "OverlayFS write latency in microseconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 20),
	})

	// OOM kill metrics
	OOMKillsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "floatie_oom_kills_total",
		Help: "Total number of OOM kill events",
	}, []string{"trigger_comm", "victim_comm"})

	// System metrics
	MemPressureGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "floatie_memory_pressure_score",
		Help: "Current memory pressure score (0-100)",
	})
)

// Register registers all metrics with the Prometheus client
func Register() {
	prometheus.MustRegister(
		ReadLatencyHist,
		WriteLatencyHist,
		OOMKillsCounter,
		MemPressureGauge,
	)
}