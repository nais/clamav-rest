package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	RequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clamav_requests_total",
			Help: "Total number of requests",
		},
		[]string{"method", "endpoint"},
	)
	RequestErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clamav_requests_errors_total",
			Help: "Total number of request errors",
		},
		[]string{"method", "endpoint"},
	)
	ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clamav_scan_duration_seconds",
			Help:    "Duration of ClamAV scan requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	VirusesDiscovered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clamav_viruses_discovered_total",
			Help: "Total number of viruses discovered by ClamAV scans",
		},
	)
)

func Init() {
	prometheus.MustRegister(RequestErrors, RequestCount, ScanDuration, VirusesDiscovered)
}
