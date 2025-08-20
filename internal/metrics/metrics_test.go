package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestInitRegistersMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(RequestErrors, RequestCount, VirusesDiscovered)

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
}

func TestVirusesDiscoveredCounter(t *testing.T) {
	VirusesDiscovered.Inc()
	value := testutil.ToFloat64(VirusesDiscovered)
	if value != 1 {
		t.Errorf("expected VirusesDiscovered to be 1, got %v", value)
	}
}

func TestRequestCountVec(t *testing.T) {
	RequestCount.WithLabelValues("POST", "/scan").Inc()
	value := testutil.ToFloat64(RequestCount.WithLabelValues("POST", "/scan"))
	if value != 1 {
		t.Errorf("expected RequestCount for POST /scan to be 1, got %v", value)
	}
}

func TestRequestErrorVec(t *testing.T) {
	RequestErrors.WithLabelValues("GET", "/ping").Inc()
	value := testutil.ToFloat64(RequestErrors.WithLabelValues("GET", "/ping"))
	if value != 1 {
		t.Errorf("expected RequestErrors for GET /ping to be 1, got %v", value)
	}
}
