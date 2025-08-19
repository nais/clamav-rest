package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

func (h *Handler) Liveness(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{"status": "alive"}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Debug().Msg("Liveness check successful")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := h.Clamav.Ping(ctx)
	if err != nil {
		http.Error(w, "ClamAV not ready", http.StatusServiceUnavailable)
		return
	}

	response := map[string]string{"status": "ready"}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Debug().Msg("Readiness check successful")
	w.WriteHeader(http.StatusOK)
}
