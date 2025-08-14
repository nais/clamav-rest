package handlers

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) Version(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.Clamav.Version(ctx)
	if err != nil {
		http.Error(w, "failed to get clamd version: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]string{"version": string(res)}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
	}
}
