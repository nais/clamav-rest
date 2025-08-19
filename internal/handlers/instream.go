package handlers

import (
	"clamav-rest/internal/metrics"
	"encoding/json"
	"net/http"
	"strings"

	"clamav-rest/internal/clamav"

	"github.com/rs/zerolog/log"
)

type StreamResp struct {
	FileName  string `json:"Filename"`
	Message   string `json:"Message"`
	Signature string `json:"Signature"`
	Result    string `json:"Result"`
}

func (h *Handler) InStream(maxFileSize int64) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		var ctx = r.Context()
		var streamResp StreamResp

		_, hd, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "failed to parse form file: "+err.Error(), http.StatusBadRequest)
			return
		}

		f, err := hd.Open()
		if err != nil {
			http.Error(w, "failed to open file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if hd.Size > maxFileSize {
			http.Error(w, "file size exceeds limit", http.StatusBadRequest)
			return
		}

		defer f.Close()

		inStream, err := h.Clamav.InStream(ctx, f, hd.Size)
		if err != nil {
			http.Error(w, "failed to scan file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if h.virusFound(string(inStream)) {
			streamResp = StreamResp{
				FileName:  hd.Filename,
				Message:   clamav.MsgVirusFound,
				Signature: h.parseSignature(string(inStream)),
				Result:    clamav.ResVirusFound,
			}
			log.Error().Msgf("virus %s found in file: %s", streamResp.Signature, streamResp.FileName)
			metrics.VirusesDiscovered.Inc()
		} else {
			streamResp = StreamResp{
				FileName:  hd.Filename,
				Message:   clamav.MsgVirusNotFound,
				Signature: "",
				Result:    clamav.ResVirusNotFound,
			}
			log.Debug().Msgf("no virus found in file: %s", streamResp.FileName)
		}

		resp, err := json.Marshal(streamResp)
		if err != nil {
			http.Error(w, "failed to marshal response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resp); err != nil {
			http.Error(w, "failed to write response: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (h *Handler) parseSignature(msg string) string {
	return strings.TrimLeft(strings.TrimRight(msg, " FOUND\n"), "stream: ")
}

func (h *Handler) virusFound(msg string) bool {
	return strings.HasSuffix(msg, "FOUND\n")
}
