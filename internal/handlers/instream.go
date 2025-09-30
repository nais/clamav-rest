package handlers

import (
	"bytes"
	"clamav-rest/internal/clamav"
	"clamav-rest/internal/metrics"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func (h *Handler) InStream(maxFileSize int64) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			streamResp = StreamResp{}
			err        error
			files      map[string][]byte
		)

		switch {
		case r.Method == http.MethodPut:
			files, err = readRequestBody(r)
		case r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
			files, err = readMultipartForm(r, maxFileSize)
		default:
			http.Error(w, "unsupported method or content type", http.StatusBadRequest)
			return
		}
		if err != nil {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			log.Error().Msgf("Error reading request body: %v", err)
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if !isSizeWithinLimit(files, maxFileSize) {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "file size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}

		for filename, buf := range files {
			part := io.NopCloser(bytes.NewBuffer(buf))
			start := time.Now()
			inStream, err := h.Clamav.InStream(r.Context(), part, int64(len(buf)))
			if err != nil {
				metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
				http.Error(w, "failed to scan file: "+err.Error(), http.StatusInternalServerError)
				return
			}

			scanDuration := time.Since(start).Seconds()
			metrics.RequestCount.WithLabelValues(r.Method, "/scan").Inc()
			metrics.ScanDuration.WithLabelValues(r.Method, "/scan").Observe(scanDuration)

			streamResp = StreamResp{
				Filename: filename,
				Result:   clamav.ResVirusNotFound,
			}
			if virusFound(string(inStream)) {
				streamResp.Result = clamav.ResVirusFound
				log.Error().Msgf("virus %s found in file: %s", parseSignature(string(inStream)), streamResp.Filename)
				metrics.VirusesDiscovered.Inc()
			} else {
				log.Debug().Msgf("no virus found in file: %s", streamResp.Filename)
			}
		}

		resp, err := json.Marshal([]StreamResp{streamResp})
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

func parseSignature(msg string) string {
	return strings.TrimLeft(strings.TrimRight(msg, " FOUND\n"), "stream: ")
}

func readRequestBody(r *http.Request) (map[string][]byte, error) {
	requestMap := make(map[string][]byte)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	requestMap["request body"] = buf
	defer r.Body.Close()

	return requestMap, nil
}

func readMultipartForm(r *http.Request, maxFileSize int64) (map[string][]byte, error) {
	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		return nil, err
	}

	files := make(map[string][]byte)
	for key := range r.MultipartForm.File {
		for _, header := range r.MultipartForm.File[key] {
			file, err := header.Open()
			if err != nil {
				return nil, err
			}

			defer file.Close()

			buf, err := io.ReadAll(file)
			if err != nil {
				return nil, err
			}

			if header.Filename == "" {
				header.Filename = "request body"
			}

			files[header.Filename] = buf
		}
	}
	return files, nil
}

func virusFound(msg string) bool {
	return strings.HasSuffix(msg, "FOUND\n")
}

func isSizeWithinLimit(files map[string][]byte, maxFileSize int64) bool {
	for _, buf := range files {
		if int64(len(buf)) > maxFileSize {
			return false
		}
	}
	return true
}
