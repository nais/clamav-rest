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
)

func (h *Handler) InStream(maxFileSize int64) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err   error
			files map[string][]byte
		)

		switch {
		case r.Method == http.MethodPut:
			files, err = readRequestBody(r)
		case r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
			files, err = readMultipartForm(r, maxFileSize)
		default:
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "unsupported method or content type", http.StatusBadRequest)
			return
		}
		if err != nil {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if !isSizeWithinLimit(files, maxFileSize) {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "file size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}

		// Initialize with empty slice to ensure we return [] instead of null
		responses := make([]StreamResp, 0, len(files))

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
			metrics.ScanDuration.WithLabelValues(r.Method, "/scan").Observe(scanDuration)
			metrics.RequestCount.WithLabelValues(r.Method, "/scan").Inc()

			streamResp := StreamResp{
				Filename: filename,
				Result:   clamav.ResVirusNotFound,
			}
			if virusFound(string(inStream)) {
				streamResp.Result = clamav.ResVirusFound
				h.Logger.Info().Msgf("virus %s found in file: %s", parseSignature(string(inStream)), streamResp.Filename)
				metrics.VirusesDiscovered.Inc()
			} else {
				h.Logger.Debug().Msgf("no virus found in file: %s", streamResp.Filename)
			}
			responses = append(responses, streamResp)
		}

		resp, err := json.Marshal(responses)
		if err != nil {
			http.Error(w, "failed to marshal response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resp); err != nil {
			h.Logger.Error().Msgf("Error writing response: %v", err)
			http.Error(w, "failed to write response: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (h *Handler) InStreamV2(maxFileSize int64) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err   error
			files map[string][]byte
		)

		switch {
		case r.Method == http.MethodPut:
			files, err = readRequestBody(r)
		case r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
			files, err = readMultipartForm(r, maxFileSize)
		default:
			metrics.RequestErrors.WithLabelValues(r.Method, "/api/v2/scan").Inc()
			http.Error(w, "unsupported method or content type", http.StatusBadRequest)
			return
		}
		if err != nil {
			metrics.RequestErrors.WithLabelValues(r.Method, "/api/v2/scan").Inc()
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if !isSizeWithinLimit(files, maxFileSize) {
			metrics.RequestErrors.WithLabelValues(r.Method, "/api/v2/scan").Inc()
			http.Error(w, "file size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}

		// Initialize with empty slice to ensure we return [] instead of null
		responses := make([]StreamRespV2, 0, len(files))

		for filename, buf := range files {
			part := io.NopCloser(bytes.NewBuffer(buf))
			start := time.Now()
			inStream, err := h.Clamav.InStream(r.Context(), part, int64(len(buf)))

			scanDuration := time.Since(start).Seconds()
			metrics.ScanDuration.WithLabelValues(r.Method, "/api/v2/scan").Observe(scanDuration)
			metrics.RequestCount.WithLabelValues(r.Method, "/api/v2/scan").Inc()

			streamResp := StreamRespV2{
				Filename: filename,
				Result:   clamav.ResVirusNotFound,
				Virus:    "",
				Error:    "",
			}

			// Check if there was a connection/scan error
			if err != nil {
				streamResp.Result = "ERROR"
				streamResp.Error = clamav.ErrScanFailure
				h.Logger.Error().Msgf("scan error for file %s: %v", filename, err)
				metrics.RequestErrors.WithLabelValues(r.Method, "/api/v2/scan").Inc()
				responses = append(responses, streamResp)
				continue
			}

			responseStr := string(inStream)

			// Check for ClamAV error responses
			if isErrorResponse(responseStr) {
				streamResp.Result = "ERROR"
				streamResp.Error = parseErrorType(responseStr)
				h.Logger.Warn().Msgf("ClamAV error for file %s: %s (response: %s)", filename, streamResp.Error, responseStr)
				responses = append(responses, streamResp)
				continue
			}

			// Check for virus
			if virusFound(responseStr) {
				streamResp.Result = clamav.ResVirusFound
				streamResp.Virus = parseSignature(responseStr)
				h.Logger.Info().Msgf("virus %s found in file: %s", streamResp.Virus, streamResp.Filename)
				metrics.VirusesDiscovered.Inc()
			} else {
				h.Logger.Debug().Msgf("no virus found in file: %s", streamResp.Filename)
			}

			responses = append(responses, streamResp)
		}

		resp, err := json.Marshal(responses)
		if err != nil {
			http.Error(w, "failed to marshal response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resp); err != nil {
			h.Logger.Error().Msgf("Error writing response: %v", err)
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

// parseErrorType detects ClamAV error responses and returns the appropriate error message
func parseErrorType(msg string) string {
	msgLower := strings.ToLower(strings.TrimSpace(msg))

	switch {
	case strings.Contains(msgLower, "unknown command"):
		return clamav.ErrUnknownCommand
	case strings.Contains(msgLower, "unsupported"):
		return clamav.ErrUnsupportedCommand
	case strings.Contains(msgLower, "error"):
		return clamav.ErrScanFailure
	case msg == "" || (!strings.HasSuffix(msg, "FOUND\n") && !strings.HasPrefix(msg, "stream: ")):
		return clamav.ErrInvalidResponse
	default:
		return ""
	}
}

// isErrorResponse checks if the ClamAV response indicates an error
func isErrorResponse(msg string) bool {
	return parseErrorType(msg) != ""
}

func isSizeWithinLimit(files map[string][]byte, maxFileSize int64) bool {
	for _, buf := range files {
		if int64(len(buf)) > maxFileSize {
			return false
		}
	}
	return true
}
