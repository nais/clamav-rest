package handlers

import (
	"bytes"
	"clamav-rest/internal/clamav"
	"clamav-rest/internal/metrics"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
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
			for key := range r.MultipartForm.File {
				h.Logger.Info().Msgf("multipart form file key: %s", key)
				for _, header := range r.MultipartForm.File[key] {
					h.Logger.Info().Msgf("multipart form file header: %+v", header)
				}
			}
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

		if files == nil {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "no files to scan", http.StatusBadRequest)
			return
		}

		if !isSizeWithinLimit(files, maxFileSize) {
			metrics.RequestErrors.WithLabelValues(r.Method, "/scan").Inc()
			http.Error(w, "file size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}

		var responses []StreamResp
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

			filename := decodeFilename(header)
			if filename == "" {
				filename = "request body"
			}

			files[filename] = buf
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

func decodeFilename(header *multipart.FileHeader) string {
	cd := header.Header.Get("Content-Disposition")
	_, params, err := mime.ParseMediaType(cd)
	if err == nil {
		if fn, ok := params["filename*"]; ok {
			if strings.HasPrefix(fn, "utf-8''") {
				decoded, err := url.QueryUnescape(fn[7:])
				if err == nil {
					return decoded
				}
			}
		}
		if fn, ok := params["filename"]; ok {
			// Try UTF-8 first
			if isUTF8(fn) {
				return fn
			}
			// Fallback: try ISO-8859-1
			decoded, err := charmap.ISO8859_1.NewDecoder().String(fn)
			if err == nil {
				return decoded
			}
		}
	}
	return header.Filename
}

func isUTF8(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		i += size
	}
	return true
}
