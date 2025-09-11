package handlers

import (
	"bytes"
	"clamav-rest/internal/clamav"
	"clamav-rest/internal/metrics"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

func (h *Handler) InStream(maxFileSize int64) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var ctx = r.Context()
		var streamResp = StreamResp{}

		buf, filename, err := readUpload(r, maxFileSize)
		if err != nil {
			metrics.RequestErrors.WithLabelValues("PATH", "/scan").Inc()
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if int64(len(buf)) > maxFileSize {
			http.Error(w, "file size exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}

		part := io.NopCloser(bytes.NewBuffer(buf))
		inStream, err := h.Clamav.InStream(ctx, part, int64(len(buf)))
		if err != nil {
			metrics.RequestErrors.WithLabelValues("PATH", "/scan").Inc()
			http.Error(w, "failed to scan file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if virusFound(string(inStream)) {
			streamResp = StreamResp{
				Filename: filename,
				//Message:   clamav.MsgVirusFound,
				//Signature: parseSignature(string(inStream)),
				Result: clamav.ResVirusFound,
			}
			log.Error().Msgf("virus %s found in file: %s", parseSignature(string(inStream)), streamResp.Filename)
			metrics.VirusesDiscovered.Inc()
		} else {
			streamResp = StreamResp{
				Filename: filename,
				//Message:   clamav.MsgVirusNotFound,
				//Signature: "",
				Result: clamav.ResVirusNotFound,
			}
			log.Debug().Msgf("no virus found in file: %s", streamResp.Filename)
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

func readUpload(r *http.Request, maxFileSize int64) ([]byte, string, error) {
	var buf []byte
	var err error
	var filename string

	switch {
	case r.Method == http.MethodPut:
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, "", err
		}
		defer r.Body.Close()
		filename = "request body"
	case r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
		if err := r.ParseMultipartForm(maxFileSize); err != nil {
			return nil, "", err
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			return nil, "", err
		}
		defer file.Close()
		filename = header.Filename
		buf, err = io.ReadAll(file)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", errors.New("invalid method or content type")
	}

	return buf, filename, nil
}

func virusFound(msg string) bool {
	return strings.HasSuffix(msg, "FOUND\n")
}
