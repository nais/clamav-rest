package handlers

import (
	"clamav-rest/internal/clamav"

	"github.com/rs/zerolog"
)

type Handler struct {
	Clamav clamav.Clamav
	Logger *zerolog.Logger
}

type StreamResp struct {
	Filename string `json:"Filename"`
	Result   string `json:"Result"`
}

// StreamRespV2 is the v2 API response with additional virus information
type StreamRespV2 struct {
	Filename string `json:"filename"`
	Result   string `json:"result"`
	Virus    string `json:"virus"` // Name of the virus if found, empty otherwise
	Error    string `json:"error"` // Error message if scan failed, empty otherwise
}

func NewHandler(logger *zerolog.Logger, clamav clamav.Clamav) *Handler {
	return &Handler{Logger: logger, Clamav: clamav}
}
