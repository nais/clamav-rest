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
	Filename  string `json:"Filename"`
	Message   string `json:"Message"`
	Signature string `json:"Signature"`
	Result    string `json:"Result"`
}

func NewHandler(logger *zerolog.Logger, clamav clamav.Clamav) *Handler {
	return &Handler{Logger: logger, Clamav: clamav}
}
