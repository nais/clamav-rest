package handlers

import (
	"clamav-rest/internal/clamav"
	"github.com/rs/zerolog"
)

type Handler struct {
	Clamav clamav.Clamav
	Logger *zerolog.Logger
}

func NewHandler(logger *zerolog.Logger, clamav clamav.Clamav) *Handler {
	return &Handler{Logger: logger, Clamav: clamav}
}
