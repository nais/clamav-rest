package clamav

var (
	ResVirusFound    = "FOUND"
	ResVirusNotFound = "OK"
)

// Error response types from ClamAV
const (
	ErrInvalidResponse    = "Invalid response"
	ErrScanFailure        = "Scan failure"
	ErrUnknownCommand     = "Unknown command"
	ErrUnsupportedCommand = "Unsupported command"
)
