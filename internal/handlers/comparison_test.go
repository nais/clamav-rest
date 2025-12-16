package handlers_test

import (
	"bytes"
	"clamav-rest/internal/clamav"
	"clamav-rest/internal/handlers"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClamav struct {
	mock.Mock
}

func (m *MockClamav) InStream(ctx context.Context, r io.Reader, size int64) ([]byte, error) {
	args := m.Called(ctx, r, size)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockClamav) Ping(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockClamav) Version(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

// TestV1vsV2Comparison demonstrates that V1 and V2 are completely separate
func TestV1vsV2Comparison(t *testing.T) {
	logger := &zerolog.Logger{}
	maxRequestSize := int64(10 * 1024 * 1024)

	t.Run("V1 and V2 have different response structures", func(t *testing.T) {
		mockClamav := new(MockClamav)
		handler := handlers.NewHandler(logger, mockClamav)

		// Mock successful scan
		mockClamav.On("InStream", mock.Anything, mock.Anything, mock.Anything).
			Return([]byte("stream: OK\n"), nil)

		testFile := []byte("test content")

		// Test V1
		body1 := &bytes.Buffer{}
		writer1 := multipart.NewWriter(body1)
		part1, _ := writer1.CreateFormFile("file", "test.txt")
		part1.Write(testFile)
		writer1.Close()

		req1 := httptest.NewRequest(http.MethodPost, "/scan", body1)
		req1.Header.Set("Content-Type", writer1.FormDataContentType())
		rr1 := httptest.NewRecorder()

		h1 := handler.InStream(maxRequestSize)
		h1(rr1, req1)

		// Test V2
		mockClamav2 := new(MockClamav)
		handler2 := handlers.NewHandler(logger, mockClamav2)
		mockClamav2.On("InStream", mock.Anything, mock.Anything, mock.Anything).
			Return([]byte("stream: OK\n"), nil)

		body2 := &bytes.Buffer{}
		writer2 := multipart.NewWriter(body2)
		part2, _ := writer2.CreateFormFile("file", "test.txt")
		part2.Write(testFile)
		writer2.Close()

		req2 := httptest.NewRequest(http.MethodPost, "/api/v2/scan", body2)
		req2.Header.Set("Content-Type", writer2.FormDataContentType())
		rr2 := httptest.NewRecorder()

		h2 := handler2.InStreamV2(maxRequestSize)
		h2(rr2, req2)

		// Parse responses
		var v1Response []map[string]interface{}
		var v2Response []map[string]interface{}

		err1 := json.Unmarshal(rr1.Body.Bytes(), &v1Response)
		err2 := json.Unmarshal(rr2.Body.Bytes(), &v2Response)

		assert.NoError(t, err1)
		assert.NoError(t, err2)

		// V1 should have only Filename and Result (uppercase)
		assert.Len(t, v1Response, 1)
		assert.Contains(t, v1Response[0], "Filename")
		assert.Contains(t, v1Response[0], "Result")
		assert.NotContains(t, v1Response[0], "filename") // lowercase not present
		assert.NotContains(t, v1Response[0], "virus")
		assert.NotContains(t, v1Response[0], "error")

		// V2 should have filename, result, virus, and error (lowercase)
		assert.Len(t, v2Response, 1)
		assert.Contains(t, v2Response[0], "filename")
		assert.Contains(t, v2Response[0], "result")
		assert.Contains(t, v2Response[0], "virus")
		assert.Contains(t, v2Response[0], "error")
		assert.NotContains(t, v2Response[0], "Filename") // uppercase not present

		// Verify field names match expected case
		assert.Equal(t, "test.txt", v1Response[0]["Filename"])
		assert.Equal(t, "test.txt", v2Response[0]["filename"])
	})

	t.Run("V1 fails entire request on error, V2 continues", func(t *testing.T) {
		mockClamav := new(MockClamav)
		handler := handlers.NewHandler(logger, mockClamav)

		// Mock scan error
		mockClamav.On("InStream", mock.Anything, mock.Anything, mock.Anything).
			Return([]byte(nil), assert.AnError)

		testFile := []byte("test content")

		// Test V1 - should return HTTP 500
		body1 := &bytes.Buffer{}
		writer1 := multipart.NewWriter(body1)
		part1, _ := writer1.CreateFormFile("file", "test.txt")
		part1.Write(testFile)
		writer1.Close()

		req1 := httptest.NewRequest(http.MethodPost, "/scan", body1)
		req1.Header.Set("Content-Type", writer1.FormDataContentType())
		rr1 := httptest.NewRecorder()

		h1 := handler.InStream(maxRequestSize)
		h1(rr1, req1)

		// V1 returns 500 on error
		assert.Equal(t, http.StatusInternalServerError, rr1.Code)

		// Test V2 - should return HTTP 200 with error in response
		mockClamav2 := new(MockClamav)
		handler2 := handlers.NewHandler(logger, mockClamav2)
		mockClamav2.On("InStream", mock.Anything, mock.Anything, mock.Anything).
			Return([]byte(nil), assert.AnError)

		body2 := &bytes.Buffer{}
		writer2 := multipart.NewWriter(body2)
		part2, _ := writer2.CreateFormFile("file", "test.txt")
		part2.Write(testFile)
		writer2.Close()

		req2 := httptest.NewRequest(http.MethodPost, "/api/v2/scan", body2)
		req2.Header.Set("Content-Type", writer2.FormDataContentType())
		rr2 := httptest.NewRecorder()

		h2 := handler2.InStreamV2(maxRequestSize)
		h2(rr2, req2)

		// V2 returns 200 with error field populated
		assert.Equal(t, http.StatusOK, rr2.Code)

		var v2Response []map[string]interface{}
		json.Unmarshal(rr2.Body.Bytes(), &v2Response)

		assert.Len(t, v2Response, 1)
		assert.Equal(t, "ERROR", v2Response[0]["result"])
		assert.Equal(t, clamav.ErrScanFailure, v2Response[0]["error"])
	})
}
