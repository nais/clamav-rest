package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func (m *MockClamav) Ping(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func TestPing(t *testing.T) {
	mockClamav := new(MockClamav)
	handler := &Handler{Clamav: mockClamav}

	mockResponse := []byte("PONG")
	mockClamav.On("Ping", mock.Anything).Return(mockResponse, nil)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()

	handler.Ping(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode, "expected status code 200")

	var actualBody map[string]string
	err := json.NewDecoder(res.Body).Decode(&actualBody)
	require.NoError(t, err, "failed to decode response body")

	expectedBody := map[string]string{"ping": "PONG"}
	require.Equal(t, expectedBody, actualBody, "response body mismatch")

	mockClamav.AssertExpectations(t)
}
