package handlers

import (
	"bytes"
	"context"
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

func TestInStreamHandler(t *testing.T) {
	logger := &zerolog.Logger{}               // Use a no-op logger for testing
	maxRequestSize := int64(10 * 1024 * 1024) // 10 MB

	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   string
		fileContent    []byte
		fileName       string
		mockError      error
		mockResponse   []byte
	}{
		{
			name:           "file size exceeds limit",
			expectedBody:   "file size exceeds limit",
			expectedStatus: http.StatusRequestEntityTooLarge,
			fileContent:    make([]byte, maxRequestSize+1),
			fileName:       "test.txt",
			mockError:      nil,
			mockResponse:   nil,
		},
		{
			name:           "successful file scan",
			expectedBody:   "OK",
			expectedStatus: http.StatusOK,
			fileContent:    []byte("test content"),
			fileName:       "test 1.txt",
			mockError:      nil,
			mockResponse:   []byte("OK"),
		},
		{
			name:           "error during file scan",
			expectedBody:   "failed to scan file",
			expectedStatus: http.StatusInternalServerError,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockError:      assert.AnError,
			mockResponse:   nil,
		},
		{
			name:           "virus found in file",
			expectedBody:   "FOUND",
			expectedStatus: http.StatusOK,
			fileContent:    []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
			fileName:       "eicar.com",
			mockError:      nil,
			mockResponse:   []byte("stream: EICAR-TEST-STRING FOUND\n"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockClamav := new(MockClamav)
			handler := NewHandler(logger, mockClamav)

			if tc.mockError != nil || tc.mockResponse != nil {
				mockClamav.On("InStream", mock.Anything, mock.Anything, mock.Anything).Return(tc.mockResponse, tc.mockError)
			}

			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("file", tc.fileName)
			assert.NoError(t, err)

			part.Write(tc.fileContent)
			writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/scan", body)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			rr := httptest.NewRecorder()
			h := handler.InStream(maxRequestSize)
			h(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tc.expectedBody)
			mockClamav.AssertExpectations(t)
		})
	}

}
