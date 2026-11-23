package handlers

import (
	"bytes"
	"clamav-rest/internal/clamav"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func TestInStreamV2Handler(t *testing.T) {
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
		expectVirus    string
		expectError    string
	}{
		{
			name:           "file size exceeds limit",
			expectedBody:   "file size exceeds limit",
			expectedStatus: http.StatusRequestEntityTooLarge,
			fileContent:    make([]byte, maxRequestSize+1),
			fileName:       "test.txt",
			mockError:      nil,
			mockResponse:   nil,
			expectVirus:    "",
			expectError:    "",
		},
		{
			name:           "successful file scan - no virus",
			expectedBody:   `"result":"OK"`,
			expectedStatus: http.StatusOK,
			fileContent:    []byte("test content"),
			fileName:       "test 1.txt",
			mockError:      nil,
			mockResponse:   []byte("stream: OK\n"),
			expectVirus:    "",
			expectError:    "",
		},
		{
			name:           "scan failure error",
			expectedBody:   `"result":"ERROR"`,
			expectedStatus: http.StatusServiceUnavailable,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockError:      assert.AnError,
			mockResponse:   nil,
			expectVirus:    "",
			expectError:    "Scan failure",
		},
		{
			name:           "virus found in file",
			expectedBody:   `"result":"FOUND"`,
			expectedStatus: http.StatusOK,
			fileContent:    []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
			fileName:       "eicar.com",
			mockError:      nil,
			mockResponse:   []byte("stream: EICAR-TEST-STRING FOUND\n"),
			expectVirus:    "EICAR-TEST-STRING",
			expectError:    "",
		},
		{
			name:           "empty file upload returns empty array",
			expectedBody:   "[]",
			expectedStatus: http.StatusOK,
			fileContent:    []byte(""),
			fileName:       "",
			mockError:      nil,
			mockResponse:   nil,
			expectVirus:    "",
			expectError:    "",
		},
		{
			name:           "unknown command error",
			expectedBody:   `"error":"Unknown command"`,
			expectedStatus: http.StatusServiceUnavailable,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockError:      nil,
			mockResponse:   []byte("UNKNOWN COMMAND\n"),
			expectVirus:    "",
			expectError:    "Unknown command",
		},
		{
			name:           "unsupported command error",
			expectedBody:   `"error":"Unsupported command"`,
			expectedStatus: http.StatusServiceUnavailable,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockError:      nil,
			mockResponse:   []byte("UNSUPPORTED\n"),
			expectVirus:    "",
			expectError:    "Unsupported command",
		},
		{
			name:           "invalid response error",
			expectedBody:   `"error":"Invalid response"`,
			expectedStatus: http.StatusServiceUnavailable,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockError:      nil,
			mockResponse:   []byte(""),
			expectVirus:    "",
			expectError:    "Invalid response",
		},
		{
			name:           "daemon scan error",
			expectedBody:   `"result":"ERROR"`,
			expectedStatus: http.StatusServiceUnavailable,
			fileContent:    []byte("test content"),
			fileName:       "test.txt",
			mockResponse:   []byte("stream: scan failed ERROR\n"),
			expectError:    "Scan failure",
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

			if tc.fileName != "" {
				part, err := writer.CreateFormFile("file", tc.fileName)
				assert.NoError(t, err)
				part.Write(tc.fileContent)
			}

			writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/api/v2/scan", body)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			rr := httptest.NewRecorder()
			h := handler.InStreamV2(maxRequestSize)
			h(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tc.expectedBody)

			if tc.expectVirus != "" {
				assert.Contains(t, rr.Body.String(), tc.expectVirus)
			}

			if tc.expectError != "" {
				assert.Contains(t, rr.Body.String(), tc.expectError)
			}

			mockClamav.AssertExpectations(t)
		})
	}
}

func TestInStreamV2PutScanFailure(t *testing.T) {
	logger := zerolog.Nop()
	mockClamav := new(MockClamav)
	mockClamav.On("InStream", mock.MatchedBy(func(ctx context.Context) bool {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		return ok && remaining > 89*time.Second && remaining <= 90*time.Second
	}), mock.Anything, mock.Anything).
		Return([]byte(nil), assert.AnError).Once()
	handler := NewHandler(&logger, mockClamav)
	req := httptest.NewRequest(http.MethodPut, "/api/v2/scan", bytes.NewBufferString("test content"))
	rr := httptest.NewRecorder()

	handler.InStreamV2(1024)(rr, req)

	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	require.JSONEq(t, `[{"filename":"request body","result":"ERROR","virus":"","error":"Scan failure"}]`, rr.Body.String())
	mockClamav.AssertExpectations(t)
}

func TestInStreamV2DaemonClosesWithoutResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	content := "test content"
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverErr <- err
			return
		}
		request := make([]byte, len(clamav.CmdInstream)+4+len(content)+4)
		_, err = io.ReadFull(conn, request)
		serverErr <- err
	}()

	logger := zerolog.Nop()
	client := clamav.NewClamClient(listener.Addr().String(), time.Second, time.Second)
	handler := NewHandler(&logger, client)
	req := httptest.NewRequest(http.MethodPut, "/api/v2/scan", bytes.NewBufferString(content))
	rr := httptest.NewRecorder()

	handler.InStreamV2(1024)(rr, req)

	require.NoError(t, <-serverErr)
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	require.JSONEq(t, `[{"filename":"request body","result":"ERROR","virus":"","error":"Invalid response"}]`, rr.Body.String())
}

func TestInStreamV2DaemonReadTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	content := "test content"
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverErr <- err
			return
		}
		request := make([]byte, len(clamav.CmdInstream)+4+len(content)+4)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Read(make([]byte, 1))
		if err == io.EOF {
			err = nil
		}
		serverErr <- err
	}()

	logger := zerolog.Nop()
	client := clamav.NewClamClient(listener.Addr().String(), time.Second, time.Second)
	handler := NewHandler(&logger, client)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPut, "/api/v2/scan", bytes.NewBufferString(content)).WithContext(ctx)
	rr := httptest.NewRecorder()
	start := time.Now()

	handler.InStreamV2(1024)(rr, req)

	require.Less(t, time.Since(start), 2*time.Second)
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	require.JSONEq(t, `[{"filename":"request body","result":"ERROR","virus":"","error":"Scan failure"}]`, rr.Body.String())
	require.NoError(t, <-serverErr)
}

func TestInStreamV2MixedScanResults(t *testing.T) {
	logger := zerolog.Nop()
	mockClamav := new(MockClamav)
	mockClamav.On("InStream", mock.Anything, mock.Anything, int64(5)).
		Return([]byte("stream: OK\n"), nil).Once()
	mockClamav.On("InStream", mock.Anything, mock.Anything, int64(6)).
		Return([]byte(nil), assert.AnError).Once()
	handler := NewHandler(&logger, mockClamav)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for _, file := range []struct {
		name    string
		content string
	}{
		{name: "clean.txt", content: "clean"},
		{name: "failed.txt", content: "failed"},
	} {
		part, err := writer.CreateFormFile("file", file.name)
		require.NoError(t, err)
		_, err = part.Write([]byte(file.content))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	req := httptest.NewRequest(http.MethodPost, "/api/v2/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.InStreamV2(1024)(rr, req)

	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	var responses []StreamRespV2
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &responses))
	require.ElementsMatch(t, []StreamRespV2{
		{Filename: "clean.txt", Result: clamav.ResVirusNotFound},
		{Filename: "failed.txt", Result: "ERROR", Error: clamav.ErrScanFailure},
	}, responses)
	mockClamav.AssertExpectations(t)
}
