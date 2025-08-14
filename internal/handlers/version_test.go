package handlers

import (
	"context"
)

func (m *MockClamav) Version(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}
