package clamav

import (
	"bufio"
	"bytes"
	"clamav-rest/internal/metrics"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

type ClamClient struct {
	dialer  net.Dialer
	address string
	network string
	conn    net.Conn
}

type Clamav interface {
	Ping(ctx context.Context) ([]byte, error)
	Version(ctx context.Context) ([]byte, error)
	InStream(ctx context.Context, r io.Reader, size int64) ([]byte, error)
}

var _ Clamav = (*ClamClient)(nil)

func NewClamClient(endpoint string, timeout, keepalive time.Duration) *ClamClient {
	return &ClamClient{
		dialer: net.Dialer{
			Timeout:   timeout,
			KeepAlive: keepalive,
		},
		address: endpoint,
		network: "tcp",
		conn:    nil,
	}

}

func (c *ClamClient) Ping(ctx context.Context) ([]byte, error) {
	metrics.RequestCount.WithLabelValues("ping").Inc()
	conn, err := c.connect(ctx)
	if err != nil {
		metrics.RequestErrors.WithLabelValues("ping").Inc()
		return nil, fmt.Errorf("failed connecting to %s: %w", c.address, err)
	}

	resp, err := c.sendCommand(conn, CmdPing)
	if err != nil {
		return nil, fmt.Errorf("failed sending command to %s: %w", c.address, err)
	}

	err = c.parseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed parsing response from %s: %w", c.address, err)
	}
	return resp, nil
}

func (c *ClamClient) Version(ctx context.Context) ([]byte, error) {
	metrics.RequestCount.WithLabelValues("version").Inc()
	conn, err := c.connect(ctx)
	if err != nil {
		metrics.RequestErrors.WithLabelValues("version").Inc()
		return nil, fmt.Errorf("failed connecting to %s: %w", c.address, err)
	}

	resp, err := c.sendCommand(conn, CmdVersion)
	if err != nil {
		return nil, fmt.Errorf("failed sending command to %s: %w", c.address, err)
	}

	err = c.parseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed parsing response from %s: %w", c.address, err)
	}
	return resp, nil
}

func (c *ClamClient) InStream(ctx context.Context, r io.Reader, size int64) ([]byte, error) {
	metrics.RequestCount.WithLabelValues("scan").Inc()
	conn, err := c.connect(ctx)
	if err != nil {
		metrics.RequestErrors.WithLabelValues("scan").Inc()
		return nil, fmt.Errorf("failed dialing %s/%s: %w", c.network, c.address, err)
	}

	reader := bufio.NewReaderSize(r, 2048)
	writer := bufio.NewWriter(conn)

	if _, err := writer.Write(CmdInstream); err != nil {
		return nil, fmt.Errorf("failed writing command to %s/%s: %w", c.network, c.address, err)
	}

	if size < 0 || size > math.MaxUint32 {
		return nil, fmt.Errorf("size %d is out of range for uint32", size)
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(size))
	if _, err := writer.Write(b); err != nil {
		return nil, fmt.Errorf("failed writing data length to %s: %w", c.address, err)
	}

	if _, err := reader.WriteTo(writer); err != nil {
		return nil, fmt.Errorf("failed streaming content to %s: %w", c.address, err)
	}

	if _, err := writer.Write([]byte{'\000', '\000', '\000', '\000'}); err != nil {
		return nil, fmt.Errorf("failed writing transfer signal to %s: %w", c.address, err)
	}

	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("failed flushing writer to %s: %w", c.address, err)
	}

	resp, err := c.readResponse(conn)
	if err != nil {
		return nil, err
	}

	if err := c.parseResponse(resp); err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *ClamClient) sendCommand(conn net.Conn, cmd []byte) ([]byte, error) {
	writer := bufio.NewWriter(conn)

	_, err := writer.Write(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed writing command to %s: %w", c.address, err)
	}

	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("failed sending command to %s: %w", c.address, err)
	}

	resp, err := c.readResponse(conn)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *ClamClient) connect(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, c.network, c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", c.address, err)
	}

	return conn, nil
}

func (c *ClamClient) readResponse(r io.Reader) ([]byte, error) {
	reader := bufio.NewReader(r)

	resp, err := reader.ReadBytes('\000')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed reading response from %s: %w", c.address, err)
	}

	return bytes.TrimSuffix(resp, []byte("\000")), nil
}

func (c *ClamClient) parseResponse(msg []byte) error {
	if bytes.EqualFold(msg, []byte(ResErrScanLimit)) {
		return fmt.Errorf("scan limit exceeded: %s", msg)
	}

	if bytes.HasPrefix(msg, []byte("stream: ")) && bytes.HasSuffix(msg, []byte("FOUND")) {
		return errors.New("file contains potential virus")
	}

	if bytes.Equal(msg, []byte(ResErrUnknown)) {
		return fmt.Errorf("unknown error occured: %s", msg)
	}

	return nil
}
