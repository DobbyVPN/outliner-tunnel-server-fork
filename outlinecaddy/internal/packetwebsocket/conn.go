// Copyright 2026 DobbyVPN
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package packetwebsocket adapts WebSocket messages to packet-oriented net.Conn
// semantics. TLS packet servers also align each WebSocket header and packet
// payload with separate TLS application records for compatibility with released
// Outline clients.
package packetwebsocket

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxIncomingMessageSize = 64 * 1024
	maxTLSRecordPacketSize = 16 * 1024
)

var upgrader = websocket.Upgrader{
	WriteBufferSize:   maxTLSRecordPacketSize,
	EnableCompression: false,
}

// Upgrade accepts a WebSocket packet connection. When the HTTP request used
// TLS, outgoing WebSocket frames are written with their header and packet
// payload in separate TLS records. remoteAddr must be the UDP address used by
// the Shadowsocks association handler.
func Upgrade(w http.ResponseWriter, r *http.Request, remoteAddr *net.UDPAddr) (net.Conn, error) {
	nativeTLS := r.TLS != nil
	hijacker := &hijackResponseWriter{ResponseWriter: w}
	ws, err := upgrader.Upgrade(hijacker, r, nil)
	if err != nil {
		if hijacker.conn != nil {
			_ = hijacker.conn.Close()
		}
		return nil, err
	}
	if hijacker.conn == nil {
		_ = ws.Close()
		return nil, errors.New("WebSocket upgrader did not hijack the connection")
	}
	if nativeTLS {
		hijacker.conn.enableTLSRecordLayout()
	}
	ws.SetReadLimit(maxIncomingMessageSize)
	return &packetConn{ws: ws, wire: hijacker.conn, remoteAddr: remoteAddr, nativeTLS: nativeTLS}, nil
}

type hijackResponseWriter struct {
	http.ResponseWriter
	conn *recordConn
}

func (w *hijackResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.conn = &recordConn{Conn: conn}
	return w.conn, buffered, nil
}

type recordConn struct {
	net.Conn

	mu                  sync.Mutex
	active              bool
	applicationDeadline time.Time
	protocolDeadline    time.Time
	controlDeadlineSet  bool
	writeErr            error
}

func (c *recordConn) enableTLSRecordLayout() {
	c.mu.Lock()
	c.active = true
	c.mu.Unlock()
}

func (c *recordConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	active := c.active
	controlWrite := c.controlDeadlineSet
	writeErr := c.writeErr
	c.mu.Unlock()
	if controlWrite {
		defer func() {
			err = errors.Join(err, c.finishControlWrite())
		}()
	}
	if writeErr != nil {
		return 0, writeErr
	}
	if !active {
		return c.Conn.Write(p)
	}

	headerLength, payloadLength, err := validateServerFrame(p)
	if err != nil {
		return 0, c.failWrite(err)
	}
	if n, err := c.Conn.Write(p[:headerLength]); err != nil {
		return 0, c.failWrite(err)
	} else if n != headerLength {
		return 0, c.failWrite(io.ErrShortWrite)
	}
	if payloadLength > 0 {
		payload := p[headerLength:]
		if n, err := c.Conn.Write(payload); err != nil {
			return 0, c.failWrite(err)
		} else if n != payloadLength {
			return 0, c.failWrite(io.ErrShortWrite)
		}
	}
	return len(p), nil
}

func (c *recordConn) failWrite(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr == nil {
		c.writeErr = errors.Join(net.ErrClosed, err)
		_ = c.Conn.Close()
	}
	return c.writeErr
}

func validateServerFrame(frame []byte) (headerLength, payloadLength int, err error) {
	invalid := func() (int, int, error) {
		return 0, 0, errors.New("invalid outgoing WebSocket frame")
	}
	if len(frame) < 2 || frame[0]&0x80 == 0 || frame[0]&0x70 != 0 || frame[1]&0x80 != 0 {
		return invalid()
	}
	opcode := frame[0] & 0x0f
	if opcode != websocket.BinaryMessage && opcode != websocket.CloseMessage && opcode != websocket.PingMessage && opcode != websocket.PongMessage {
		return invalid()
	}

	payloadLength = int(frame[1] & 0x7f)
	headerLength = 2
	switch payloadLength {
	case 126:
		if len(frame) < 4 {
			return invalid()
		}
		payloadLength = int(frame[2])<<8 | int(frame[3])
		if payloadLength < 126 {
			return invalid()
		}
		headerLength = 4
	case 127:
		return invalid()
	}
	if payloadLength > maxTLSRecordPacketSize || len(frame) != headerLength+payloadLength {
		return invalid()
	}
	if opcode != websocket.BinaryMessage && payloadLength > 125 {
		return invalid()
	}
	return headerLength, payloadLength, nil
}

type packetConn struct {
	ws         *websocket.Conn
	wire       *recordConn
	remoteAddr *net.UDPAddr
	nativeTLS  bool

	readMu    sync.Mutex
	writeMu   sync.Mutex
	stateMu   sync.Mutex
	readErr   error
	closeOnce sync.Once
}

var _ net.Conn = (*packetConn)(nil)

func (c *packetConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.terminalError(); err != nil {
		return 0, err
	}

	messageType, reader, err := c.ws.NextReader()
	if err != nil {
		if closeErr, ok := err.(*websocket.CloseError); ok && (closeErr.Code == websocket.CloseNormalClosure || closeErr.Code == websocket.CloseGoingAway) {
			c.abort(io.EOF)
			return 0, io.EOF
		}
		return 0, c.abort(errors.Join(net.ErrClosed, err))
	}
	if messageType != websocket.BinaryMessage {
		c.sendClose(websocket.CloseUnsupportedData, "binary messages required")
		return 0, c.abort(errors.Join(net.ErrClosed, errors.New("WebSocket packet message is not binary")))
	}

	message, err := io.ReadAll(io.LimitReader(reader, maxIncomingMessageSize+1))
	if err != nil {
		return 0, c.abort(errors.Join(net.ErrClosed, err))
	}
	if len(message) > maxIncomingMessageSize {
		c.sendClose(websocket.CloseMessageTooBig, "packet too large")
		return 0, c.abort(errors.Join(net.ErrClosed, errors.New("WebSocket packet message exceeds 64 KiB")))
	}
	if len(message) == 0 {
		c.sendClose(websocket.ClosePolicyViolation, "empty packet")
		return 0, c.abort(errors.Join(net.ErrClosed, errors.New("empty WebSocket packet message")))
	}
	if len(message) > len(p) {
		c.sendClose(websocket.ClosePolicyViolation, "packet buffer too small")
		return 0, c.abort(errors.Join(net.ErrClosed, io.ErrShortBuffer))
	}
	return copy(p, message), nil
}

func (c *packetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.terminalError(); err != nil {
		return 0, err
	}
	if c.nativeTLS && len(p) > maxTLSRecordPacketSize {
		return 0, io.ErrShortBuffer
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) sendClose(code int, reason string) {
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
}

func (c *packetConn) abort(err error) error {
	c.stateMu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	terminal := c.readErr
	c.stateMu.Unlock()
	c.closeOnce.Do(func() { _ = c.wire.Close() })
	return terminal
}

func (c *packetConn) terminalError() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.readErr
}

func (c *packetConn) Close() error {
	c.stateMu.Lock()
	alreadyClosed := c.readErr != nil
	if !alreadyClosed {
		c.readErr = net.ErrClosed
	}
	c.stateMu.Unlock()
	if !alreadyClosed {
		_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	}
	var closeErr error
	c.closeOnce.Do(func() { closeErr = c.wire.Close() })
	return closeErr
}

func (c *packetConn) LocalAddr() net.Addr { return c.ws.LocalAddr() }

func (c *packetConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *packetConn) SetDeadline(t time.Time) error {
	return errors.Join(c.ws.SetReadDeadline(t), c.wire.setApplicationWriteDeadline(t))
}

func (c *packetConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return c.wire.setApplicationWriteDeadline(t)
}

func (c *recordConn) SetDeadline(t time.Time) error {
	return errors.Join(c.Conn.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *recordConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.protocolDeadline = t
	c.controlDeadlineSet = true
	return c.applyWriteDeadlineLocked()
}

func (c *recordConn) setApplicationWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applicationDeadline = t
	return c.applyWriteDeadlineLocked()
}

func (c *recordConn) applyWriteDeadlineLocked() error {
	deadline := c.applicationDeadline
	if !c.protocolDeadline.IsZero() && (deadline.IsZero() || c.protocolDeadline.Before(deadline)) {
		deadline = c.protocolDeadline
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *recordConn) finishControlWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.protocolDeadline = time.Time{}
	c.controlDeadlineSet = false
	return c.applyWriteDeadlineLocked()
}
