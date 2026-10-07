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

package packetwebsocket

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func testTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunnel.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		DNSNames:              []string{"tunnel.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(
		pemEncode("CERTIFICATE", der),
		pemEncode("EC PRIVATE KEY", keyDER),
	)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool.AddCert(parsed)
	return certificate, pool
}

func pemEncode(kind string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data})
}

func TestValidateServerFrame(t *testing.T) {
	for _, size := range []int{0, 1, 125, 126, 1335, 4092, 4093, 8192, 16384} {
		frame := serverFrame(bytes.Repeat([]byte{0xa5}, size))
		headerLength, payloadLength, err := validateServerFrame(frame)
		require.NoError(t, err, "size %d", size)
		require.Equal(t, size, payloadLength)
		if size < 126 {
			require.Equal(t, 2, headerLength)
		} else {
			require.Equal(t, 4, headerLength)
		}
	}

	for name, frame := range map[string][]byte{
		"empty":        nil,
		"fragmented":   {0x02, 0x01, 0xaa},
		"masked":       {0x82, 0x81, 0, 0, 0, 0, 0xaa},
		"reserved":     {0x92, 0x01, 0xaa},
		"text":         {0x81, 0x01, 0xaa},
		"noncanonical": {0x82, 126, 0, 1, 0xaa},
		"oversized":    serverFrame(bytes.Repeat([]byte{0}, maxTLSRecordPacketSize+1)),
		"concatenated": append(serverFrame([]byte{1}), serverFrame([]byte{2})...),
		"length127":    {0x82, 127, 0, 0, 0, 0, 0, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := validateServerFrame(frame)
			require.Error(t, err)
		})
	}
}

func TestTLSRecordConnSeparatesHeaderAndPayload(t *testing.T) {
	certificate, roots := testTLSCertificate(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, size := range []int{84, 1335, maxTLSRecordPacketSize} {
			t.Run(tls.VersionName(version)+"/"+strconv.Itoa(size), func(t *testing.T) {
				serverRaw, clientRaw := net.Pipe()
				require.NoError(t, serverRaw.SetDeadline(time.Now().Add(5*time.Second)))
				require.NoError(t, clientRaw.SetDeadline(time.Now().Add(5*time.Second)))
				serverTLS := tls.Server(serverRaw, &tls.Config{
					Certificates:                []tls.Certificate{certificate},
					MinVersion:                  version,
					MaxVersion:                  version,
					DynamicRecordSizingDisabled: true,
				})
				clientTLS := tls.Client(clientRaw, &tls.Config{
					RootCAs:    roots,
					ServerName: "tunnel.test",
					MinVersion: version,
					MaxVersion: version,
				})
				handshakeErr := make(chan error, 1)
				go func() { handshakeErr <- clientTLS.Handshake() }()
				require.NoError(t, serverTLS.Handshake())
				require.NoError(t, <-handshakeErr)
				t.Cleanup(func() {
					_ = serverRaw.Close()
					_ = clientRaw.Close()
				})

				payload := bytes.Repeat([]byte{0x5a}, size)
				frame := serverFrame(payload)
				wire := &recordConn{Conn: serverTLS}
				wire.enableTLSRecordLayout()
				writeErr := make(chan error, 1)
				go func() {
					n, err := wire.Write(frame)
					if err == nil && n != len(frame) {
						err = io.ErrShortWrite
					}
					writeErr <- err
				}()

				header := make([]byte, 4)
				n, err := clientTLS.Read(header)
				require.NoError(t, err)
				headerLength := 2
				if size >= 126 {
					headerLength = 4
				}
				require.Equal(t, headerLength, n)
				require.Equal(t, frame[:headerLength], header[:n])
				body := make([]byte, size)
				n, err = clientTLS.Read(body)
				require.NoError(t, err)
				require.Equal(t, size, n)
				require.Equal(t, payload, body[:n])
				require.NoError(t, <-writeErr)
			})
		}
	}
}

func TestReadWaitsForWholeWebSocketMessage(t *testing.T) {
	resultCh := make(chan readResult, 1)
	server := newPacketTestServer(t, false, 256, resultCh, nil)
	client := dialPacketTestClient(t, server, false, 1)
	defer client.Close()

	writer, err := client.NextWriter(websocket.BinaryMessage)
	require.NoError(t, err)
	first := bytes.Repeat([]byte{0x31}, 63)
	second := bytes.Repeat([]byte{0x72}, 21)
	_, err = writer.Write(first)
	require.NoError(t, err)
	select {
	case result := <-resultCh:
		t.Fatalf("server returned an incomplete message: %d bytes, %v", result.n, result.err)
	case <-time.After(30 * time.Millisecond):
	}
	_, err = writer.Write(second)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	select {
	case result := <-resultCh:
		require.NoError(t, result.err)
		require.Equal(t, 84, result.n)
		require.Equal(t, append(first, second...), result.payload)
		remote, ok := result.remote.(*net.UDPAddr)
		require.True(t, ok)
		require.Equal(t, 12345, remote.Port)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish reading the WebSocket message")
	}
}

func TestReadShortBufferReturnsNoPacketAndCachesClose(t *testing.T) {
	resultCh := make(chan readResult, 1)
	server := newPacketTestServer(t, false, 63, resultCh, nil)
	client := dialPacketTestClient(t, server, false, 1)
	defer client.Close()
	require.NoError(t, client.WriteMessage(websocket.BinaryMessage, bytes.Repeat([]byte{0x44}, 84)))

	select {
	case result := <-resultCh:
		require.Zero(t, result.n)
		require.ErrorIs(t, result.err, net.ErrClosed)
		require.ErrorIs(t, result.err, io.ErrShortBuffer)
		require.ErrorIs(t, result.secondErr, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not reject the short read buffer")
	}
}

func TestReadRejectsOversizedMessageWithoutPartialPacket(t *testing.T) {
	resultCh := make(chan readResult, 1)
	server := newPacketTestServer(t, false, maxIncomingMessageSize, resultCh, nil)
	client := dialPacketTestClient(t, server, false, 0)
	defer client.Close()
	require.NoError(t, client.WriteMessage(websocket.BinaryMessage, bytes.Repeat([]byte{0x55}, maxIncomingMessageSize+1)))

	select {
	case result := <-resultCh:
		require.Zero(t, result.n)
		require.ErrorIs(t, result.err, net.ErrClosed)
		require.ErrorIs(t, result.secondErr, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not reject the oversized WebSocket message")
	}
}

func TestPingControlDeadlineDoesNotExpireLaterPacketWrites(t *testing.T) {
	ready := make(chan struct{})
	writeErr := make(chan error, 1)
	server := newPacketTestServer(t, false, 256, nil, func(conn net.Conn) {
		go func() {
			_, _ = conn.Read(make([]byte, 256))
		}()
		close(ready)
		time.Sleep(1200 * time.Millisecond)
		_, err := conn.Write([]byte("packet after ping"))
		writeErr <- err
	})
	client := dialPacketTestClient(t, server, false, 0)
	defer client.Close()
	<-ready
	require.NoError(t, client.WriteControl(websocket.PingMessage, []byte("keepalive"), time.Now().Add(time.Second)))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(4*time.Second)))
	messageType, message, err := client.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.BinaryMessage, messageType)
	require.Equal(t, []byte("packet after ping"), message)
	require.NoError(t, <-writeErr)
}

func TestNativeTLSPacketWriteAndOversizeDrop(t *testing.T) {
	for _, size := range []int{1335, 16384} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			writeErr := make(chan error, 2)
			payloads := [][]byte{bytes.Repeat([]byte{0x33}, maxTLSRecordPacketSize+1), bytes.Repeat([]byte{0x66}, size)}
			server := newPacketTestServer(t, true, 64*1024, nil, func(conn net.Conn) {
				n, err := conn.Write(payloads[0])
				if !errors.Is(err, io.ErrShortBuffer) || n != 0 {
					writeErr <- errors.New("oversized packet was not dropped before writing")
					return
				}
				n, err = conn.Write(payloads[1])
				if err == nil && n != len(payloads[1]) {
					err = io.ErrShortWrite
				}
				writeErr <- err
			})
			client := dialPacketTestClient(t, server, true, 0)
			defer client.Close()
			messageType, received, err := client.ReadMessage()
			require.NoError(t, err)
			require.Equal(t, websocket.BinaryMessage, messageType)
			require.Equal(t, payloads[1], received)
			require.NoError(t, <-writeErr)
		})
	}
}

type readResult struct {
	n         int
	payload   []byte
	err       error
	secondErr error
	remote    net.Addr
}

func newPacketTestServer(t *testing.T, nativeTLS bool, readBufferSize int, resultCh chan<- readResult, write func(net.Conn)) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		conn, err := Upgrade(w, r, nativeTLS, remote)
		if err != nil {
			if resultCh != nil {
				resultCh <- readResult{err: err}
			}
			return
		}
		defer conn.Close()
		if write != nil {
			write(conn)
			return
		}
		buffer := make([]byte, readBufferSize)
		n, readErr := conn.Read(buffer)
		result := readResult{n: n, payload: append([]byte(nil), buffer[:n]...), err: readErr, remote: conn.RemoteAddr()}
		if readErr != nil {
			_, result.secondErr = conn.Read(buffer)
		}
		resultCh <- result
	})
	if !nativeTLS {
		return httptest.NewServer(handler)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func dialPacketTestClient(t *testing.T, server *httptest.Server, nativeTLS bool, writeBufferSize int) *websocket.Conn {
	t.Helper()
	url := "ws" + server.URL[len("http"):]
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if nativeTLS {
		config.RootCAs = x509.NewCertPool()
		config.RootCAs.AddCert(server.Certificate())
	}
	dialer := websocket.Dialer{WriteBufferSize: writeBufferSize, TLSClientConfig: config}
	client, response, err := dialer.Dial(url, nil)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	require.NoError(t, err)
	return client
}

func serverFrame(payload []byte) []byte {
	if len(payload) < 126 {
		return append([]byte{0x82, byte(len(payload))}, payload...)
	}
	return append([]byte{0x82, 126, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}
