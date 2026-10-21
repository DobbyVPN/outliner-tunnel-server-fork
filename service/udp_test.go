// Copyright 2018 The Outline Authors
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

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"

	onet "golang.getoutline.org/tunnel-server/net"
)

const timeout = 5 * time.Minute

var clientAddr = net.UDPAddr{IP: []byte{192, 0, 2, 1}, Port: 12345}

var targetAddr = net.UDPAddr{IP: []byte{192, 0, 2, 2}, Port: 54321}
var localAddr = net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 9}
var dnsAddr = net.UDPAddr{IP: []byte{192, 0, 2, 3}, Port: 53}

var natCryptoKey *shadowsocks.EncryptionKey

func init() {
	logging.SetLevel(logging.INFO, "")
	natCryptoKey, _ = shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, "test password")
}

type fakePacket struct {
	addr    net.Addr
	payload []byte
	err     error
}

type packetListener struct {
	conn net.PacketConn
}

func (ln *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return ln.conn, nil
}

func WrapWithValidatingPacketListener(conn net.PacketConn, targetIPValidator onet.TargetIPValidator) transport.PacketListener {
	return &packetListener{
		&validatingPacketConn{
			PacketConn:        conn,
			targetIPValidator: targetIPValidator,
		},
	}
}

func wrapWithTimedValidatingPacketListener(conn net.PacketConn, targetIPValidator onet.TargetIPValidator, timeout time.Duration) transport.PacketListener {
	return &packetListener{
		conn: &timedPacketConn{
			PacketConn: &validatingPacketConn{
				PacketConn:        conn,
				targetIPValidator: targetIPValidator,
			},
			defaultTimeout: timeout,
		},
	}
}

func registerTestPacketServeCleanup(t *testing.T, clientConn, targetConn *fakePacketConn) {
	t.Helper()
	t.Cleanup(func() {
		_ = clientConn.Close()
		select {
		case <-targetConn.closed:
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for the target connection to close")
		}
	})
}

type fakePacketConn struct {
	net.PacketConn
	send      chan fakePacket
	recv      chan fakePacket
	closed    chan struct{}
	deadline  time.Time
	closedNow bool
	closeOnce sync.Once
	mu        sync.Mutex
}

func makePacketConn() *fakePacketConn {
	return &fakePacketConn{
		send:   make(chan fakePacket, 1),
		recv:   make(chan fakePacket),
		closed: make(chan struct{}),
	}
}

type trackedPacketConn struct {
	*fakePacketConn
	readStarted  chan struct{}
	readReturned chan struct{}
}

func makeTrackedPacketConn() *trackedPacketConn {
	return &trackedPacketConn{
		fakePacketConn: makePacketConn(),
		readStarted:    make(chan struct{}, 8),
		readReturned:   make(chan struct{}, 8),
	}
}

func (conn *trackedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readStarted <- struct{}{}
	n, addr, err := conn.fakePacketConn.ReadFrom(buffer)
	conn.readReturned <- struct{}{}
	return n, addr, err
}

type handlerTestConn struct {
	input        chan []byte
	writes       chan []byte
	readStarted  chan struct{}
	writeStarted chan struct{}
	closed       chan struct{}
	readEOF      chan struct{}
	blockedWrite <-chan struct{}
	closeOnce    sync.Once
	readEOFOnce  sync.Once
}

func makeHandlerTestConn() *handlerTestConn {
	return &handlerTestConn{
		input:        make(chan []byte),
		writes:       make(chan []byte, 1),
		readStarted:  make(chan struct{}, 8),
		writeStarted: make(chan struct{}, 1),
		closed:       make(chan struct{}),
		readEOF:      make(chan struct{}),
	}
}

func (conn *handlerTestConn) Read(buffer []byte) (int, error) {
	select {
	case conn.readStarted <- struct{}{}:
	default:
	}
	select {
	case <-conn.closed:
		return 0, net.ErrClosed
	case <-conn.readEOF:
		return 0, io.EOF
	case payload := <-conn.input:
		n := copy(buffer, payload)
		if n < len(payload) {
			return n, io.ErrShortBuffer
		}
		return n, nil
	}
}

func (conn *handlerTestConn) Write(payload []byte) (int, error) {
	if conn.blockedWrite != nil {
		select {
		case conn.writeStarted <- struct{}{}:
		default:
		}
		select {
		case <-conn.closed:
			return 0, net.ErrClosed
		case <-conn.blockedWrite:
		}
	}
	select {
	case <-conn.closed:
		return 0, net.ErrClosed
	default:
		conn.writes <- append([]byte(nil), payload...)
		return len(payload), nil
	}
}

func (conn *handlerTestConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return nil
}

func (conn *handlerTestConn) LocalAddr() net.Addr              { return &localAddr }
func (conn *handlerTestConn) RemoteAddr() net.Addr             { return &clientAddr }
func (conn *handlerTestConn) SetDeadline(time.Time) error      { return nil }
func (conn *handlerTestConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *handlerTestConn) SetWriteDeadline(time.Time) error { return nil }

func (conn *handlerTestConn) send(payload []byte) {
	conn.input <- payload
}

func (conn *handlerTestConn) halfCloseRead() {
	conn.readEOFOnce.Do(func() { close(conn.readEOF) })
}

func waitForTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func makeEncryptedUDPPacket(t *testing.T, addr net.Addr, key *shadowsocks.EncryptionKey, payload []byte) []byte {
	t.Helper()
	plaintext := append(append([]byte(nil), socks.ParseAddr(addr.String())...), payload...)
	ciphertext, err := shadowsocks.Pack(make([]byte, key.SaltSize()+len(plaintext)+key.TagSize()), plaintext, key)
	require.NoError(t, err)
	return ciphertext
}

func (conn *fakePacketConn) getReadDeadline() time.Time {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.deadline
}

func (conn *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.deadline = deadline
	return nil
}

func (conn *fakePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closedNow {
		return 0, net.ErrClosed
	}
	conn.send <- fakePacket{addr, payload, nil}
	return len(payload), nil
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	pkt, ok := <-conn.recv
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(buffer, pkt.payload)
	if n < len(pkt.payload) {
		return n, pkt.addr, io.ErrShortBuffer
	}
	return n, pkt.addr, pkt.err
}

func (conn *fakePacketConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.closeOnce.Do(func() {
		conn.closedNow = true
		close(conn.closed)
		close(conn.send)
		close(conn.recv)
	})
	return nil
}

func (conn *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
}

func (conn *fakePacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8888}
}

type udpReport struct {
	accessKey, status                  string
	clientProxyBytes, proxyTargetBytes int64
}

// Stub metrics implementation for testing NAT behaviors.
type natTestMetrics struct {
	natEntriesAdded int
}

var _ NATMetrics = (*natTestMetrics)(nil)

func (m *natTestMetrics) AddNATEntry() {
	m.natEntriesAdded++
}
func (m *natTestMetrics) RemoveNATEntry() {}

type fakeUDPAssociationMetrics struct {
	accessKey         string
	upstreamPackets   []udpReport
	downstreamPackets []udpReport
	mu                sync.Mutex
}

var _ UDPAssociationMetrics = (*fakeUDPAssociationMetrics)(nil)

func (m *fakeUDPAssociationMetrics) AddAuthentication(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessKey = key
}

func (m *fakeUDPAssociationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamPackets = append(m.upstreamPackets, udpReport{m.accessKey, status, clientProxyBytes, proxyTargetBytes})
}

func (m *fakeUDPAssociationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downstreamPackets = append(m.downstreamPackets, udpReport{m.accessKey, status, targetProxyBytes, proxyClientBytes})
}

func (m *fakeUDPAssociationMetrics) AddClose() {}

// sendSSPayload sends a single Shadowsocks packet to the provided connection.
// The packet is constructed with the given address, cipher, and payload.
func sendSSPayload(conn *fakePacketConn, addr net.Addr, cipher *shadowsocks.EncryptionKey, payload []byte) {
	socksAddr := socks.ParseAddr(addr.String())
	plaintext := append(socksAddr, payload...)
	ciphertext := make([]byte, cipher.SaltSize()+len(plaintext)+cipher.TagSize())
	shadowsocks.Pack(ciphertext, plaintext, cipher)
	conn.recv <- fakePacket{
		addr:    &clientAddr,
		payload: ciphertext,
	}
}

// startTestHandler creates a new association handler with a fake
// client and target connection for testing purposes. It also starts a
// PacketServe goroutine to handle incoming packets on the client connection.
func startTestHandler(t *testing.T) (AssociationHandler, func(target net.Addr, payload []byte), *fakePacketConn) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, allowAll, timeout))
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
	}, &natTestMetrics{})
	registerTestPacketServeCleanup(t, clientConn, targetConn)
	return handler, func(target net.Addr, payload []byte) {
		sendSSPayload(clientConn, target, cipher, payload)
	}, targetConn
}

func TestAssociationCloseWhileReading(t *testing.T) {
	assoc := &association{
		pc:         makePacketConn(),
		clientAddr: &clientAddr,
		readCh:     make(chan *packet),
	}
	go func() {
		buf := make([]byte, 1024)
		assoc.Read(buf)
	}()

	err := assoc.Close()

	assert.NoError(t, err, "Close should not panic or return an error")
}

func TestAssociationHandler_Handle_IPFilter(t *testing.T) {
	t.Run("RequirePublicIP blocks localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler(t)
		handler.SetTargetPacketListener(WrapWithValidatingPacketListener(targetConn, onet.RequirePublicIP))

		sendPayload(&localAddr, []byte{1, 2, 3})

		select {
		case <-targetConn.send:
			t.Errorf("Expected no packets to be sent")
		case <-time.After(100 * time.Millisecond):
			return
		}
	})

	t.Run("allowAll allows localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler(t)
		handler.SetTargetPacketListener(WrapWithValidatingPacketListener(targetConn, allowAll))

		sendPayload(&localAddr, []byte{1, 2, 3})

		sent := <-targetConn.send
		if !bytes.Equal([]byte{1, 2, 3}, sent.payload) {
			t.Errorf("Expected %v, but got %v", []byte{1, 2, 3}, sent.payload)
		}
	})
}

func TestUpstreamMetrics(t *testing.T) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, allowAll, timeout))
	metrics := &fakeUDPAssociationMetrics{}
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, metrics)
	}, &natTestMetrics{})
	registerTestPacketServeCleanup(t, clientConn, targetConn)

	// Test both the first-packet and subsequent-packet cases.
	const N = 10
	for i := 1; i <= N; i++ {
		sendSSPayload(clientConn, &targetAddr, cipher, make([]byte, i))
		<-targetConn.send
	}

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	assert.Equal(t, N, len(metrics.upstreamPackets), "Expected %d reports, not %d", N, len(metrics.upstreamPackets))
	for i, report := range metrics.upstreamPackets {
		assert.Equal(t, int64(i+1), report.proxyTargetBytes, "Expected %d payload bytes, not %d", i+1, report.proxyTargetBytes)
		assert.Greater(t, report.clientProxyBytes, report.proxyTargetBytes, "Expected nonzero input overhead (%d > %d)", report.clientProxyBytes, report.proxyTargetBytes)
		assert.Equal(t, "id-0", report.accessKey, "Unexpected access key name: %s", report.accessKey)
		assert.Equal(t, "OK", report.status, "Wrong status: %s", report.status)
	}
}

func assertAlmostEqual(t *testing.T, a, b time.Time) {
	delta := a.Sub(b)
	limit := 100 * time.Millisecond
	if delta > limit || -delta > limit {
		t.Errorf("Times are not close: %v, %v", a, b)
	}
}

func assertUDPAddrEqual(t *testing.T, a net.Addr, b *net.UDPAddr) {
	addr, ok := a.(*net.UDPAddr)
	if !ok || !addr.IP.Equal(b.IP) || addr.Port != b.Port || addr.Zone != b.Zone {
		t.Errorf("Mismatched address: %v != %v", a, b)
	}
}

// Implements net.Error
type fakeTimeoutError struct {
	error
}

func (e *fakeTimeoutError) Timeout() bool {
	return true
}

func (e *fakeTimeoutError) Temporary() bool {
	return false
}

func startDirectAssociation(t *testing.T, validator onet.TargetIPValidator, timeout time.Duration) (*handlerTestConn, *trackedPacketConn, *shadowsocks.EncryptionKey, context.CancelFunc, <-chan struct{}, *fakeUDPAssociationMetrics) {
	t.Helper()
	ciphers, err := MakeTestCiphers([]string{"asdf"})
	require.NoError(t, err)
	key := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	clientConn := makeHandlerTestConn()
	targetConn := makeTrackedPacketConn()
	metrics := &fakeUDPAssociationMetrics{}
	handler := NewAssociationHandler(ciphers, nil)
	handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, validator, timeout))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handler.HandleAssociation(ctx, clientConn, metrics)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		_ = targetConn.Close()
	})
	waitForTestSignal(t, clientConn.readStarted, "the initial client read")
	return clientConn, targetConn, key, cancel, done, metrics
}

func assertAssociationRelayStopped(t *testing.T, targetConn *trackedPacketConn, done <-chan struct{}) {
	t.Helper()
	waitForTestSignal(t, targetConn.closed, "the target connection to close")
	waitForTestSignal(t, targetConn.readReturned, "the reverse relay read to return")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the association and reverse relay to stop")
	}
}

func TestAssociationHandlerRejectedFirstDisconnectClosesTargetAndStopsRelay(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("cycle_%02d", i), func(t *testing.T) {
			clientConn, targetConn, key, _, done, _ := startDirectAssociation(t, onet.RequirePublicIP, timeout)
			clientConn.send(makeEncryptedUDPPacket(t, &localAddr, key, []byte{1}))
			waitForTestSignal(t, clientConn.readStarted, "the client read after the rejected packet")
			waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")

			assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
			select {
			case <-targetConn.send:
				t.Fatal("rejected destination packet was sent to the target")
			default:
			}

			// Closing the client connection simulates a client disconnect while
			// the handler is blocked on its next read.
			require.NoError(t, clientConn.Close())
			assertAssociationRelayStopped(t, targetConn, done)
		})
	}
}

func TestAssociationHandlerCancellationClosesTargetAndStopsRelay(t *testing.T) {
	clientConn, targetConn, key, cancel, done, _ := startDirectAssociation(t, allowAll, timeout)
	clientConn.send(makeEncryptedUDPPacket(t, &targetAddr, key, []byte{1}))
	waitForTestSignal(t, clientConn.readStarted, "the client read after the first packet")
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")
	require.Equal(t, []byte{1}, (<-targetConn.send).payload)

	cancel()
	assertAssociationRelayStopped(t, targetConn, done)
}

func TestAssociationHandlerClientReadHalfCloseInterruptsBlockedRelayWrite(t *testing.T) {
	clientConn, targetConn, key, _, done, _ := startDirectAssociation(t, allowAll, timeout)
	clientConn.blockedWrite = make(chan struct{})
	clientConn.send(makeEncryptedUDPPacket(t, &targetAddr, key, []byte{1}))
	waitForTestSignal(t, clientConn.readStarted, "the client read after the first packet")
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")
	require.Equal(t, []byte{1}, (<-targetConn.send).payload)

	targetConn.recv <- fakePacket{addr: &targetAddr, payload: []byte{2}}
	waitForTestSignal(t, clientConn.writeStarted, "the reverse relay to block writing to the client")
	clientConn.halfCloseRead()

	assertAssociationRelayStopped(t, targetConn, done)
	select {
	case <-clientConn.closed:
	default:
		t.Fatal("handler did not close the client connection after read EOF")
	}
}

func TestAssociationHandlerTargetTimeoutClosesTargetAndStopsRelay(t *testing.T) {
	clientConn, targetConn, key, _, done, _ := startDirectAssociation(t, allowAll, timeout)
	clientConn.send(makeEncryptedUDPPacket(t, &targetAddr, key, []byte{1}))
	waitForTestSignal(t, clientConn.readStarted, "the client read after the first packet")
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")
	require.Equal(t, []byte{1}, (<-targetConn.send).payload)

	targetConn.recv <- fakePacket{err: &fakeTimeoutError{}}
	assertAssociationRelayStopped(t, targetConn, done)
}

func TestAssociationHandlerWrappedClosedErrorClosesTargetAndStopsRelay(t *testing.T) {
	clientConn, targetConn, key, _, done, metrics := startDirectAssociation(t, allowAll, timeout)
	clientConn.send(makeEncryptedUDPPacket(t, &targetAddr, key, []byte{1}))
	waitForTestSignal(t, clientConn.readStarted, "the client read after the first packet")
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")
	require.Equal(t, []byte{1}, (<-targetConn.send).payload)

	targetConn.recv <- fakePacket{err: fmt.Errorf("read wrapper: %w", net.ErrClosed)}
	assertAssociationRelayStopped(t, targetConn, done)
	metrics.mu.Lock()
	require.Len(t, metrics.downstreamPackets, 1)
	require.Equal(t, "ERR_READ", metrics.downstreamPackets[0].status)
	metrics.mu.Unlock()
}

func TestAssociationHandlerRecoverableTargetReadErrorContinuesRelay(t *testing.T) {
	clientConn, targetConn, key, _, done, _ := startDirectAssociation(t, allowAll, timeout)
	clientConn.send(makeEncryptedUDPPacket(t, &targetAddr, key, []byte{1}))
	waitForTestSignal(t, clientConn.readStarted, "the client read after the first packet")
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to start")
	require.Equal(t, []byte{1}, (<-targetConn.send).payload)

	targetConn.recv <- fakePacket{err: io.ErrUnexpectedEOF}
	waitForTestSignal(t, targetConn.readStarted, "the reverse relay to retry after a recoverable error")
	targetConn.recv <- fakePacket{addr: &targetAddr, payload: []byte{2}}
	select {
	case response := <-clientConn.writes:
		require.NotEmpty(t, response, "the target response should be relayed to the client")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the reverse relay to forward a response")
	}

	clientConn.Close()
	assertAssociationRelayStopped(t, targetConn, done)
}

func TestRejectedDestinationStartsTargetTimeout(t *testing.T) {
	const idleTimeout = 50 * time.Millisecond
	listener := MakeTargetUDPListener(onet.RequirePublicIP, idleTimeout, 0)
	targetConn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	defer targetConn.Close()

	_, err = targetConn.WriteTo([]byte{1}, &localAddr)
	require.Error(t, err, "the local target must be rejected")

	type readResult struct{ err error }
	readDone := make(chan readResult, 1)
	go func() {
		_, _, readErr := targetConn.ReadFrom(make([]byte, 32))
		readDone <- readResult{err: readErr}
	}()
	select {
	case result := <-readDone:
		var netErr net.Error
		require.ErrorAs(t, result.err, &netErr)
		require.True(t, netErr.Timeout(), "expected the rejected first destination to start the idle timeout")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the target inactivity deadline")
	}
}

func TestTimedPacketConn(t *testing.T) {
	t.Run("Write", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler(t)

		buf := []byte{1}
		sendPayload(&targetAddr, buf)

		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &targetAddr)
	})

	t.Run("WriteDNS", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler(t)

		// Simulate one DNS query being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &dnsAddr)
	})

	t.Run("WriteDNSMultiple", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler(t)

		// Simulate three DNS queries being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("WriteMixed", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler(t)

		// Simulate both non-DNS and DNS packets being sent.
		buf := []byte{1}
		sendPayload(&targetAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// Mixed DNS and non-DNS connections should have the user-specified timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("FastClose", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, allowAll, timeout))
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})
		registerTestPacketServeCleanup(t, clientConn, targetConn)

		// Send one DNS query.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close immediately.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now())
	})

	t.Run("NoFastClose_NotDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, allowAll, timeout))
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})
		registerTestPacketServeCleanup(t, clientConn, targetConn)

		// Send one non-DNS packet.
		sendSSPayload(clientConn, &targetAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &targetAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close after the full timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("NoFastClose_MultipleDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(wrapWithTimedValidatingPacketListener(targetConn, allowAll, timeout))
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})
		registerTestPacketServeCleanup(t, clientConn, targetConn)

		// Send two DNS packets.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		<-targetConn.send
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{2})
		<-targetConn.send

		// Send a response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		<-clientConn.send

		// targetConn should be scheduled to close after the DNS timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("Timeout", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler(t)

		// Simulate a non-DNS initial packet.
		sendPayload(&targetAddr, []byte{1})
		<-targetConn.send
		// Simulate a read timeout.
		received := fakePacket{err: &fakeTimeoutError{}}
		before := time.Now()
		targetConn.recv <- received
		// Wait for targetConn to close.
		if _, ok := <-targetConn.send; ok {
			t.Error("targetConn should be closed due to read timeout")
		}

		// targetConn should be closed as soon as the timeout error is received.
		assertAlmostEqual(t, before, time.Now())
	})
}

func TestNATMap(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		nm := newNATmap()
		if nm.Get("foo") != nil {
			t.Error("Expected nil value from empty NAT map")
		}
	})

	t.Run("Add", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc1 := &association{}

		nm.Add(addr.String(), assoc1)
		assert.Equal(t, assoc1, nm.Get(addr.String()), "Get should return the correct connection")

		assoc2 := &association{}
		nm.Add(addr.String(), assoc2)
		assert.Equal(t, assoc2, nm.Get(addr.String()), "Adding with the same address should overwrite the entry")
	})

	t.Run("Get", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc := &association{}
		nm.Add(addr.String(), assoc)

		assert.Equal(t, assoc, nm.Get(addr.String()), "Get should return the correct connection for an existing address")

		addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5678}
		assert.Nil(t, nm.Get(addr2.String()), "Get should return nil for a non-existent address")
	})

	t.Run("Del", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc := &association{}
		nm.Add(addr.String(), assoc)

		nm.Del(addr.String())

		assert.Nil(t, nm.Get(addr.String()), "Get should return nil after deleting the entry")
	})
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	textBuf := make([]byte, serverUDPBufferSize)
	testIP := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKeyUDP(testIP, textBuf, testPayload, cipherList, noopLogger())
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(makeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	packets := [numCiphers][]byte{}
	ips := [numCiphers]netip.Addr{}
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	for i, element := range snapshot {
		packets[i] = make([]byte, 0, serverUDPBufferSize)
		plaintext := makeTestPayload(50)
		packets[i], err = shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, element.Value.(*CipherEntry).CryptoKey)
		if err != nil {
			b.Error(err)
		}
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cipherNumber := n % numCiphers
		ip := ips[cipherNumber]
		packet := packets[cipherNumber]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1)) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	plaintext := makeTestPayload(50)
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cryptoKey := snapshot[0].Value.(*CipherEntry).CryptoKey
	packet, err := shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, cryptoKey)
	require.Nil(b, err)

	const numIPs = 100 // Must be <256
	ips := [numIPs]netip.Addr{}
	for i := 0; i < numIPs; i++ {
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
		if err != nil {
			b.Error(err)
		}
	}
}

func TestUDPEarlyClose(t *testing.T) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	const testTimeout = 200 * time.Millisecond
	handler := NewAssociationHandler(cipherList, &fakeShadowsocksMetrics{})
	handler.SetTargetPacketListener(&packetListener{makePacketConn()})

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	require.Nil(t, clientConn.Close())
	// This should return quickly without timing out.
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
	}, &natTestMetrics{})
}

// Makes sure the UDP listener returns [io.ErrClosed] on reads and writes after Close().
func TestClosedUDPListenerError(t *testing.T) {
	var packetConn net.PacketConn
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	err = packetConn.Close()
	require.NoError(t, err)

	_, _, err = packetConn.ReadFrom(nil)
	require.ErrorIs(t, err, net.ErrClosed)

	_, err = packetConn.WriteTo(nil, &net.UDPAddr{})
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestAssociationCloseRaceWithPacketServe(t *testing.T) {
	// Regression test: when the handler calls Close() (which closes readCh
	// in the old code) while PacketServe's main loop is simultaneously
	// enqueuing a packet into readCh, the old code panicked with
	// "send on closed channel".
	//
	// The fix changes Close() to close doneCh instead (via sync.Once),
	// leaving readCh open so the send cannot panic.
	//
	// https://github.com/OutlineFoundation/tunnel-server/pull/289

	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey

	handler := NewAssociationHandler(ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetPacketListener(&packetListener{targetConn})

	// Use a handler that reads one packet, then explicitly closes the
	// connection while more packets are in flight. In the old code Close()
	// called close(readCh), so a concurrent send from PacketServe's main
	// loop would panic with "send on closed channel".
	handlerDone := make(chan struct{})
	var closeOnce sync.Once
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		buf := make([]byte, 1024)
		conn.Read(buf) // Read one packet.
		conn.Close()   // Close while PacketServe may still enqueue packets.
		closeOnce.Do(func() { close(handlerDone) })
	}, &natTestMetrics{})

	// Send the first packet to create the association and let the handler read it.
	sendSSPayload(clientConn, &targetAddr, cipher, []byte{1})
	<-handlerDone

	// Now blast more packets from the same client address. PacketServe will
	// try to enqueue these into the association's readCh while/after Close()
	// has been called. Before the fix, this would panic.
	for i := 0; i < 50; i++ {
		sendSSPayload(clientConn, &targetAddr, cipher, []byte{byte(i)})
	}

	// Give PacketServe time to process the queued packets.
	time.Sleep(50 * time.Millisecond)

	// Clean shutdown. If we get here without a panic, the race is fixed.
	_ = clientConn.Close()
}
