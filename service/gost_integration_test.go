// Copyright 2026 The DobbyVPN Authors
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
	"container/list"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"golang.getoutline.org/tunnel-server/service/metrics"
)

const gostIntegrationTimeout = 20 * time.Second

type gostIntegrationCipher struct {
	id         string
	method     string
	secret     string
	stockAlias string
}

var gostMixedCiphers = []gostIntegrationCipher{
	{id: "gost", method: "kuznyechik-mgm", secret: "gost integration secret"},
	{id: "chacha", method: shadowsocks.CHACHA20IETFPOLY1305, stockAlias: "CHACHA20-IETF-POLY1305", secret: "chacha integration secret"},
	{id: "aes", method: shadowsocks.AES256GCM, stockAlias: "AES-256-GCM", secret: "aes integration secret"},
}

func makeGOSTIntegrationCipherList(t *testing.T, specs []gostIntegrationCipher) (CipherList, map[string]*shadowsocks.EncryptionKey) {
	t.Helper()
	contents := list.New()
	keys := make(map[string]*shadowsocks.EncryptionKey, len(specs))
	for _, spec := range specs {
		key, err := shadowsocks.NewEncryptionKey(spec.method, spec.secret)
		require.NoError(t, err, "make %s key", spec.id)
		entry := MakeCipherEntry(spec.id, key, spec.secret)
		contents.PushBack(&entry)
		keys[spec.id] = key
	}
	ciphers := NewCipherList()
	ciphers.Update(contents)
	return ciphers, keys
}

type gostTCPIntegrationMetrics struct {
	authEvents  chan string
	closeEvents chan string
}

func newGOSTTCPIntegrationMetrics() *gostTCPIntegrationMetrics {
	return &gostTCPIntegrationMetrics{
		authEvents:  make(chan string, 16),
		closeEvents: make(chan string, 16),
	}
}

func (m *gostTCPIntegrationMetrics) AddAuthentication(id string) {
	m.authEvents <- id
}

func (m *gostTCPIntegrationMetrics) AddClose(status string, _ metrics.ProxyMetrics, _ time.Duration) {
	m.closeEvents <- status
}

func (*gostTCPIntegrationMetrics) AddProbe(string, string, int64)      {}
func (*gostTCPIntegrationMetrics) AddCipherSearch(bool, time.Duration) {}

func startGOSTTCPProxy(t *testing.T, ciphers CipherList, replayCache *ReplayCache, connMetrics TCPConnMetrics) string {
	t.Helper()
	listener := makeLocalhostListener(t)
	handler := NewStreamHandler(NewShadowsocksStreamAuthenticator(ciphers, replayCache, nil, nil), 5*time.Second)
	handler.SetTargetDialer(MakeValidatingTCPStreamDialer(allowAll, 0))
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) {
				handler.HandleStream(ctx, conn, connMetrics)
			},
		)
		close(done)
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		<-done
	})
	return listener.Addr().String()
}

func startGOSTTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	acceptDone := make(chan struct{})
	var connections sync.WaitGroup
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		<-acceptDone
		connections.Wait()
	})
	return listener.Addr().String()
}

func stockStreamCipher(t *testing.T, spec gostIntegrationCipher) core.Cipher {
	t.Helper()
	if spec.stockAlias == "" {
		t.Fatalf("%s is not a stock Shadowsocks cipher", spec.id)
	}
	cipher, err := core.PickCipher(spec.stockAlias, nil, spec.secret)
	require.NoError(t, err)
	return cipher
}

func makeGOSTTCPWire(t *testing.T, key *shadowsocks.EncryptionKey, target string, payload []byte) []byte {
	t.Helper()
	addr := socks.ParseAddr(target)
	request := append(bytes.Clone(addr), payload...)
	var wire bytes.Buffer
	writer := shadowsocks.NewWriter(&wire, key)
	n, err := writer.Write(request)
	require.NoError(t, err)
	require.Equal(t, len(request), n)
	require.GreaterOrEqual(t, wire.Len(), key.SaltSize()+2+key.TagSize())
	return bytes.Clone(wire.Bytes())
}

func exchangeGOSTTCPWire(t *testing.T, server string, key *shadowsocks.EncryptionKey, wire []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server, gostIntegrationTimeout)
	require.NoError(t, err)
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(gostIntegrationTimeout)))
	n, err := tcpConn.Write(wire)
	require.NoError(t, err)
	require.Equal(t, len(wire), n)
	require.NoError(t, tcpConn.CloseWrite())
	response, err := io.ReadAll(shadowsocks.NewReader(tcpConn, key))
	require.NoError(t, err)
	return response
}

func exchangeStockTCP(t *testing.T, server, target string, spec gostIntegrationCipher, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server, gostIntegrationTimeout)
	require.NoError(t, err)
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(gostIntegrationTimeout)))
	clientConn := stockStreamCipher(t, spec).StreamConn(tcpConn)
	request := append(bytes.Clone(socks.ParseAddr(target)), payload...)
	n, err := clientConn.Write(request)
	require.NoError(t, err)
	require.Equal(t, len(request), n)
	require.NoError(t, tcpConn.CloseWrite())
	response, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	return response
}

func awaitGOSTTCPEvents(t *testing.T, metrics *gostTCPIntegrationMetrics, accessKey, status string) {
	t.Helper()
	if accessKey != "" {
		select {
		case got := <-metrics.authEvents:
			require.Equal(t, accessKey, got)
		case <-time.After(gostIntegrationTimeout):
			t.Fatal("timed out waiting for TCP access-key authentication")
		}
	}
	select {
	case got := <-metrics.closeEvents:
		require.Equal(t, status, got)
	case <-time.After(gostIntegrationTimeout):
		t.Fatal("timed out waiting for TCP connection completion")
	}
}

func TestGOSTMixedTCPServerWithStockPeers(t *testing.T) {
	echoAddr := startGOSTTCPEcho(t)
	ciphers, keys := makeGOSTIntegrationCipherList(t, gostMixedCiphers)
	replayCache := NewReplayCache(8)
	serverMetrics := newGOSTTCPIntegrationMetrics()
	server := startGOSTTCPProxy(t, ciphers, &replayCache, serverMetrics)

	for _, spec := range []gostIntegrationCipher{gostMixedCiphers[2], gostMixedCiphers[1]} {
		payload := bytes.Repeat([]byte("stock Shadowsocks stream "), 19)
		require.Equal(t, payload, exchangeStockTCP(t, server, echoAddr, spec, payload))
		awaitGOSTTCPEvents(t, serverMetrics, spec.id, "OK")
	}

	gost := gostMixedCiphers[0]
	key := keys[gost.id]
	// findAccessKey reads 50 bytes before trial-decrypting: GOST's 32-byte salt,
	// encrypted two-byte length, and 16-byte tag exactly fill that probe window.
	require.Equal(t, 32, key.SaltSize())
	require.Equal(t, 16, key.TagSize())
	require.Equal(t, bytesForKeyFinding, key.SaltSize()+2+key.TagSize())

	// Each TCP chunk consumes two AEAD nonces. At the 16 KiB chunk limit, this
	// payload spans 72 chunks, exercising more than 128 AEAD calls in each stream.
	longPayload := bytes.Repeat([]byte("Kuznyechik MGM stream integration payload."), 28000)
	longWire := makeGOSTTCPWire(t, key, echoAddr, longPayload)
	require.Equal(t, longPayload, exchangeGOSTTCPWire(t, server, key, longWire))
	awaitGOSTTCPEvents(t, serverMetrics, gost.id, "OK")

	wrongKey, err := shadowsocks.NewEncryptionKey(gost.method, "wrong GOST secret")
	require.NoError(t, err)
	wrongWire := makeGOSTTCPWire(t, wrongKey, echoAddr, []byte("wrong key"))
	conn, err := net.DialTimeout("tcp", server, gostIntegrationTimeout)
	require.NoError(t, err)
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(gostIntegrationTimeout)))
	_, err = tcpConn.Write(wrongWire)
	require.NoError(t, err)
	require.NoError(t, tcpConn.CloseWrite())
	_, err = io.Copy(io.Discard, tcpConn)
	require.NoError(t, err)
	require.NoError(t, tcpConn.Close())
	awaitGOSTTCPEvents(t, serverMetrics, "", "ERR_CIPHER")

	tamperedWire := makeGOSTTCPWire(t, key, echoAddr, []byte("tampered GOST payload"))
	// The first 50 bytes authenticate the encrypted length. Corrupt the first
	// payload byte after that point so the normal stream reader rejects it.
	tamperedWire[bytesForKeyFinding] ^= 0x80
	conn, err = net.DialTimeout("tcp", server, gostIntegrationTimeout)
	require.NoError(t, err)
	tcpConn = conn.(*net.TCPConn)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(gostIntegrationTimeout)))
	_, err = tcpConn.Write(tamperedWire)
	require.NoError(t, err)
	require.NoError(t, tcpConn.CloseWrite())
	_, err = io.Copy(io.Discard, tcpConn)
	require.NoError(t, err)
	require.NoError(t, tcpConn.Close())
	awaitGOSTTCPEvents(t, serverMetrics, gost.id, "ERR_READ_ADDRESS")

	replayWire := makeGOSTTCPWire(t, key, echoAddr, []byte("single-use salt"))
	require.Equal(t, []byte("single-use salt"), exchangeGOSTTCPWire(t, server, key, replayWire))
	awaitGOSTTCPEvents(t, serverMetrics, gost.id, "OK")
	conn, err = net.DialTimeout("tcp", server, gostIntegrationTimeout)
	require.NoError(t, err)
	tcpConn = conn.(*net.TCPConn)
	defer tcpConn.Close()
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(gostIntegrationTimeout)))
	_, err = tcpConn.Write(replayWire)
	require.NoError(t, err)
	require.NoError(t, tcpConn.CloseWrite())
	_, err = io.Copy(io.Discard, tcpConn)
	require.NoError(t, err)
	require.NoError(t, tcpConn.Close())
	awaitGOSTTCPEvents(t, serverMetrics, "", "ERR_REPLAY_CLIENT")
}

type gostUDPIntegrationMetrics struct {
	mu          sync.Mutex
	auth        []string
	status      []string
	closeEvents chan struct{}
}

func newGOSTUDPIntegrationMetrics() *gostUDPIntegrationMetrics {
	return &gostUDPIntegrationMetrics{closeEvents: make(chan struct{}, 8)}
}

func (m *gostUDPIntegrationMetrics) AddAuthentication(id string) {
	m.mu.Lock()
	m.auth = append(m.auth, id)
	m.mu.Unlock()
}

func (m *gostUDPIntegrationMetrics) AddPacketFromClient(status string, _, _ int64) {
	m.mu.Lock()
	m.status = append(m.status, status)
	m.mu.Unlock()
}

func (*gostUDPIntegrationMetrics) AddPacketFromTarget(string, int64, int64) {}
func (m *gostUDPIntegrationMetrics) AddClose()                              { m.closeEvents <- struct{}{} }

func startGOSTUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			reply := bytes.Clone(buffer[:n])
			if n == 0 {
				reply = []byte("empty application datagram received")
			}
			if _, err := conn.WriteToUDP(reply, addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		<-done
	})
	return conn
}

func startGOSTUDPProxy(t *testing.T, ciphers CipherList, assocMetrics UDPAssociationMetrics) *net.UDPConn {
	t.Helper()
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	handler := NewAssociationHandler(ciphers, nil)
	handler.SetTargetPacketListener(MakeTargetUDPListener(allowAll, 500*time.Millisecond, 0))
	done := make(chan struct{})
	go func() {
		PacketServe(serverConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, assocMetrics)
		}, &natTestMetrics{})
		close(done)
	}()
	t.Cleanup(func() {
		require.NoError(t, serverConn.Close())
		<-done
	})
	return serverConn
}

func packGOSTUDPPacket(t *testing.T, key *shadowsocks.EncryptionKey, target string, payload []byte) []byte {
	t.Helper()
	plain := append(bytes.Clone(socks.ParseAddr(target)), payload...)
	ciphertext := make([]byte, key.SaltSize()+len(plain)+key.TagSize())
	packet, err := shadowsocks.Pack(ciphertext, plain, key)
	require.NoError(t, err)
	return packet
}

func exchangeStockUDPPacket(t *testing.T, client net.PacketConn, server net.Addr, target string, spec gostIntegrationCipher, payload []byte) []byte {
	t.Helper()
	clientConn := stockStreamCipher(t, spec).PacketConn(client)
	request := append(bytes.Clone(socks.ParseAddr(target)), payload...)
	_, err := clientConn.WriteTo(request, server)
	require.NoError(t, err)
	response := make([]byte, 64*1024)
	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(gostIntegrationTimeout)))
	n, _, err := clientConn.ReadFrom(response)
	require.NoError(t, err)
	return stripGOSTUDPAddress(t, response[:n], target)
}

func exchangeGOSTUDPPacket(t *testing.T, client net.PacketConn, server net.Addr, key *shadowsocks.EncryptionKey, target string, payload []byte) []byte {
	t.Helper()
	packet := packGOSTUDPPacket(t, key, target, payload)
	_, err := client.WriteTo(packet, server)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(gostIntegrationTimeout)))
	buffer := make([]byte, 64*1024)
	n, _, err := client.ReadFrom(buffer)
	require.NoError(t, err)
	plain, err := shadowsocks.Unpack(nil, buffer[:n], key)
	require.NoError(t, err)
	return stripGOSTUDPAddress(t, plain, target)
}

func stripGOSTUDPAddress(t *testing.T, packet []byte, target string) []byte {
	t.Helper()
	addr := socks.SplitAddr(packet)
	require.NotNil(t, addr, "response must begin with a Shadowsocks destination address")
	require.Equal(t, target, addr.String())
	return bytes.Clone(packet[len(addr):])
}

func TestGOSTMixedUDPServerWithStockPeersAndEmptyApplicationDatagram(t *testing.T) {
	echoConn := startGOSTUDPEcho(t)
	ciphers, keys := makeGOSTIntegrationCipherList(t, gostMixedCiphers)
	assocMetrics := newGOSTUDPIntegrationMetrics()
	serverConn := startGOSTUDPProxy(t, ciphers, assocMetrics)
	target := echoConn.LocalAddr().String()
	server := serverConn.LocalAddr()
	gostKey := keys["gost"]
	wrongKey, err := shadowsocks.NewEncryptionKey(gostMixedCiphers[0].method, "wrong UDP GOST secret")
	require.NoError(t, err)
	badPackets := [][]byte{
		packGOSTUDPPacket(t, wrongKey, target, []byte("wrong UDP key")),
		packGOSTUDPPacket(t, gostKey, target, []byte("tampered UDP packet")),
	}
	badPackets[1][len(badPackets[1])-1] ^= 0x80
	for _, packet := range badPackets {
		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, client.Close()) })
		_, err = client.WriteTo(packet, server)
		require.NoError(t, err)
	}

	for _, spec := range []gostIntegrationCipher{gostMixedCiphers[2], gostMixedCiphers[1]} {
		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, client.Close()) })
		payload := []byte("stock Shadowsocks UDP payload for " + spec.id)
		require.Equal(t, payload, exchangeStockUDPPacket(t, client, server, target, spec, payload))
		require.Equal(t, []byte("empty application datagram received"), exchangeStockUDPPacket(t, client, server, target, spec, nil))
	}

	gostClient, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gostClient.Close()) })
	gostPayload := []byte("Kuznyechik MGM UDP payload")
	require.Equal(t, gostPayload, exchangeGOSTUDPPacket(t, gostClient, server, gostKey, target, gostPayload))
	// The encrypted plaintext still contains the destination header, so an empty
	// application datagram is a non-empty Shadowsocks UDP packet for GOST.
	require.Equal(t, []byte("empty application datagram received"), exchangeGOSTUDPPacket(t, gostClient, server, gostKey, target, nil))

	for i := 0; i < len(gostMixedCiphers)+len(badPackets); i++ {
		select {
		case <-assocMetrics.closeEvents:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for UDP association cleanup")
		}
	}
	assocMetrics.mu.Lock()
	defer assocMetrics.mu.Unlock()
	require.ElementsMatch(t, []string{"aes", "chacha", "gost"}, assocMetrics.auth)
	require.Len(t, assocMetrics.status, 6+len(badPackets))
	require.Equal(t, 2, countStatus(assocMetrics.status, "ERR_CIPHER"))
	for _, status := range assocMetrics.status {
		require.Contains(t, []string{"OK", "ERR_CIPHER"}, status)
	}
}

func countStatus(statuses []string, target string) int {
	count := 0
	for _, status := range statuses {
		if status == target {
			count++
		}
	}
	return count
}

func TestGOSTUnframedEmptyUDPPacketRejected(t *testing.T) {
	key, err := shadowsocks.NewEncryptionKey("kuznyechik-mgm", "empty unframed packet")
	require.NoError(t, err)
	_, err = shadowsocks.Pack(make([]byte, key.SaltSize()+key.TagSize()), nil, key)
	require.ErrorIs(t, err, shadowsocks.ErrEmptyKuznyechikMGMPacket)
}

var _ TCPConnMetrics = (*gostTCPIntegrationMetrics)(nil)
var _ ShadowsocksConnMetrics = (*gostTCPIntegrationMetrics)(nil)
var _ UDPAssociationMetrics = (*gostUDPIntegrationMetrics)(nil)
