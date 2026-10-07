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

// Command compat_client exercises the unmodified released Outline SDK packet
// WebSocket endpoint against the local server integration fixture.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	sdkws "golang.getoutline.org/sdk/x/websocket"
)

func main() {
	mode := flag.String("mode", "packet", "packet or http3")
	wssURL := flag.String("wss-url", "", "packet WebSocket URL")
	serverName := flag.String("server-name", "tunnel.test", "TLS server name")
	outerTLSVersion := flag.String("outer-tls-version", "", "outer TLS version: 1.2 or 1.3")
	caFile := flag.String("ca-file", "", "PEM certificate used to trust local test servers")
	certFile := flag.String("cert-file", "", "test HTTP/3 server certificate")
	keyFile := flag.String("key-file", "", "test HTTP/3 server private key")
	secret := flag.String("secret", "local compatibility test key", "test Shadowsocks secret")
	target := flag.String("target", "", "UDP echo server address for packet mode")
	transferBytes := flag.Int("transfer-bytes", 50*1024*1024, "HTTP/3 response size")
	repetitions := flag.Int("repetitions", 3, "number of HTTP/3 transfers")
	operationTimeout := flag.Duration("timeout", 5*time.Minute, "maximum time for one compatibility run")
	flag.Parse()

	if *wssURL == "" || *caFile == "" {
		fatalf("wss-url and ca-file are required")
	}
	if *mode == "packet" && *target == "" {
		fatalf("target is required in packet mode")
	}
	if *mode == "http3" && (*certFile == "" || *keyFile == "") {
		fatalf("cert-file and key-file are required in http3 mode")
	}
	if err := run(*mode, *wssURL, *serverName, *outerTLSVersion, *caFile, *certFile, *keyFile, *secret, *target, *transferBytes, *repetitions, *operationTimeout); err != nil {
		fatalf("%v", err)
	}
}

func run(mode, wssURL, serverName, outerTLSVersion, caFile, certFile, keyFile, secret, target string, transferBytes, repetitions int, operationTimeout time.Duration) error {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to load test CA certificate")
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
	switch outerTLSVersion {
	case "":
	case "1.2":
		tlsConfig = tlsConfig.Clone()
		tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	case "1.3":
		tlsConfig = tlsConfig.Clone()
		tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	default:
		return fmt.Errorf("unsupported outer TLS version %q", outerTLSVersion)
	}
	parsedURL, err := url.Parse(wssURL)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	streamEndpoint := transport.FuncStreamEndpoint(func(ctx context.Context) (transport.StreamConn, error) {
		conn, err := dialer.DialContext(ctx, "tcp", parsedURL.Host)
		if err != nil {
			return nil, err
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("unexpected stream connection type %T", conn)
		}
		return tcpConn, nil
	})
	connect, err := sdkws.NewPacketEndpoint(wssURL, streamEndpoint, sdkws.WithTLSConfig(tlsConfig))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	streamConn, err := connect(ctx)
	if err != nil {
		return fmt.Errorf("connect packet WebSocket: %w", err)
	}
	key, err := shadowsocks.NewEncryptionKey("chacha20-ietf-poly1305", secret)
	if err != nil {
		_ = streamConn.Close()
		return err
	}
	packetConn := shadowsocks.NewPacketConn(streamConn, key)
	defer packetConn.Close()
	if err := packetConn.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		return err
	}

	switch mode {
	case "packet":
		return verifyPacketEcho(packetConn, target, key)
	case "http3":
		return verifyHTTP3(packetConn, serverName, certFile, keyFile, tlsConfig, transferBytes, repetitions)
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func verifyPacketEcho(conn net.PacketConn, target string, key *shadowsocks.EncryptionKey) error {
	dst, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	targetAddressLength := len(socks.ParseAddr(dst.String()))
	overhead := key.SaltSize() + 16 + targetAddressLength
	for _, cipherSize := range []int{84, 1335, 4092, 4093, 8192, 16384} {
		payloadSize := cipherSize - overhead
		if payloadSize <= 0 {
			return fmt.Errorf("cipher size %d is too small for packet overhead %d", cipherSize, overhead)
		}
		payload := make([]byte, payloadSize)
		for i := range payload {
			payload[i] = byte((i*31 + cipherSize) % 251)
		}
		if n, err := conn.WriteTo(payload, dst); err != nil {
			return fmt.Errorf("write %d-byte packet: %w", cipherSize, err)
		} else if n != len(payload) {
			return fmt.Errorf("short packet write: %d of %d", n, len(payload))
		}
		buffer := make([]byte, 65536)
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return fmt.Errorf("read %d-byte packet echo: %w", cipherSize, err)
		}
		if addr.String() != dst.String() || !bytes.Equal(buffer[:n], payload) {
			return fmt.Errorf("packet echo mismatch for encrypted size %d (got %d bytes from %s)", cipherSize, n, addr)
		}
		fmt.Printf("verified encrypted packet %d bytes\n", cipherSize)
	}
	return nil
}

func verifyHTTP3(tunnel net.PacketConn, serverName, certFile, keyFile string, tlsConfig *tls.Config, transferBytes, repetitions int) error {
	if transferBytes <= 0 || repetitions <= 0 {
		return fmt.Errorf("transfer size and repetition count must be positive")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	pattern := make([]byte, transferBytes)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	want := sha256.Sum256(pattern)
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprint(len(pattern)))
			_, _ = w.Write(pattern)
		}),
	}
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverConn) }()
	defer func() {
		_ = server.Close()
		_ = serverConn.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
		}
	}()
	remote, ok := serverConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected HTTP/3 listener address %T", serverConn.LocalAddr())
	}
	transport := &http3.Transport{
		TLSClientConfig: http3TLSConfig(tlsConfig),
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 30 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlyConnection, error) {
			return quic.DialEarly(ctx, tunnel, remote, tlsConfig, quicConfig)
		},
	}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Minute}
	url := "https://" + serverName + ":" + fmt.Sprint(remote.Port) + "/payload"
	for i := 0; i < repetitions; i++ {
		response, err := client.Get(url)
		if err != nil {
			return fmt.Errorf("HTTP/3 request %d: %w", i+1, err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return fmt.Errorf("HTTP/3 request %d returned %s", i+1, response.Status)
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, response.Body)
		closeErr := response.Body.Close()
		if copyErr != nil {
			return fmt.Errorf("read HTTP/3 response %d: %w", i+1, copyErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if n != int64(transferBytes) || !bytes.Equal(hash.Sum(nil), want[:]) {
			return fmt.Errorf("HTTP/3 response %d integrity mismatch: got %d bytes", i+1, n)
		}
		fmt.Printf("verified HTTP/3 transfer %d/%d: %d bytes sha256=%x\n", i+1, repetitions, n, want)
	}
	return nil
}

// The HTTP/3 tunnel uses inner TLS independently of the outer WebSocket TLS
// connection. QUIC requires TLS 1.3 even when the outer WebSocket uses TLS 1.2.
func http3TLSConfig(outer *tls.Config) *tls.Config {
	inner := outer.Clone()
	inner.MinVersion = tls.VersionTLS13
	inner.MaxVersion = tls.VersionTLS13
	return inner
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
