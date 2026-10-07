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

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/internal/packetwebsocket"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/stretchr/testify/require"
)

const compatSecret = "local Outline SDK compatibility test key"

func TestReleasedOutlineSDKPacketAndHTTP3Compatibility(t *testing.T) {
	helper := os.Getenv("OUTLINE_COMPAT_CLIENT_BIN")
	if helper == "" {
		t.Skip("set OUTLINE_COMPAT_CLIENT_BIN to the pinned released-SDK helper to run this compatibility test")
	}
	if _, err := os.Stat(helper); err != nil {
		t.Fatalf("OUTLINE_COMPAT_CLIENT_BIN: %v", err)
	}

	certPEM, certificate, keyPEM := makeCompatCertificate(t)
	workDir := t.TempDir()
	caFile := filepath.Join(workDir, "test-ca.pem")
	certFile := filepath.Join(workDir, "fullchain.pem")
	keyFile := filepath.Join(workDir, "privkey.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	echoDone := make(chan struct{})
	go runUDPEcho(echoConn, echoDone)
	t.Cleanup(func() {
		_ = echoConn.Close()
		<-echoDone
	})

	ciphers, err := service.MakeTestCiphers([]string{compatSecret})
	require.NoError(t, err)
	association := service.NewAssociationHandler(ciphers, &fakeShadowsocksMetrics{})
	association.SetTargetIPValidator(func(net.IP) error { return nil })
	mux := http.NewServeMux()
	mux.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
		clientAddrPort, err := onet.ParseAddrPortOrIP(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid client address", http.StatusBadRequest)
			return
		}
		conn, err := packetwebsocket.Upgrade(w, r, true, net.UDPAddrFromAddrPort(clientAddrPort))
		if err != nil {
			return
		}
		defer conn.Close()
		association.HandleAssociation(r.Context(), conn, &service.NoOpUDPAssociationMetrics{})
	})
	wsServer := httptest.NewUnstartedServer(mux)
	wsServer.EnableHTTP2 = false
	wsServer.TLS = &tls.Config{
		Certificates:                []tls.Certificate{certificate},
		MinVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	}
	wsServer.StartTLS()
	t.Cleanup(wsServer.Close)
	websocketURL, err := url.Parse(wsServer.URL)
	require.NoError(t, err)
	websocketURL.Scheme = "wss"
	websocketURL.Path = "/packets"

	runCompatClient(t, helper,
		"--mode", "packet",
		"--wss-url", websocketURL.String(),
		"--server-name", "tunnel.test",
		"--ca-file", caFile,
		"--cert-file", certFile,
		"--key-file", keyFile,
		"--secret", compatSecret,
		"--target", echoConn.LocalAddr().String(),
	)
	runCompatClient(t, helper,
		"--mode", "http3",
		"--wss-url", websocketURL.String(),
		"--server-name", "tunnel.test",
		"--ca-file", caFile,
		"--cert-file", certFile,
		"--key-file", keyFile,
		"--secret", compatSecret,
		"--transfer-bytes", strconv.Itoa(50*1024*1024),
		"--repetitions", "3",
	)
}

func makeCompatCertificate(t *testing.T) ([]byte, tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7001),
		Subject:               pkix.Name{CommonName: "tunnel.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		DNSNames:              []string{"tunnel.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return certPEM, certificate, keyPEM
}

func runUDPEcho(conn *net.UDPConn, done chan<- struct{}) {
	defer close(done)
	buffer := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if _, err := conn.WriteToUDP(buffer[:n], addr); err != nil {
			return
		}
	}
}

func runCompatClient(t *testing.T, helper string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, helper, args...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("released SDK client exceeded its time limit: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("released SDK client failed: %v\n%s", err, output)
	}
	if len(output) > 0 {
		t.Log(strings.TrimSpace(string(output)))
	}
}
