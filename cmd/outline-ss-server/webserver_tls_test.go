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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/prometheus"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/stretchr/testify/require"
)

func writeTestCertificate(t *testing.T, dir string, serial int64) (*x509.Certificate, string, string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o700))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
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
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return cert, certFile, keyFile
}

func TestLoadWebServerTLSConfigs(t *testing.T) {
	dir := t.TempDir()
	_, certFile, keyFile := writeTestCertificate(t, dir, 1)

	configs, err := loadWebServerTLSConfigs([]WebServerConfig{{ID: "plain"}})
	require.NoError(t, err)
	require.Empty(t, configs)

	configs, err = loadWebServerTLSConfigs([]WebServerConfig{{ID: "native", TLSCertFile: certFile, TLSKeyFile: keyFile}})
	require.NoError(t, err)
	require.Len(t, configs, 1)
	require.Len(t, configs["native"].Certificates, 1)
	require.Equal(t, uint16(tls.VersionTLS12), configs["native"].MinVersion)
	require.True(t, configs["native"].DynamicRecordSizingDisabled)

	_, err = loadWebServerTLSConfigs([]WebServerConfig{{ID: "invalid", TLSCertFile: filepath.Join(dir, "missing.pem"), TLSKeyFile: keyFile}})
	require.ErrorContains(t, err, "web server `invalid`")
}

func TestTLSCertificateReloadKeepsActiveCertificateOnFailure(t *testing.T) {
	dir := t.TempDir()
	certA, certFile, keyFile := writeTestCertificate(t, dir, 101)
	certB, certBFile, keyBFile := writeTestCertificate(t, filepath.Join(dir, "next"), 102)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certA)
	rootPool.AddCert(certB)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	configFile := filepath.Join(dir, "config.yaml")
	config := "web:\n  servers:\n    - id: test-web\n      listen: [\"" + address + "\"]\n      tls_cert_file: \"" + certFile + "\"\n      tls_key_file: \"" + keyFile + "\"\n"
	require.NoError(t, os.WriteFile(configFile, []byte(config), 0o600))
	serviceMetrics, err := prometheus.NewServiceMetrics(nil)
	require.NoError(t, err)
	server := &OutlineServer{
		lnManager:      service.NewListenerManager(),
		natTimeout:     time.Minute,
		serverMetrics:  newPrometheusServerMetrics(),
		serviceMetrics: serviceMetrics,
		replayCache:    service.NewReplayCache(100),
	}
	t.Cleanup(func() { _ = server.Stop() })
	require.NoError(t, server.loadConfig(configFile))

	peerSerial := func() *big.Int {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{
			RootCAs:    rootPool,
			ServerName: "tunnel.test",
			MinVersion: tls.VersionTLS12,
		})
		require.NoError(t, err)
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber
	}
	require.Equal(t, certA.SerialNumber, peerSerial())

	require.NoError(t, os.WriteFile(certFile, []byte("not a certificate"), 0o600))
	require.Error(t, server.loadConfig(configFile))
	require.Equal(t, certA.SerialNumber, peerSerial())

	certPEM, err := os.ReadFile(certBFile)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(keyBFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))
	require.NoError(t, server.loadConfig(configFile))
	require.Equal(t, certB.SerialNumber, peerSerial())
}
