//go:build integration

package outlinecaddy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/gorilla/websocket"
	_ "github.com/mholt/caddy-l4"
	"github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4http"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"go.uber.org/zap"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	sdkwebsocket "golang.getoutline.org/sdk/x/websocket"
)

const (
	integrationSecret = "dobby-local-compatibility-key"
	tunnelTestHost    = "tunnel.test"
)

var (
	caddyConfigMu       sync.Mutex
	streamDials         atomic.Int64
	packetReads         atomic.Int64
	legacyUpgradeErrors atomic.Int64
	legacyUpgradeDetail atomic.Value
)

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  "layer4.handlers.compat_test_shadowsocks",
		New: func() caddy.Module { return new(compatTestShadowsocksHandler) },
	})
	caddy.RegisterModule(ModuleRegistration{
		ID:  "http.handlers.compat_test_legacy_sdk_packet",
		New: func() caddy.Module { return new(compatTestLegacySDKPacketHandler) },
	})
}

// TestCaddyPacketCompatibility exercises the built Caddy module through real
// HTTP and TLS listeners. The compatibility binaries are deliberately built
// from isolated, pinned SDK manifests by scripts/review.sh.
func TestCaddyPacketCompatibility(t *testing.T) {
	releasedClient := requiredEnv(t, "OUTLINE_COMPAT_RELEASED_CLIENT")
	stockClient := requiredEnv(t, "OUTLINE_COMPAT_STOCK_CLIENT")
	for _, binary := range []string{releasedClient, stockClient} {
		if _, err := os.Stat(binary); err != nil {
			t.Fatalf("compatibility client is unavailable: %v", err)
		}
	}

	certs := makeIntegrationCertificate(t)
	udpEcho := startUDPEcho(t)
	tcpEcho := startTCPEcho(t)

	for _, version := range []string{"1.2", "1.3"} {
		t.Run("outer_tls_"+strings.ReplaceAll(version, ".", "_"), func(t *testing.T) {
			server := startIntegrationCaddy(t, certs, version, true, true, "static-ok")
			assertHTTPBody(t, server.client, server.url("/static.txt"), "static-ok")
			assertHTTPBody(t, server.client, server.url("/account.txt"), "account-ok")
			assertStreamRoute(t, server, tcpEcho.Addr().String())

			for name, binary := range map[string]string{
				"released": releasedClient,
				"stock":    stockClient,
			} {
				t.Run(name+"_packets", func(t *testing.T) {
					streamDialCount := streamDials.Load()
					output := runCompatClient(t, binary, "-mode", "packet", "-wss-url", server.wssURL("/packet"),
						"-server-name", tunnelTestHost, "-outer-tls-version", version,
						"-ca-file", certs.caFile, "-target", udpEcho.LocalAddr().String(), "-secret", integrationSecret)
					for _, packetSize := range []string{"84", "1335", "4092", "4093", "8192", "16384"} {
						if !strings.Contains(output, "verified encrypted packet "+packetSize+" bytes") {
							t.Fatalf("compatibility client omitted successful packet size %s", packetSize)
						}
					}
					if streamDials.Load() != streamDialCount {
						t.Fatal("packet mode attempted a TCP target fallback")
					}
				})
				t.Run(name+"_http3", func(t *testing.T) {
					streamDialCount := streamDials.Load()
					output := runCompatClient(t, binary, "-mode", "http3", "-wss-url", server.wssURL("/packet"),
						"-server-name", tunnelTestHost, "-outer-tls-version", version,
						"-ca-file", certs.caFile, "-cert-file", certs.certFile, "-key-file", certs.keyFile,
						"-target", udpEcho.LocalAddr().String(), "-secret", integrationSecret,
						"-transfer-bytes", "50000000", "-repetitions", "3")
					if got := strings.Count(output, "verified HTTP/3 transfer "); got != 3 {
						t.Fatalf("compatibility client reported %d HTTP/3 transfers; want 3", got)
					}
					for _, line := range strings.Split(output, "\n") {
						if strings.HasPrefix(line, "verified HTTP/3 transfer ") {
							t.Logf("%s outer TLS %s: %s", name, version, line)
						}
					}
					if streamDials.Load() != streamDialCount {
						t.Fatal("HTTP/3 packet mode attempted a TCP target fallback")
					}
				})
			}

			if version == "1.3" {
				assertTLSVerificationFailures(t, releasedClient, server, certs, udpEcho.LocalAddr().String())
				assertReloadLifecycle(t, server, certs, version, releasedClient, udpEcho.LocalAddr().String())
			}
		})
	}

	t.Run("without_access_logs", func(t *testing.T) {
		server := startIntegrationCaddy(t, certs, "1.3", true, false, "no-logs-static")
		streamDialCount := streamDials.Load()
		assertStreamRoute(t, server, tcpEcho.Addr().String())
		if streamDials.Load() != streamDialCount+1 {
			t.Fatal("no-access-logs stream route did not dial exactly one TCP target")
		}
		output := runCompatClient(t, releasedClient, "-mode", "packet", "-wss-url", server.wssURL("/packet"),
			"-server-name", tunnelTestHost, "-outer-tls-version", "1.3", "-ca-file", certs.caFile,
			"-target", udpEcho.LocalAddr().String(), "-secret", integrationSecret)
		for _, packetSize := range []string{"84", "1335", "4092", "4093", "8192", "16384"} {
			if !strings.Contains(output, "verified encrypted packet "+packetSize+" bytes") {
				t.Fatalf("no-access-logs compatibility client omitted successful packet size %s", packetSize)
			}
		}
		if streamDials.Load() != streamDialCount+1 {
			t.Fatal("no-access-logs packet route attempted a TCP target fallback")
		}
	})

	// First record whether the old SDK Upgrade also fails at Caddy's hijack
	// wrapper. Then disable access logging and exercise the packet transport to
	// isolate the TLS record corruption baseline from any Hijacker limitation.
	t.Run("legacy_sdk_upgrade_baseline", func(t *testing.T) {
		t.Run("access_log_hijack", func(t *testing.T) {
			loggedServer := startIntegrationCaddy(t, certs, "1.3", false, true, "legacy-logged")
			upgradeErrorsBefore := legacyUpgradeErrors.Load()
			loggedOutput, loggedErr := runCompatClientResult(t, releasedClient, "-mode", "packet", "-wss-url", loggedServer.wssURL("/legacy"),
				"-server-name", tunnelTestHost, "-outer-tls-version", "1.3", "-ca-file", certs.caFile,
				"-target", udpEcho.LocalAddr().String(), "-secret", integrationSecret, "-timeout", "5s")
			if loggedErr != nil && legacyUpgradeErrors.Load() > upgradeErrorsBefore {
				detail, _ := legacyUpgradeDetail.Load().(string)
				t.Logf("legacy direct SDK Upgrade failed before packet transport (%s; %s)", detail, legacyBaselineDiagnostic(loggedOutput, loggedErr))
			} else if failureSize := legacyPacketFailureSize(loggedOutput); loggedErr != nil && failureSize != "" {
				t.Logf("legacy direct SDK Upgrade reached packet transport and reproduced TLS record failure at encrypted size %s", failureSize)
			} else {
				t.Fatalf("legacy direct SDK control did not reproduce an upgrade or packet failure (client=%s)", legacyBaselineDiagnostic(loggedOutput, loggedErr))
			}
		})

		t.Run("packet_record_baseline_without_access_logs", func(t *testing.T) {
			server := startIntegrationCaddy(t, certs, "1.3", false, false, "legacy-baseline")
			failed := 0
			for _, binary := range []string{releasedClient, stockClient} {
				output, err := runCompatClientResult(t, binary, "-mode", "packet", "-wss-url", server.wssURL("/legacy-framing"),
					"-server-name", tunnelTestHost, "-outer-tls-version", "1.3",
					"-ca-file", certs.caFile, "-target", udpEcho.LocalAddr().String(),
					"-secret", integrationSecret, "-timeout", "5s")
				failureSize := legacyPacketFailureSize(output)
				if err == nil || failureSize == "" {
					t.Errorf("legacy SDK Upgrade did not reproduce a packet echo/read failure after encrypted size 84 for %s (client=%s)", filepath.Base(binary), legacyBaselineDiagnostic(output, err))
				} else {
					failed++
					t.Logf("legacy SDK TLS packet record failure reproduced for %s at encrypted size %s (%s)", filepath.Base(binary), failureSize, legacyBaselineDiagnostic(output, err))
				}
			}
			if failed == 0 {
				t.Fatal("legacy SDK Upgrade baseline did not reproduce the TLS packet failure")
			}
			h3Output, h3Err := runCompatClientResult(t, releasedClient, "-mode", "http3", "-wss-url", server.wssURL("/legacy-framing"),
				"-server-name", tunnelTestHost, "-outer-tls-version", "1.3", "-ca-file", certs.caFile,
				"-cert-file", certs.certFile, "-key-file", certs.keyFile, "-target", udpEcho.LocalAddr().String(),
				"-secret", integrationSecret, "-transfer-bytes", "50000000", "-repetitions", "3", "-timeout", "15s")
			transferCount := legacyHTTP3SuccessCount(h3Output)
			if failure := legacyHTTP3Failure(h3Output, h3Err); failure != "" {
				t.Logf("legacy SDK HTTP/3 packet transport failure observed: %s", failure)
			} else if h3Err == nil && transferCount == 3 {
				for _, line := range strings.Split(h3Output, "\n") {
					if strings.HasPrefix(line, "verified HTTP/3 transfer ") {
						t.Logf("legacy SDK HTTP/3 baseline: %s", line)
					}
				}
			} else {
				t.Fatalf("legacy SDK HTTP/3 baseline completed without three verified transfers or failed outside HTTP/3 transport (verified=%d, client=%s)", transferCount, legacyBaselineDiagnostic(h3Output, h3Err))
			}
		})

		t.Run("missing_hook_fails_closed", func(t *testing.T) {
			noHookLogged := startIntegrationCaddy(t, certs, "1.3", false, true, "no-hook")
			assertPacketRouteFailsClosed(t, noHookLogged)
		})
	})

	if packetReads.Load() == 0 {
		t.Fatal("no packet reached the loopback-only integration listener")
	}
	if streamDials.Load() == 0 {
		t.Fatal("the stream compatibility route did not dial its loopback target")
	}
	if !t.Failed() {
		t.Log("Caddy compatibility matrix passed: released and stock clients, outer TLS 1.2/1.3, packet and stream routes, file_server/account checks, reload retention, and legacy failure baseline")
	}
}

type integrationCerts struct {
	caFile   string
	certFile string
	keyFile  string
	certPEM  string
	keyPEM   string
}

type integrationServer struct {
	address    string
	staticRoot string
	caFile     string
	client     *http.Client
	tlsConfig  *tls.Config
}

func (s integrationServer) url(path string) string {
	return "https://" + s.address + path
}

func (s integrationServer) wssURL(path string) string {
	return "wss://" + s.address + path
}

func makeIntegrationCertificate(t *testing.T) integrationCerts {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Dobby local compatibility test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: tunnelTestHost},
		DNSNames:     []string{tunnelTestHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	dir := t.TempDir()
	result := integrationCerts{
		caFile: filepath.Join(dir, "ca.pem"), certFile: filepath.Join(dir, "cert.pem"),
		keyFile: filepath.Join(dir, "key.pem"), certPEM: string(certPEM), keyPEM: string(keyPEM),
	}
	for path, data := range map[string][]byte{result.caFile: caPEM, result.certFile: certPEM, result.keyFile: keyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packetReads.Add(1)
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn
}

func startTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func startIntegrationCaddy(t *testing.T, certs integrationCerts, outerVersion string, packetTLSHook, accessLogs bool, staticBody string) integrationServer {
	t.Helper()
	caddyConfigMu.Lock()
	t.Cleanup(func() {
		_ = caddy.Stop()
		caddyConfigMu.Unlock()
	})

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	staticRoot := writeStaticRoot(t, staticBody)
	config := integrationCaddyConfig(certs, address, outerVersion, packetTLSHook, accessLogs, staticRoot)
	if err := caddy.Load(config, true); err != nil {
		t.Fatalf("load real Caddy integration fixture: %v", err)
	}
	// Trust only the local generated CA, the same file used by the SDK clients.
	caPEM, err := os.ReadFile(certs.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not load local test CA")
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: tunnelTestHost, MinVersion: tlsVersion(outerVersion), MaxVersion: tlsVersion(outerVersion)}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	t.Cleanup(func() { client.CloseIdleConnections() })
	return integrationServer{address: address, staticRoot: staticRoot, caFile: certs.caFile, client: client, tlsConfig: tlsConfig}
}

func integrationCaddyConfig(certs integrationCerts, address, version string, packetTLSHook, accessLogs bool, staticRoot string) []byte {
	policy := map[string]any{"protocol_min": "tls" + version, "protocol_max": "tls" + version}
	wrappers := []any{}
	if packetTLSHook {
		wrappers = append(wrappers, map[string]any{"wrapper": "outline_packet_tls"})
		wrappers = append(wrappers, map[string]any{"wrapper": "tls"})
	}
	routes := []any{
		map[string]any{"match": []any{map[string]any{"path": []string{"/packet"}}}, "handle": []any{map[string]any{"handler": "websocket2layer4", "type": "packet", "connection_handler": "compat"}}, "terminal": true},
		map[string]any{"match": []any{map[string]any{"path": []string{"/stream"}}}, "handle": []any{map[string]any{"handler": "websocket2layer4", "type": "stream", "connection_handler": "compat"}}, "terminal": true},
		map[string]any{"match": []any{map[string]any{"path": []string{"/legacy"}}}, "handle": []any{map[string]any{"handler": "compat_test_legacy_sdk_packet", "connection_handler": "compat"}}, "terminal": true},
		map[string]any{"match": []any{map[string]any{"path": []string{"/legacy-framing"}}}, "handle": []any{map[string]any{"handler": "compat_test_legacy_sdk_packet", "connection_handler": "compat", "response_controller_hijack": true}}, "terminal": true},
		map[string]any{"match": []any{map[string]any{"path": []string{"/static.txt"}}}, "handle": []any{map[string]any{"handler": "file_server", "root": staticRoot}}, "terminal": true},
		map[string]any{"match": []any{map[string]any{"path": []string{"/account.txt"}}}, "handle": []any{map[string]any{"handler": "file_server", "root": staticRoot}}, "terminal": true},
	}
	config := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"writer": map[string]any{"output": "discard"}, "level": "ERROR"}}},
		"apps": map[string]any{
			"tls": map[string]any{"certificates": map[string]any{"load_pem": []any{map[string]any{"certificate": certs.certPEM, "key": certs.keyPEM}}}},
			"http": map[string]any{"servers": map[string]any{"compat": map[string]any{
				"listen": []string{address}, "tls_connection_policies": []any{policy},
				"protocols": []string{"h1", "h2"}, "automatic_https": map[string]any{"disable": true}, "routes": routes,
			}}},
			"outline": map[string]any{"connection_handlers": []any{map[string]any{"name": "compat", "handle": map[string]any{
				"handler": "compat_test_shadowsocks", "keys": []any{map[string]any{"id": "compat", "cipher": "chacha20-ietf-poly1305", "secret": integrationSecret}},
			}}}},
		},
	}
	if packetTLSHook {
		config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["compat"].(map[string]any)["listener_wrappers"] = wrappers
	}
	if accessLogs {
		config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["compat"].(map[string]any)["logs"] = map[string]any{}
	}
	raw, _ := json.Marshal(config)
	return raw
}

func assertHTTPBody(t *testing.T, client *http.Client, url, want string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed", safePath(url))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		t.Fatal("could not read static response")
	}
	if response.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("GET %s returned %d and %q; want 200 and %q", safePath(url), response.StatusCode, string(body), want)
	}
}

func assertStreamRoute(t *testing.T, server integrationServer, target string) {
	t.Helper()
	connect, err := sdkwebsocket.NewStreamEndpoint(server.wssURL("/stream"), transport.FuncStreamEndpoint(func(ctx context.Context) (transport.StreamConn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", server.address)
		if err != nil {
			return nil, err
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("unexpected connection type %T", conn)
		}
		return tcpConn, nil
	}), sdkwebsocket.WithTLSConfig(server.client.Transport.(*http.Transport).TLSClientConfig))
	if err != nil {
		t.Fatal("create stream WebSocket endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := connect(ctx)
	if err != nil {
		t.Fatal("connect stream WebSocket route")
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal("set stream route deadline")
	}
	key, err := shadowsocks.NewEncryptionKey("chacha20-ietf-poly1305", integrationSecret)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("stream-loopback-echo")
	request := append(socks.ParseAddr(target), payload...)
	writer := shadowsocks.NewWriter(stream, key)
	if _, err := writer.Write(request); err != nil {
		t.Fatal("write stream Shadowsocks request")
	}
	got := make([]byte, len(payload))
	reader := shadowsocks.NewReader(stream, key)
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal("read stream Shadowsocks response")
	}
	if string(got) != string(payload) {
		t.Fatalf("stream Shadowsocks response mismatch: got %d bytes", len(got))
	}
}

func assertTLSVerificationFailures(t *testing.T, binary string, server integrationServer, certs integrationCerts, target string) {
	t.Helper()
	wrongCA := filepath.Join(t.TempDir(), "wrong-ca.pem")
	wrongCAPEM := makeUnrelatedRoot(t)
	if err := os.WriteFile(wrongCA, wrongCAPEM, 0600); err != nil {
		t.Fatal(err)
	}
	baseArgs := []string{"-mode", "packet", "-wss-url", server.wssURL("/packet"), "-outer-tls-version", "1.3", "-target", target, "-secret", integrationSecret}
	if _, err := runCompatClientResult(t, binary, append(baseArgs, "-server-name", tunnelTestHost, "-ca-file", wrongCA)...); err == nil {
		t.Fatal("client accepted an untrusted Caddy certificate")
	}
	if _, err := runCompatClientResult(t, binary, append(baseArgs, "-server-name", "wrong.tunnel.test", "-ca-file", certs.caFile)...); err == nil {
		t.Fatal("client accepted a hostname that does not match the Caddy certificate")
	}
}

func assertPacketRouteFailsClosed(t *testing.T, server integrationServer) {
	t.Helper()
	dialer := websocket.Dialer{TLSClientConfig: server.client.Transport.(*http.Transport).TLSClientConfig}
	conn, response, err := dialer.Dial(server.wssURL("/packet"), nil)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusInternalServerError {
		if response != nil {
			t.Fatalf("packet route without TLS hook returned HTTP %d; expected 500 before upgrade", response.StatusCode)
		}
		t.Fatal("packet route without TLS hook did not fail before WebSocket upgrade")
	}
}

func assertReloadLifecycle(t *testing.T, server integrationServer, certs integrationCerts, version, clientBinary, udpTarget string) {
	t.Helper()
	assertHTTPBody(t, server.client, server.url("/static.txt"), "static-ok")
	reloadedRoot := writeStaticRoot(t, "static-reloaded")
	if err := caddy.Load(integrationCaddyConfig(certs, server.address, version, true, true, reloadedRoot), true); err != nil {
		t.Fatalf("successful Caddy config reload failed: %v", err)
	}
	server.client.CloseIdleConnections()
	assertHTTPBody(t, server.client, server.url("/static.txt"), "static-reloaded")
	assertReloadedPacketRoute(t, clientBinary, server, udpTarget)
	invalid := []byte(`{"admin":{"disabled":true},"apps":{"http":{"servers":{"compat":{"listen":["not-a-valid-listener"]}}}}}`)
	if err := caddy.Load(invalid, true); err == nil {
		t.Fatal("invalid Caddy reload unexpectedly succeeded")
	}
	server.client.CloseIdleConnections()
	assertHTTPBody(t, server.client, server.url("/static.txt"), "static-reloaded")
	assertReloadedPacketRoute(t, clientBinary, server, udpTarget)
}

func assertReloadedPacketRoute(t *testing.T, binary string, server integrationServer, target string) {
	t.Helper()
	streamDialCount := streamDials.Load()
	output := runCompatClient(t, binary, "-mode", "packet", "-wss-url", server.wssURL("/packet"),
		"-server-name", tunnelTestHost, "-outer-tls-version", "1.3", "-ca-file", server.caFile,
		"-target", target, "-secret", integrationSecret, "-timeout", "15s")
	for _, size := range []string{"84", "1335", "4092", "4093", "8192", "16384"} {
		if !strings.Contains(output, "verified encrypted packet "+size+" bytes") {
			t.Fatalf("packet route stopped working after reload; missing size %s", size)
		}
	}
	if streamDials.Load() != streamDialCount {
		t.Fatal("packet route after reload attempted a TCP target fallback")
	}
}

func runCompatClient(t *testing.T, binary string, args ...string) string {
	t.Helper()
	output, err := runCompatClientResult(t, binary, args...)
	if err != nil {
		t.Fatalf("compatibility client failed for %s: %s", filepath.Base(binary), sanitizeClientError(err))
	}
	return output
}

func runCompatClientResult(t *testing.T, binary string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("client timed out")
	}
	return string(output), err
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("required integration input %s is missing; run scripts/review.sh", name)
	}
	return value
}

func safePath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	return parsed.Path
}

func sanitizeClientError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "process returned a failure status"
}

func writeStaticRoot(t *testing.T, staticBody string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{"static.txt": staticBody, "account.txt": "account-ok"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func makeUnrelatedRoot(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "Unrelated local root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func legacyPacketFailureSize(output string) string {
	if !strings.Contains(output, "verified encrypted packet 84 bytes") {
		return ""
	}
	for _, size := range []string{"1335", "4092", "4093", "8192", "16384"} {
		if strings.Contains(output, "read "+size+"-byte packet echo:") ||
			strings.Contains(output, "write "+size+"-byte packet:") ||
			strings.Contains(output, "packet echo mismatch for encrypted size "+size) {
			return size
		}
	}
	return ""
}

func legacyBaselineDiagnostic(output string, err error) string {
	firstEcho := strings.Contains(output, "verified encrypted packet 84 bytes")
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"write ", "read ", "packet echo mismatch for encrypted size ", "connect packet WebSocket:"} {
			if strings.HasPrefix(line, prefix) {
				return fmt.Sprintf("first-84-byte-echo=%t, transport-error=%q, process-failed=%t", firstEcho, line, err != nil)
			}
		}
	}
	return fmt.Sprintf("first-84-byte-echo=%t, transport-error=unclassified, process-failed=%t", firstEcho, err != nil)
}

func legacyHTTP3Failure(output string, err error) string {
	if err == nil {
		return ""
	}
	switch {
	case strings.Contains(output, "HTTP/3 request "):
		return "request failed"
	case strings.Contains(output, "read HTTP/3 response "):
		return "response read failed"
	case strings.Contains(output, "HTTP/3 response "):
		return "response validation failed"
	default:
		return ""
	}
}

func legacyHTTP3SuccessCount(output string) int {
	count := 0
	for i := 1; i <= 3; i++ {
		prefix := fmt.Sprintf("verified HTTP/3 transfer %d/3: 50000000 bytes sha256=ac133d1cddbbf3141b9272ab8e4bd153fa3142187b11746db5df561fca4e0056", i)
		if strings.Contains(output, prefix) {
			count++
		}
	}
	return count
}

func tlsVersion(version string) uint16 {
	if version == "1.2" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

type compatTestShadowsocksHandler struct {
	ShadowsocksHandler
}

func (h *compatTestShadowsocksHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "layer4.handlers.compat_test_shadowsocks"}
}

func (h *compatTestShadowsocksHandler) Provision(ctx caddy.Context) error {
	if err := h.ShadowsocksHandler.Provision(ctx); err != nil {
		return err
	}
	h.associationHandler.SetTargetPacketListener(loopbackPacketListener{})
	h.streamHandler.SetTargetDialer(transport.FuncStreamDialer(func(ctx context.Context, address string) (transport.StreamConn, error) {
		target, err := net.ResolveTCPAddr("tcp", address)
		if err != nil || !target.IP.IsLoopback() {
			return nil, fmt.Errorf("integration fixture refuses non-loopback stream target")
		}
		streamDials.Add(1)
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", target.String())
		if err != nil {
			return nil, err
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("integration stream dial returned %T", conn)
		}
		return tcpConn, nil
	}))
	return nil
}

type loopbackPacketListener struct{}

func (loopbackPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	packetConn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return loopbackOnlyPacketConn{PacketConn: packetConn}, nil
}

type loopbackOnlyPacketConn struct {
	net.PacketConn
}

func (c loopbackOnlyPacketConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || !udpAddr.IP.IsLoopback() {
		return 0, errors.New("integration fixture refuses non-loopback packet target")
	}
	return c.PacketConn.WriteTo(packet, addr)
}

func (c loopbackOnlyPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(packet)
		if err != nil {
			return n, addr, err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if ok && udpAddr.IP.IsLoopback() {
			return n, addr, nil
		}
	}
}

type compatTestLegacySDKPacketHandler struct {
	ConnectionHandler        string `json:"connection_handler,omitempty"`
	ResponseControllerHijack bool   `json:"response_controller_hijack,omitempty"`
	compiledHandler          layer4.NextHandler
	logger                   *slog.Logger
	zlogger                  *zap.Logger
}

func (h *compatTestLegacySDKPacketHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.compat_test_legacy_sdk_packet"}
}

func (h *compatTestLegacySDKPacketHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()
	h.zlogger = ctx.Logger()
	mod, err := ctx.AppIfConfigured(outlineModuleName)
	if err != nil {
		return err
	}
	app, ok := mod.(*OutlineApp)
	if !ok {
		return fmt.Errorf("outline app has unexpected type %T", mod)
	}
	for _, handler := range app.Handlers {
		if handler.Name == h.ConnectionHandler {
			h.compiledHandler = handler
			break
		}
	}
	if h.compiledHandler == nil {
		return fmt.Errorf("legacy test route has no connection handler")
	}
	return nil
}

func (h *compatTestLegacySDKPacketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if h.ResponseControllerHijack {
		w = legacyHijackResponseWriter{ResponseWriter: w}
	}
	conn, err := sdkwebsocket.Upgrade(w, r, nil)
	if err != nil {
		legacyUpgradeErrors.Add(1)
		legacyUpgradeDetail.Store(legacyUpgradeFailureKind(err))
		return fmt.Errorf("legacy SDK WebSocket upgrade failed")
	}
	var streamConn transport.StreamConn = conn
	if clientIP := requestClientIP(r); clientIP != nil {
		streamConn = &replaceAddrConn{StreamConn: streamConn, raddr: &net.UDPAddr{IP: clientIP}}
	}
	serializedConn := &legacySerializedStreamConn{StreamConn: streamConn}
	defer serializedConn.Close()
	cx := layer4.WrapConnection(serializedConn, nil, h.zlogger)
	cx.SetVar(outlineConnectionTypeCtxKey, PacketConnectionType)
	return h.compiledHandler.Handle(cx, nil)
}

func legacyUpgradeFailureKind(err error) string {
	if strings.Contains(err.Error(), "Hijacker") {
		return "Caddy response writer did not expose http.Hijacker"
	}
	return "SDK WebSocket Upgrade returned an error"
}

// legacyHijackResponseWriter supplies the direct Hijacker interface required
// by the old SDK while delegating Caddy's wrapped writer through its supported
// ResponseController path. This isolates the old SDK's packet framing behavior
// from Caddy's separate response-writer interface limitation.
type legacyHijackResponseWriter struct {
	http.ResponseWriter
}

func (w legacyHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w legacyHijackResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// legacySerializedStreamConn guards the old SDK's unsynchronized half-close
// bookkeeping while leaving its WebSocket frame reads and writes untouched.
type legacySerializedStreamConn struct {
	transport.StreamConn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (c *legacySerializedStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.StreamConn.Read(p)
}

func (c *legacySerializedStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.StreamConn.Write(p)
}

func (c *legacySerializedStreamConn) CloseRead() error {
	_ = c.StreamConn.SetReadDeadline(time.Now())
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.StreamConn.CloseRead()
}

func (c *legacySerializedStreamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.StreamConn.CloseWrite()
}

func (c *legacySerializedStreamConn) Close() error {
	_ = c.StreamConn.SetReadDeadline(time.Now())
	c.writeMu.Lock()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	defer c.writeMu.Unlock()
	return c.StreamConn.Close()
}

var _ caddyhttp.MiddlewareHandler = (*compatTestLegacySDKPacketHandler)(nil)
