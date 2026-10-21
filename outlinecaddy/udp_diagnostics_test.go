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

package outlinecaddy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/tunnel-server/service"
)

func TestUDPDiagnosticsLifecycleCountersAndEventCorrelation(t *testing.T) {
	diagnostics := newUDPDiagnostics()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.activeHandlers))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.openTargetSockets))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetsAfterHandler))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetReadsAfterHandler))

	association := diagnostics.begin(logger, "wss")
	require.Equal(t, float64(1), promtest.ToFloat64(diagnostics.activeHandlers))
	associationMetrics := &diagnosticUDPAssociationMetrics{
		inner:       &service.NoOpUDPAssociationMetrics{},
		association: association,
	}
	associationMetrics.AddAuthentication("SECRET_ACCESS_KEY")
	associationMetrics.AddPacketFromClient("OK", 11, 7)
	associationMetrics.AddPacketFromTarget("ERR_READ", 5, 0)

	ctx := contextWithUDPDiagnostics(context.Background(), association)
	packetConn, err := (&diagnosticPacketListener{inner: diagnosticTestPacketListener{conn: &diagnosticTestPacketConn{}}}).ListenPacket(ctx)
	require.NoError(t, err)
	require.Equal(t, float64(1), promtest.ToFloat64(diagnostics.openTargetSockets))

	association.handlerCompleted()
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.activeHandlers))
	require.Equal(t, float64(1), promtest.ToFloat64(diagnostics.targetsAfterHandler))

	// Target accounting after the handler returns is correlated once without
	// producing a packet-level log for every packet.
	associationMetrics.AddPacketFromTarget("OK", 13, 17)
	associationMetrics.AddPacketFromTarget("OK", 19, 23)
	require.NoError(t, packetConn.Close())
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.openTargetSockets))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetsAfterHandler))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetReadsAfterHandler))

	output := logs.String()
	require.Contains(t, output, "udp_association_start")
	require.Contains(t, output, "udp_target_socket_created")
	require.Contains(t, output, "udp_association_handler_complete")
	require.Contains(t, output, "udp_association_activity_after_handler")
	require.Contains(t, output, "udp_target_socket_close_returned")
	require.Equal(t, 1, strings.Count(output, "udp_association_activity_after_handler"))
	require.Contains(t, output, "client_packets=1")
	require.Contains(t, output, "target_packets=1")
	require.Contains(t, output, "client_proxy_bytes=11")
	require.Contains(t, output, "proxy_target_bytes=7")
	require.Contains(t, output, "target_proxy_bytes=5")
	require.Contains(t, output, "proxy_client_bytes=0")
	require.Contains(t, output, "error_categories=[read:1]")
	require.Contains(t, output, "transport=wss")
	require.NotContains(t, output, "SECRET_ACCESS_KEY")
	require.NotContains(t, output, "payload")
	require.NotContains(t, output, "https://")

	lines := strings.Split(strings.TrimSpace(output), "\n")
	var associationID string
	for _, line := range lines {
		if strings.Contains(line, "udp_association_start") {
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "association_id=") {
					associationID = strings.TrimPrefix(field, "association_id=")
				}
			}
		}
	}
	require.NotEmpty(t, associationID)
	for _, event := range []string{
		"udp_association_start",
		"udp_target_socket_created",
		"udp_association_handler_complete",
		"udp_association_activity_after_handler",
		"udp_target_socket_close_returned",
	} {
		for _, line := range lines {
			if strings.Contains(line, event) {
				require.Contains(t, line, "association_id="+associationID)
			}
		}
	}
}

func TestUDPDiagnosticsSocketFailureIsCategorizedWithoutRawError(t *testing.T) {
	diagnostics := newUDPDiagnostics()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	association := diagnostics.begin(logger, "udp")
	secretError := "udp dial https://private.example/path?token=SECRET failed"
	listener := &diagnosticPacketListener{inner: diagnosticTestPacketListener{err: testDiagnosticError(secretError)}}
	_, err := listener.ListenPacket(contextWithUDPDiagnostics(context.Background(), association))
	require.Error(t, err)
	metrics := &diagnosticUDPAssociationMetrics{inner: &service.NoOpUDPAssociationMetrics{}, association: association}
	metrics.AddPacketFromClient("ERR_CREATE_SOCKET", 14, 0)
	association.handlerCompleted()
	output := logs.String()
	require.Contains(t, output, "error_category=socket_create")
	require.Contains(t, output, "error_categories=[socket_create:1]")
	require.Equal(t, 1, strings.Count(output, "socket_create:1"))
	require.NotContains(t, output, secretError)
	require.NotContains(t, output, "SECRET")
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.openTargetSockets))
}

func TestUDPDiagnosticsCloseErrorIsCategorizedWithoutRawError(t *testing.T) {
	diagnostics := newUDPDiagnostics()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	association := diagnostics.begin(logger, "udp")
	secretError := "close failed for udp://private.example:1234"
	packetConn, err := (&diagnosticPacketListener{
		inner: diagnosticTestPacketListener{conn: &diagnosticTestPacketConn{closeErr: testDiagnosticError(secretError)}},
	}).ListenPacket(contextWithUDPDiagnostics(context.Background(), association))
	require.NoError(t, err)
	require.Error(t, packetConn.Close())
	association.handlerCompleted()

	output := logs.String()
	require.Contains(t, output, "close_error_category=close")
	require.Equal(t, 1, strings.Count(output, "close_error_category=close"))
	require.NotContains(t, output, secretError)
	require.NotContains(t, output, "private.example")
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.openTargetSockets))
}

func TestUDPDiagnosticsPacketTotalsExcludeEmptyReadErrorsAndCountEmptyDatagrams(t *testing.T) {
	diagnostics := newUDPDiagnostics()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	association := diagnostics.begin(logger, "udp")
	metrics := &diagnosticUDPAssociationMetrics{inner: &service.NoOpUDPAssociationMetrics{}, association: association}

	metrics.AddPacketFromClient("ERR_READ", 0, 0)
	metrics.AddPacketFromTarget("ERR_READ", 0, 0)
	metrics.AddPacketFromClient("OK", 0, 0)
	metrics.AddPacketFromTarget("OK", 0, 0)
	association.handlerCompleted()

	output := logs.String()
	require.Contains(t, output, "client_packets=1")
	require.Contains(t, output, "target_packets=1")
	require.Contains(t, output, "error_categories=[read:2]")
	require.Contains(t, output, "client_proxy_bytes=0")
	require.Contains(t, output, "target_proxy_bytes=0")
}

func TestUDPDiagnosticsTracksTargetReadFromStillInFlightAfterHandler(t *testing.T) {
	diagnostics := newUDPDiagnostics()
	association := diagnostics.begin(slog.New(slog.NewTextHandler(io.Discard, nil)), "udp")
	conn := &diagnosticBlockingPacketConn{started: make(chan struct{}), release: make(chan struct{})}
	packetConn := &diagnosticPacketConn{PacketConn: conn, association: association}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _, _ = packetConn.ReadFrom(make([]byte, 8))
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("client read did not start")
	}

	association.handlerCompleted()
	require.Equal(t, float64(1), promtest.ToFloat64(diagnostics.targetReadsAfterHandler))
	close(conn.release)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("client read did not return")
	}
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetReadsAfterHandler))
}

func TestUDPDiagnosticsCollectorIsReusedOnReloadAndStartsAtBaseline(t *testing.T) {
	registry := prometheus.NewRegistry()
	first := &OutlineApp{}
	require.NoError(t, first.defineMetrics(registry))
	second := &OutlineApp{}
	require.NoError(t, second.defineMetrics(registry))
	require.Same(t, first.diagnostics, second.diagnostics)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range metricFamilies {
		if strings.HasPrefix(family.GetName(), "outline_udp_association_") {
			for _, metric := range family.Metric {
				require.Empty(t, metric.Label)
				require.Zero(t, metric.GetGauge().GetValue())
			}
		}
	}
}

func TestReadBuildMetadataReportsBuildAndEffectiveCoreVersions(t *testing.T) {
	metadata := readBuildMetadata()
	require.NotEmpty(t, metadata.buildModule)
	require.NotEmpty(t, metadata.buildVersion)
	require.NotEqual(t, "dev", metadata.buildVersion)
	require.NotEmpty(t, metadata.goVersion)
	require.NotEmpty(t, metadata.caddyVersion)
	require.Equal(t, outlineCoreModule, metadata.coreModule)
	require.Equal(t, "unknown", metadata.coreVersion)
}

func TestEffectiveCoreMetadataUsesVersionedReplacement(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{{
		Path:    outlineCoreModule,
		Version: "v1.9.3-rc2.0.20260904072137-2e9909e67173",
		Replace: &debug.Module{
			Path:    outlineCoreForkModule,
			Version: "v1.9.3-rc2.0.20261021155211-530c7083b0dd",
		},
	}}}
	modulePath, moduleVersion := effectiveCoreMetadata(info)
	require.Equal(t, outlineCoreForkModule, modulePath)
	require.Equal(t, "v1.9.3-rc2.0.20261021155211-530c7083b0dd", moduleVersion)
}

func TestCategorizeUDPStatus(t *testing.T) {
	for status, expected := range map[string]string{
		"ERR_READ_ADDRESS":    "read_address",
		"ERR_CONVERT_ADDRESS": "convert_address",
		"ERR_CREATE_SOCKET":   "socket_create",
		"ERR_ADDRESS_INVALID": "invalid_address",
	} {
		require.Equal(t, expected, categorizeUDPStatus(status), status)
	}
}

func TestResolveBuildVersion(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{{
			Key:   "vcs.revision",
			Value: "0123456789abcdef",
		}},
	}
	require.Equal(t, "v2.11.7-r3", resolveBuildVersion(info, "v2.11.7-r3", "r3"))
	require.Equal(t, "0123456789abcdef", resolveBuildVersion(info, "", "r3"))
	require.Equal(t, "r3", resolveBuildVersion(&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "", "r3"))
}

func TestWebSocketPacketTransportUsesTLSState(t *testing.T) {
	wsRequest := &http.Request{}
	wssRequest := &http.Request{TLS: &tls.ConnectionState{}}
	require.Equal(t, "ws", websocketPacketTransport(wsRequest))
	require.Equal(t, "wss", websocketPacketTransport(wssRequest))
	require.Equal(t, "udp", udpTransportFromContext(context.Background()))
	require.Equal(t, "ws", udpTransportFromContext(contextWithUDPTransport(context.Background(), websocketPacketTransport(wsRequest))))
	require.Equal(t, "wss", udpTransportFromContext(contextWithUDPTransport(context.Background(), websocketPacketTransport(wssRequest))))
	require.Equal(t, "udp", udpTransportFromContext(contextWithUDPTransport(context.Background(), "private-value")))
}

func TestUDPAssociationDiagnosticStateDoesNotRetainClientConnection(t *testing.T) {
	finalized := make(chan struct{}, 1)
	diagnostics := newUDPDiagnostics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var association *udpAssociationDiagnostics
	handler := keepAssociationDiagnosticsLiveWhileDroppingClient(t, diagnostics, logger, finalized, &association)

	collected := false
	for i := 0; i < 100; i++ {
		runtime.GC()
		select {
		case <-finalized:
			collected = true
		default:
			runtime.Gosched()
			time.Sleep(10 * time.Millisecond)
		}
		if collected {
			break
		}
	}
	runtime.KeepAlive(association)
	runtime.KeepAlive(handler)
	require.True(t, collected, "diagnostic state retained the client connection after handler completion")
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.openTargetSockets))
	require.Equal(t, float64(0), promtest.ToFloat64(diagnostics.targetsAfterHandler))
	runtime.KeepAlive(association)
}

func keepAssociationDiagnosticsLiveWhileDroppingClient(t *testing.T, diagnostics *udpDiagnostics, logger *slog.Logger, finalized chan<- struct{}, association **udpAssociationDiagnostics) *ShadowsocksHandler {
	t.Helper()
	handler := &ShadowsocksHandler{
		metrics:            diagnosticNoOpServiceMetrics{},
		diagnostics:        diagnostics,
		logger:             logger,
		associationHandler: diagnosticAssociationHandler{association: association},
	}
	clientConn, peerConn := net.Pipe()
	conn := &diagnosticLifetimeConn{Conn: clientConn}
	runtime.SetFinalizer(conn, func(*diagnosticLifetimeConn) { finalized <- struct{}{} })
	cx := layer4.WrapConnection(conn, nil, zap.NewNop())
	cx.SetVar(outlineConnectionTypeCtxKey, PacketConnectionType)
	require.NoError(t, handler.Handle(cx, nil))
	_ = conn.Close()
	_ = peerConn.Close()
	runtime.KeepAlive(cx)
	runtime.KeepAlive(conn)
	return handler
}

type diagnosticNoOpServiceMetrics struct{}

func (diagnosticNoOpServiceMetrics) AddOpenUDPAssociation(net.Conn) service.UDPAssociationMetrics {
	return &service.NoOpUDPAssociationMetrics{}
}
func (diagnosticNoOpServiceMetrics) AddOpenTCPConnection(net.Conn) service.TCPConnMetrics {
	return &service.NoOpTCPConnMetrics{}
}
func (diagnosticNoOpServiceMetrics) AddTCPCipherSearch(bool, time.Duration) {}
func (diagnosticNoOpServiceMetrics) AddUDPCipherSearch(bool, time.Duration) {}

type diagnosticAssociationHandler struct {
	association **udpAssociationDiagnostics
}

func (h diagnosticAssociationHandler) HandleAssociation(_ context.Context, conn net.Conn, metrics service.UDPAssociationMetrics) {
	if wrapped, ok := metrics.(*diagnosticUDPAssociationMetrics); ok && h.association != nil {
		*h.association = wrapped.association
	}
	metrics.AddClose()
	_ = conn.Close()
}
func (diagnosticAssociationHandler) SetLogger(*slog.Logger)                           {}
func (diagnosticAssociationHandler) SetTargetPacketListener(transport.PacketListener) {}

type diagnosticTestPacketListener struct {
	conn net.PacketConn
	err  error
}

func (l diagnosticTestPacketListener) ListenPacket(context.Context) (net.PacketConn, error) {
	return l.conn, l.err
}

type diagnosticTestPacketConn struct {
	closeErr error
}

func (*diagnosticTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (*diagnosticTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *diagnosticTestPacketConn) Close() error                            { return c.closeErr }
func (*diagnosticTestPacketConn) LocalAddr() net.Addr                       { return diagnosticTestAddr("local") }
func (*diagnosticTestPacketConn) SetDeadline(time.Time) error               { return nil }
func (*diagnosticTestPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*diagnosticTestPacketConn) SetWriteDeadline(time.Time) error          { return nil }

type diagnosticTestAddr string

func (a diagnosticTestAddr) Network() string { return "udp" }
func (a diagnosticTestAddr) String() string  { return string(a) }

type testDiagnosticError string

func (e testDiagnosticError) Error() string { return string(e) }

type diagnosticBlockingPacketConn struct {
	started chan struct{}
	release chan struct{}
}

func (c *diagnosticBlockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	close(c.started)
	<-c.release
	return 0, nil, net.ErrClosed
}
func (*diagnosticBlockingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*diagnosticBlockingPacketConn) Close() error                              { return nil }
func (*diagnosticBlockingPacketConn) LocalAddr() net.Addr                       { return diagnosticTestAddr("local") }
func (*diagnosticBlockingPacketConn) SetDeadline(time.Time) error               { return nil }
func (*diagnosticBlockingPacketConn) SetReadDeadline(time.Time) error {
	return nil
}
func (*diagnosticBlockingPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

type diagnosticLifetimeConn struct{ net.Conn }
