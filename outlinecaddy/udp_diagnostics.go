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
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/tunnel-server/service"
)

type udpDiagnosticsContextKey struct{}
type udpTransportContextKey struct{}

// udpDiagnostics is a reload-safe aggregate collector. It deliberately keeps
// no per-association registry or connection references.
type udpDiagnostics struct {
	activeHandlers          prometheus.Gauge
	openTargetSockets       prometheus.Gauge
	targetsAfterHandler     prometheus.Gauge
	targetReadsAfterHandler prometheus.Gauge
	nextAssociationID       atomic.Uint64
}

var _ prometheus.Collector = (*udpDiagnostics)(nil)

func newUDPDiagnostics() *udpDiagnostics {
	return &udpDiagnostics{
		activeHandlers: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "udp",
			Name:      "association_active_handlers",
			Help:      "Association handler calls that have started and not returned.",
		}),
		openTargetSockets: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "udp",
			Name:      "association_open_target_sockets",
			Help:      "Target PacketConn handles created by the listener wrapper whose Close method has not returned.",
		}),
		targetsAfterHandler: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "udp",
			Name:      "association_targets_after_handler",
			Help:      "Target PacketConn handles whose wrapped Close method had not returned when their association handler returned.",
		}),
		targetReadsAfterHandler: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "udp",
			Name:      "association_target_reads_after_handler",
			Help:      "Target PacketConn.ReadFrom calls still in flight after their association handler returned; this observes in-flight calls, not whether a goroutine is blocked.",
		}),
	}
}

func (d *udpDiagnostics) Describe(ch chan<- *prometheus.Desc) {
	d.activeHandlers.Describe(ch)
	d.openTargetSockets.Describe(ch)
	d.targetsAfterHandler.Describe(ch)
	d.targetReadsAfterHandler.Describe(ch)
}

func (d *udpDiagnostics) Collect(ch chan<- prometheus.Metric) {
	d.activeHandlers.Collect(ch)
	d.openTargetSockets.Collect(ch)
	d.targetsAfterHandler.Collect(ch)
	d.targetReadsAfterHandler.Collect(ch)
}

func (d *udpDiagnostics) begin(logger *slog.Logger, transportName string) *udpAssociationDiagnostics {
	if logger == nil {
		logger = slog.Default()
	}
	a := &udpAssociationDiagnostics{
		diagnostics: d,
		logger:      logger,
		id:          fmt.Sprintf("udp-%016x", d.nextAssociationID.Add(1)),
		transport:   transportName,
		startedAt:   time.Now(),
		errorCounts: make(map[string]uint64),
	}
	d.activeHandlers.Inc()
	logger.Debug("udp_association_start",
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
	)
	return a
}

type udpAssociationDiagnostics struct {
	diagnostics *udpDiagnostics
	logger      *slog.Logger
	id          string
	transport   string
	startedAt   time.Time

	mu                  sync.Mutex
	handlerDone         bool
	targetOpen          bool
	targetOpenedAt      time.Time
	targetAfterHandler  bool
	targetReadsInFlight int
	lateActivityLogged  bool
	clientPackets       uint64
	targetPackets       uint64
	clientProxyBytes    uint64
	proxyTargetBytes    uint64
	targetProxyBytes    uint64
	proxyClientBytes    uint64
	errorCounts         map[string]uint64
}

func (a *udpAssociationDiagnostics) handlerCompleted() {
	a.mu.Lock()
	if a.handlerDone {
		a.mu.Unlock()
		return
	}
	a.handlerDone = true
	if a.targetOpen {
		a.targetAfterHandler = true
		a.diagnostics.targetsAfterHandler.Inc()
	}
	if a.targetReadsInFlight > 0 {
		a.diagnostics.targetReadsAfterHandler.Add(float64(a.targetReadsInFlight))
	}
	duration := time.Since(a.startedAt)
	errors := a.errorSummaryLocked()
	clientPackets := a.clientPackets
	targetPackets := a.targetPackets
	clientProxyBytes := a.clientProxyBytes
	proxyTargetBytes := a.proxyTargetBytes
	targetProxyBytes := a.targetProxyBytes
	proxyClientBytes := a.proxyClientBytes
	a.mu.Unlock()

	a.diagnostics.activeHandlers.Dec()
	a.logger.Debug("udp_association_handler_complete",
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
		slog.Duration("duration", duration),
		slog.Uint64("client_packets", clientPackets),
		slog.Uint64("target_packets", targetPackets),
		slog.Uint64("client_proxy_bytes", clientProxyBytes),
		slog.Uint64("proxy_target_bytes", proxyTargetBytes),
		slog.Uint64("target_proxy_bytes", targetProxyBytes),
		slog.Uint64("proxy_client_bytes", proxyClientBytes),
		slog.Any("error_categories", errors),
	)
}

func (a *udpAssociationDiagnostics) targetSocketCreated() {
	now := time.Now()
	a.mu.Lock()
	if a.targetOpen {
		a.mu.Unlock()
		return
	}
	a.targetOpen = true
	a.targetOpenedAt = now
	a.diagnostics.openTargetSockets.Inc()
	if a.handlerDone {
		a.targetAfterHandler = true
		a.diagnostics.targetsAfterHandler.Inc()
	}
	a.mu.Unlock()
	a.logger.Debug("udp_target_socket_created",
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
	)
}

func (a *udpAssociationDiagnostics) targetSocketCreateFailed() {
	// The core reports ERR_CREATE_SOCKET through the existing metrics interface.
	// Count that status once there; this event only records the listener result.
	a.logger.Debug("udp_target_socket_create_failed",
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
		slog.String("error_category", "socket_create"),
	)
}

func (a *udpAssociationDiagnostics) targetSocketCloseReturned(err error) {
	a.mu.Lock()
	if !a.targetOpen {
		a.mu.Unlock()
		return
	}
	a.targetOpen = false
	openedAt := a.targetOpenedAt
	a.targetOpenedAt = time.Time{}
	if a.targetAfterHandler {
		a.targetAfterHandler = false
		a.diagnostics.targetsAfterHandler.Dec()
	}
	a.diagnostics.openTargetSockets.Dec()
	a.mu.Unlock()
	attrs := []any{
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
		slog.Duration("socket_lifetime", time.Since(openedAt)),
		slog.String("close_result", "returned"),
	}
	if err != nil {
		attrs = append(attrs, slog.String("close_error_category", "close"))
	}
	a.logger.Debug("udp_target_socket_close_returned", attrs...)
}

func (a *udpAssociationDiagnostics) targetReadStarted() {
	a.mu.Lock()
	a.targetReadsInFlight++
	if a.handlerDone {
		a.diagnostics.targetReadsAfterHandler.Inc()
	}
	a.mu.Unlock()
}

func (a *udpAssociationDiagnostics) targetReadReturned() {
	a.mu.Lock()
	if a.targetReadsInFlight > 0 {
		a.targetReadsInFlight--
	}
	if a.handlerDone {
		a.diagnostics.targetReadsAfterHandler.Dec()
	}
	a.mu.Unlock()
}

func (a *udpAssociationDiagnostics) recordClientPacket(status string, clientProxyBytes, proxyTargetBytes int64) {
	a.mu.Lock()
	if countUDPDatagram(status, clientProxyBytes) {
		a.clientPackets++
	}
	a.clientProxyBytes += positiveBytes(clientProxyBytes)
	a.proxyTargetBytes += positiveBytes(proxyTargetBytes)
	a.addStatusLocked(status)
	late := a.handlerDone && !a.lateActivityLogged
	if late {
		a.lateActivityLogged = true
	}
	packets := a.clientPackets
	bytes := a.clientProxyBytes + a.proxyTargetBytes
	a.mu.Unlock()
	if late {
		a.logActivityAfterHandler("client", packets, bytes)
	}
}

func (a *udpAssociationDiagnostics) recordTargetPacket(status string, targetProxyBytes, proxyClientBytes int64) {
	a.mu.Lock()
	if countUDPDatagram(status, targetProxyBytes) {
		a.targetPackets++
	}
	a.targetProxyBytes += positiveBytes(targetProxyBytes)
	a.proxyClientBytes += positiveBytes(proxyClientBytes)
	a.addStatusLocked(status)
	late := a.handlerDone && !a.lateActivityLogged
	if late {
		a.lateActivityLogged = true
	}
	packets := a.targetPackets
	bytes := a.targetProxyBytes + a.proxyClientBytes
	a.mu.Unlock()
	if late {
		a.logActivityAfterHandler("target", packets, bytes)
	}
}

func (a *udpAssociationDiagnostics) logActivityAfterHandler(direction string, packets, bytes uint64) {
	a.logger.Debug("udp_association_activity_after_handler",
		slog.String("association_id", a.id),
		slog.String("transport", a.transport),
		slog.String("direction", direction),
		slog.Uint64("packets", packets),
		slog.Uint64("bytes", bytes),
	)
}

func (a *udpAssociationDiagnostics) addStatusLocked(status string) {
	if category := categorizeUDPStatus(status); category != "" {
		a.errorCounts[category]++
	}
}

func (a *udpAssociationDiagnostics) errorSummaryLocked() []string {
	if len(a.errorCounts) == 0 {
		return []string{}
	}
	categories := make([]string, 0, len(a.errorCounts))
	for category := range a.errorCounts {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for i, category := range categories {
		categories[i] = fmt.Sprintf("%s:%d", category, a.errorCounts[category])
	}
	return categories
}

func categorizeUDPStatus(status string) string {
	switch status {
	case "", "OK":
		return ""
	case "ERR_READ":
		return "read"
	case "ERR_CIPHER":
		return "cipher"
	case "ERR_READ_ADDRESS":
		return "read_address"
	case "ERR_CONVERT_ADDRESS":
		return "convert_address"
	case "ERR_RESOLVE_ADDRESS":
		return "resolve_address"
	case "ERR_ADDRESS_INVALID":
		return "invalid_address"
	case "ERR_CREATE_SOCKET":
		return "socket_create"
	case "ERR_WRITE":
		return "write"
	case "ERR_PACK":
		return "pack"
	default:
		return "other"
	}
}

func countUDPDatagram(status string, sourceBytes int64) bool {
	// Read errors with no source bytes report a failed read attempt, not a
	// datagram. An OK status with zero bytes is a valid zero-length UDP packet.
	return status != "ERR_READ" || sourceBytes > 0
}

func positiveBytes(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func contextWithUDPDiagnostics(ctx context.Context, association *udpAssociationDiagnostics) context.Context {
	return context.WithValue(ctx, udpDiagnosticsContextKey{}, association)
}

func contextWithUDPTransport(ctx context.Context, transportName string) context.Context {
	return context.WithValue(ctx, udpTransportContextKey{}, transportName)
}

func udpDiagnosticsFromContext(ctx context.Context) *udpAssociationDiagnostics {
	if ctx == nil {
		return nil
	}
	association, _ := ctx.Value(udpDiagnosticsContextKey{}).(*udpAssociationDiagnostics)
	return association
}

func udpTransportFromContext(ctx context.Context) string {
	if ctx != nil {
		if transportName, _ := ctx.Value(udpTransportContextKey{}).(string); transportName == "ws" || transportName == "wss" {
			return transportName
		}
	}
	return "udp"
}

type diagnosticPacketListener struct {
	inner transport.PacketListener
}

var _ transport.PacketListener = (*diagnosticPacketListener)(nil)

func (l *diagnosticPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := l.inner.ListenPacket(ctx)
	association := udpDiagnosticsFromContext(ctx)
	if err != nil {
		if association != nil {
			association.targetSocketCreateFailed()
		}
		return nil, err
	}
	if conn == nil {
		if association != nil {
			association.targetSocketCreateFailed()
		}
		return nil, fmt.Errorf("packet listener returned a nil connection")
	}
	if association == nil {
		return conn, nil
	}
	association.targetSocketCreated()
	return &diagnosticPacketConn{PacketConn: conn, association: association}, nil
}

type diagnosticPacketConn struct {
	net.PacketConn
	association *udpAssociationDiagnostics
	closeOnce   sync.Once
	closeErr    error
}

func (c *diagnosticPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.association.targetReadStarted()
	defer c.association.targetReadReturned()
	return c.PacketConn.ReadFrom(p)
}

func (c *diagnosticPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.PacketConn.Close()
		c.association.targetSocketCloseReturned(c.closeErr)
	})
	return c.closeErr
}

type diagnosticUDPAssociationMetrics struct {
	inner       service.UDPAssociationMetrics
	association *udpAssociationDiagnostics
}

var _ service.UDPAssociationMetrics = (*diagnosticUDPAssociationMetrics)(nil)

func (m *diagnosticUDPAssociationMetrics) AddAuthentication(accessKey string) {
	m.inner.AddAuthentication(accessKey)
}

func (m *diagnosticUDPAssociationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
	m.inner.AddPacketFromClient(status, clientProxyBytes, proxyTargetBytes)
	m.association.recordClientPacket(status, clientProxyBytes, proxyTargetBytes)
}

func (m *diagnosticUDPAssociationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
	m.inner.AddPacketFromTarget(status, targetProxyBytes, proxyClientBytes)
	m.association.recordTargetPacket(status, targetProxyBytes, proxyClientBytes)
}

func (m *diagnosticUDPAssociationMetrics) AddClose() {
	m.inner.AddClose()
}
