// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package outlinecaddy

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/websocket"
	"golang.getoutline.org/tunnel-server/outlinecaddy/internal/packetwebsocket"
)

const wsModuleName = "http.handlers.websocket2layer4"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  wsModuleName,
		New: func() caddy.Module { return new(WebSocketHandler) },
	})
}

// WebSocketHandler implements a Caddy HTTP middleware handler that proxies
// WebSocket connections for Outline.
//
// It upgrades HTTP WebSocket requests to a raw connection that can be handled
// by an Outline connection handler. This allows using Outline's connection
// handling logic over WebSockets.
type WebSocketHandler struct {
	// Type specifies the type of connection being proxied (stream or packet). If
	// not provided, it defaults to StreamConnectionType.
	Type ConnectionType `json:"type,omitempty"`

	// ConnectionHandler specifies the name of the connection handler to use. This
	// name must match a handler configured within the Outline app.
	ConnectionHandler string `json:"connection_handler,omitempty"`

	// compiledHandler is the compiled instance of the named connection
	// handler. It is populated during the Provision step.
	compiledHandler layer4.NextHandler

	logger  *slog.Logger
	zlogger *zap.Logger
}

var (
	_ caddy.Provisioner           = (*WebSocketHandler)(nil)
	_ caddy.Validator             = (*WebSocketHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebSocketHandler)(nil)
)

func (*WebSocketHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: wsModuleName}
}

// Provision implements caddy.Provisioner.
func (h *WebSocketHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()
	h.zlogger = ctx.Logger()
	if h.Type == "" {
		// The default connection type if not provided is a stream.
		h.Type = StreamConnectionType
	}

	mod, err := ctx.AppIfConfigured(outlineModuleName)
	if err != nil {
		return fmt.Errorf("outline app configure error: %w", err)
	}
	app, ok := mod.(*OutlineApp)
	if !ok {
		return fmt.Errorf("module `%s` is of type `%T`, expected `OutlineApp`", outlineModuleName, app)
	}
	for _, compiledHandler := range app.Handlers {
		if compiledHandler.Name == h.ConnectionHandler {
			h.compiledHandler = compiledHandler
			break
		}
	}
	if h.compiledHandler == nil {
		return fmt.Errorf("no connection handler configured for `%s`", h.ConnectionHandler)
	}

	return nil
}

// Validate implements caddy.Validator.
func (h *WebSocketHandler) Validate() error {
	if h.Type != "" && h.Type != StreamConnectionType && h.Type != PacketConnectionType {
		return fmt.Errorf("unsupported `type`: %v", h.Type)
	}
	if h.ConnectionHandler == "" {
		return errors.New("must specify `connection_handler`")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	h.logger.Debug("handling connection",
		slog.String("path", r.URL.Path),
		slog.Any("remote_addr", r.RemoteAddr))

	var conn net.Conn
	switch h.Type {
	case StreamConnectionType:
		streamConn, err := websocket.Upgrade(webSocketResponseWriter{w}, r, nil)
		if err != nil {
			h.logger.Error("failed to upgrade stream WebSocket", "err", err)
			return nil
		}
		conn = streamConn
		if clientIP := requestClientIP(r); clientIP != nil {
			conn = &replaceAddrConn{StreamConn: streamConn, raddr: &net.TCPAddr{IP: clientIP}}
		}
	case PacketConnectionType:
		if r.TLS != nil && !packetTLSRecordSizingEnabled(r) {
			h.logger.Error("packet WebSocket TLS requires the outline_packet_tls listener wrapper")
			http.Error(w, "packet WebSocket TLS listener is not configured for packet compatibility", http.StatusInternalServerError)
			return nil
		}
		remoteAddr := &net.UDPAddr{IP: requestClientIP(r)}
		var err error
		conn, err = packetwebsocket.Upgrade(w, r, remoteAddr)
		if err != nil {
			h.logger.Error("failed to upgrade packet WebSocket", "err", err)
			return nil
		}
	default:
		return fmt.Errorf("unsupported connection type %q", h.Type)
	}
	defer conn.Close()
	cx := layer4.WrapConnection(conn, []byte{}, h.zlogger)
	cx.SetVar(outlineConnectionTypeCtxKey, h.Type)
	return h.compiledHandler.Handle(cx, nil)
}

// webSocketResponseWriter exposes the Hijacker interface required by the SDK
// through Caddy's supported response-writer unwrapping path.
type webSocketResponseWriter struct {
	http.ResponseWriter
}

func (w webSocketResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w webSocketResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func requestClientIP(r *http.Request) net.IP {
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
		if parsed := net.ParseIP(clientIP); parsed != nil {
			return parsed
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(r.RemoteAddr)
}

// TODO: Create a dedicated `ClientConn` struct with `ClientAddr` and `Conn`.
// replaceAddrConn overrides a [transport.StreamConn]'s remote address handling.
type replaceAddrConn struct {
	transport.StreamConn
	raddr net.Addr
}

func (c replaceAddrConn) RemoteAddr() net.Addr {
	return c.raddr
}

// wsToStreamConn converts a [websocket.Conn] to a [transport.StreamConn].
type wsToStreamConn struct {
	net.Conn
}

var _ transport.StreamConn = (*wsToStreamConn)(nil)

func (c *wsToStreamConn) CloseRead() error {
	// Nothing to do.
	return nil
}

func (c *wsToStreamConn) CloseWrite() error {
	return c.Conn.Close()
}
