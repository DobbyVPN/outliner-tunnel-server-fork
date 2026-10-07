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
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const packetTLSListenerModuleID = "caddy.listeners.outline_packet_tls"

func init() {
	caddy.RegisterModule(&PacketTLSListenerWrapper{})
}

// PacketTLSListenerWrapper configures Caddy's TLS policies for the packet
// framing expected by released Outline WebSocket clients. It must be listed
// before Caddy's TLS listener wrapper so it can update the policies before
// Caddy builds its TLS listener.
type PacketTLSListenerWrapper struct {
	server *caddyhttp.Server
	once   sync.Once
	err    error
}

var (
	_ caddy.Provisioner     = (*PacketTLSListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*PacketTLSListenerWrapper)(nil)
)

func (*PacketTLSListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  packetTLSListenerModuleID,
		New: func() caddy.Module { return new(PacketTLSListenerWrapper) },
	}
}

// Provision captures the HTTP server whose TLS policies this wrapper adjusts.
func (w *PacketTLSListenerWrapper) Provision(ctx caddy.Context) error {
	if ctx.Context == nil {
		return errors.New("outline_packet_tls listener wrapper must be provisioned by an HTTP server")
	}
	server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || server == nil {
		return errors.New("outline_packet_tls listener wrapper must be provisioned by an HTTP server")
	}
	if len(server.TLSConnPolicies) == 0 {
		return errors.New("outline_packet_tls listener wrapper requires at least one TLS connection policy")
	}
	w.server = server
	return nil
}

// WrapListener validates and updates every TLS policy once for this server.
// On success, Caddy receives the same listener it passed in. If Caddy's TLS
// policies are unexpectedly incomplete, the listener is closed and replaced
// by one that rejects Accept rather than silently serving incompatible TLS.
func (w *PacketTLSListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	w.once.Do(w.configureTLSRecordSizing)
	if w.err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return rejectingListener{Listener: ln, err: w.err}
	}
	return ln
}

func (w *PacketTLSListenerWrapper) configureTLSRecordSizing() {
	if w.server == nil {
		w.err = errors.New("outline_packet_tls listener wrapper was not provisioned")
		return
	}
	policies := w.server.TLSConnPolicies
	if len(policies) == 0 {
		w.err = errors.New("outline_packet_tls listener wrapper has no TLS connection policies")
		return
	}
	for i, policy := range policies {
		if policy == nil {
			w.err = fmt.Errorf("outline_packet_tls listener wrapper has nil TLS connection policy %d", i)
			return
		}
		if policy.TLSConfig == nil {
			w.err = fmt.Errorf("outline_packet_tls listener wrapper has no TLS config for policy %d", i)
			return
		}
	}
	for _, policy := range policies {
		policy.TLSConfig.DynamicRecordSizingDisabled = true
	}
}

// packetTLSRecordSizingEnabled reports whether every TLS policy configured on
// the request's Caddy HTTP server has the record sizing behavior required by
// packet WebSockets.
func packetTLSRecordSizingEnabled(r *http.Request) bool {
	server, ok := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || server == nil || len(server.TLSConnPolicies) == 0 {
		return false
	}
	for _, policy := range server.TLSConnPolicies {
		if policy == nil || policy.TLSConfig == nil || !policy.TLSConfig.DynamicRecordSizingDisabled {
			return false
		}
	}
	return true
}

type rejectingListener struct {
	net.Listener
	err error
}

func (l rejectingListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l rejectingListener) Close() error {
	if l.Listener == nil {
		return nil
	}
	return l.Listener.Close()
}

func (l rejectingListener) Addr() net.Addr {
	if l.Listener == nil {
		return nil
	}
	return l.Listener.Addr()
}
