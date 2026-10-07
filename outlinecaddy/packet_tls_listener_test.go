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
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/stretchr/testify/require"
)

func TestPacketTLSListenerWrapperProvisionRequiresHTTPServerAndTLS(t *testing.T) {
	for _, ctx := range []caddy.Context{
		{},
		{Context: context.Background()},
	} {
		wrapper := new(PacketTLSListenerWrapper)
		err := wrapper.Provision(ctx)
		require.ErrorContains(t, err, "must be provisioned by an HTTP server")
	}

	wrapper := new(PacketTLSListenerWrapper)
	err := wrapper.Provision(packetListenerContext(&caddyhttp.Server{}))
	require.ErrorContains(t, err, "requires at least one TLS connection policy")
}

func TestPacketTLSRecordSizingRequiresEveryServerPolicy(t *testing.T) {
	request := httptest.NewRequest("GET", "https://outline.example.com/packet", nil)
	require.False(t, packetTLSRecordSizingEnabled(request))

	first := &caddytls.ConnectionPolicy{TLSConfig: &tls.Config{DynamicRecordSizingDisabled: true}}
	second := &caddytls.ConnectionPolicy{TLSConfig: &tls.Config{}}
	server := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{first, second}}
	request = request.WithContext(context.WithValue(request.Context(), caddyhttp.ServerCtxKey, server))
	require.False(t, packetTLSRecordSizingEnabled(request))

	second.TLSConfig.DynamicRecordSizingDisabled = true
	require.True(t, packetTLSRecordSizingEnabled(request))
}

func TestPacketTLSListenerWrapperPreservesListenersAndConfiguresEveryPolicy(t *testing.T) {
	firstPolicy := &caddytls.ConnectionPolicy{TLSConfig: &tls.Config{}}
	secondPolicy := &caddytls.ConnectionPolicy{TLSConfig: &tls.Config{}}
	server := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{firstPolicy, secondPolicy}}
	wrapper := new(PacketTLSListenerWrapper)
	require.NoError(t, wrapper.Provision(packetListenerContext(server)))

	firstListener := &stubListener{}
	require.Same(t, firstListener, wrapper.WrapListener(firstListener))
	require.True(t, firstPolicy.TLSConfig.DynamicRecordSizingDisabled)
	require.True(t, secondPolicy.TLSConfig.DynamicRecordSizingDisabled)

	secondListener := &stubListener{}
	require.Same(t, secondListener, wrapper.WrapListener(secondListener))
	require.False(t, secondListener.closed.Load())
}

func TestPacketTLSListenerWrapperRejectsUnexpectedNilPolicyOrTLSConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies caddytls.ConnectionPolicies
		wantErr  string
	}{
		{
			name:     "nil policy",
			policies: caddytls.ConnectionPolicies{nil},
			wantErr:  "nil TLS connection policy 0",
		},
		{
			name:     "nil TLS config",
			policies: caddytls.ConnectionPolicies{{}, {TLSConfig: &tls.Config{}}},
			wantErr:  "no TLS config for policy 0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &caddyhttp.Server{TLSConnPolicies: tc.policies}
			wrapper := new(PacketTLSListenerWrapper)
			require.NoError(t, wrapper.Provision(packetListenerContext(server)))

			listener := &stubListener{}
			rejected := wrapper.WrapListener(listener)
			require.True(t, listener.closed.Load())
			_, err := rejected.Accept()
			require.ErrorContains(t, err, tc.wantErr)
			require.Same(t, listener, rejected.(rejectingListener).Listener)
			if policy := tc.policies[len(tc.policies)-1]; policy != nil && policy.TLSConfig != nil {
				require.False(t, policy.TLSConfig.DynamicRecordSizingDisabled, "policies must not be partially modified on failure")
			}
		})
	}
}

func TestPacketTLSListenerWrapperIsSafeAcrossAddresses(t *testing.T) {
	policies := caddytls.ConnectionPolicies{
		{TLSConfig: &tls.Config{}},
		{TLSConfig: &tls.Config{}},
	}
	wrapper := new(PacketTLSListenerWrapper)
	require.NoError(t, wrapper.Provision(packetListenerContext(&caddyhttp.Server{TLSConnPolicies: policies})))

	const count = 8
	listeners := make([]*stubListener, count)
	results := make([]net.Listener, count)
	var wg sync.WaitGroup
	for i := range listeners {
		listeners[i] = &stubListener{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = wrapper.WrapListener(listeners[i])
		}(i)
	}
	wg.Wait()
	for i, listener := range listeners {
		require.Same(t, listener, results[i])
		require.False(t, listener.closed.Load())
	}
	for _, policy := range policies {
		require.True(t, policy.TLSConfig.DynamicRecordSizingDisabled)
	}
}

func TestPacketTLSListenerWrapperProvisioningIsPerReload(t *testing.T) {
	oldConfig := &tls.Config{}
	oldServer := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{TLSConfig: oldConfig}}}
	oldWrapper := new(PacketTLSListenerWrapper)
	require.NoError(t, oldWrapper.Provision(packetListenerContext(oldServer)))
	oldListener := &stubListener{}
	require.Same(t, oldListener, oldWrapper.WrapListener(oldListener))

	newConfig := &tls.Config{}
	newServer := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{TLSConfig: newConfig}}}
	newWrapper := new(PacketTLSListenerWrapper)
	require.NoError(t, newWrapper.Provision(packetListenerContext(newServer)))
	newListener := &stubListener{}
	require.Same(t, newListener, newWrapper.WrapListener(newListener))

	require.True(t, oldConfig.DynamicRecordSizingDisabled)
	require.True(t, newConfig.DynamicRecordSizingDisabled)
}

func packetListenerContext(server *caddyhttp.Server) caddy.Context {
	return caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, server)}
}

type stubListener struct {
	closed atomic.Bool
}

func (l *stubListener) Accept() (net.Conn, error) {
	return nil, errors.New("stub listener has no connections")
}

func (l *stubListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (*stubListener) Addr() net.Addr { return &net.TCPAddr{} }
