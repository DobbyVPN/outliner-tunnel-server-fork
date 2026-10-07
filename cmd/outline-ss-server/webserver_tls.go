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
	"crypto/tls"
	"fmt"
)

// loadWebServerTLSConfigs loads every configured pair before runConfig opens
// replacement listeners. This lets a failed certificate rotation leave the
// currently active configuration serving with its already loaded certificate.
func loadWebServerTLSConfigs(servers []WebServerConfig) (map[string]*tls.Config, error) {
	configs := make(map[string]*tls.Config)
	for _, server := range servers {
		if server.TLSCertFile == "" && server.TLSKeyFile == "" {
			continue
		}
		if server.TLSCertFile == "" || server.TLSKeyFile == "" {
			return nil, fmt.Errorf("web server `%s` must specify both tls_cert_file and tls_key_file", server.ID)
		}
		certificate, err := tls.LoadX509KeyPair(server.TLSCertFile, server.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("web server `%s`: failed to load TLS certificate and key: %w", server.ID, err)
		}
		configs[server.ID] = &tls.Config{
			Certificates:                []tls.Certificate{certificate},
			MinVersion:                  tls.VersionTLS12,
			DynamicRecordSizingDisabled: true,
		}
	}
	return configs, nil
}
