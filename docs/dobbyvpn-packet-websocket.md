# DobbyVPN packet WebSocket fix

This fork starts from Outline `tunnel-server` v1.9.2 (`be0f6d7`). It keeps the Outline binary name, module path, keys, metrics, config identities, and protocols. The patch fixes packet handling for WebSocket listeners and adds optional TLS termination to the existing web server.

## What changes

- Packet WebSocket reads now return one complete binary WebSocket message as one packet. Fragmented messages are reassembled. Empty, text, oversized, and truncated packets are rejected without passing partial data to Shadowsocks.
- When the configured web server terminates TLS, each outgoing packet WebSocket frame header and payload are written in separate TLS records. Adaptive TLS record sizing is disabled for that listener. This matches the read behavior in the released Outline SDK versions exercised by the compatibility test.
- Native TLS listeners accept TLS 1.2 or newer. Outgoing packet messages are limited to 16 KiB; inbound WebSocket messages are limited to 64 KiB.
- Both PEM paths are loaded before a replacement config starts. If either file is missing or invalid during a reload, the current config and its loaded certificate continue serving.

## TLS certificate handoff

The tunnel server does not request or renew certificates. A separate certificate handler must write the complete certificate chain and private key to the configured PEM files. Once both files form a valid matching pair, signal the server with `SIGHUP` to load them. A failed reload leaves the currently loaded certificate active.

Keep certificate and key paths readable by the Outline service account. Rotate both files atomically as a pair before sending `SIGHUP`; certificate issuance and renewal remain the responsibility of the external handler.

Example web server configuration:

```yaml
web:
  servers:
    - id: public_web
      listen:
        - "0.0.0.0:443"
      tls_cert_file: "/var/lib/outline-tls/fullchain.pem"
      tls_key_file: "/var/lib/outline-tls/privkey.pem"

services:
  - listeners:
      - type: websocket-packet
        web_server: public_web
        path: "/SECRET/udp"
    keys:
      - id: user-0
        cipher: chacha20-ietf-poly1305
        secret: replace-with-a-real-secret
```

When a web server has these TLS paths, Outline terminates TLS itself on every listener in that web server. The packet framing fix is enabled for its packet WebSocket endpoint. WebSocket stream endpoints on the same web server also use native TLS.

## Local validation

Run the upstream Go tests with the race detector and the released-client compatibility test:

```sh
./scripts/review-packet-websocket.sh
```

The script builds the server and a separate compatibility client module. That module pins Outline SDK `v0.1.0-rc1`, SDK/x `v0.0.9-alpha.1`, Gorilla WebSocket `v1.5.3`, and quic-go `v0.48.1`; it uses the SDK's packet endpoint and Shadowsocks packet connection without modifying their sources. The integration test checks encrypted packet sizes from 84 bytes through 16 KiB, then downloads and verifies three 50 MiB HTTP/3 responses through the packet tunnel. The temporary binaries are removed when the script exits.

The integration fixture binds only to loopback and uses a generated local certificate and test key. It does not contact a certificate authority or a production server.
