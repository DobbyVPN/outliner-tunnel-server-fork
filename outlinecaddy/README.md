# Caddy module

This module adds an Outline Shadowsocks app and a WebSocket handler to Caddy. Stream and packet WebSockets can share the same Outline connection handler. Caddy continues to own HTTPS certificates and their renewal.

## Build and run

Use Go 1.26.8 or later. From this directory, build the Caddy binary with the Outline, Caddy standard, YAML adapter, and layer4 modules registered:

```sh
go build -tags nomysql -o ./caddy ./cmd/caddy
./caddy validate --config examples/outline-websocket.json
./caddy run --config examples/outline-websocket.json
```

The sample binds only to loopback (`127.0.0.1:8443`) and keeps the Caddy admin endpoint on loopback. The placeholder names `outline.example.com` and `account.example.com` qualify for automatic HTTPS, so `./caddy run` will attempt certificate management for them. Replace the domains before running; `validate` only checks the configuration. External Outline clients cannot reach a loopback listener. For a public service, replace the listen address with the intended public interface or `:443`, use domains you control, and make the HTTP and HTTPS challenge ports reachable so Caddy can obtain and renew certificates. Caddy's automatic HTTPS remains enabled; do not add a separate certificate issuer for these routes.

The example includes both an Outline stream route and packet route, an account file server on `account.example.com`, and a static file fallback on `outline.example.com`. Replace both example domains, both `change-me` URL paths, the example secret, and the two static roots with your values. Use long, randomly generated private paths and a unique Shadowsocks secret. The endpoint URLs for Outline clients are `wss://outline.example.com/change-me-random-stream-path` and `wss://outline.example.com/change-me-random-packet-path` after substituting the public domain and paths.

The `outline_packet_tls` listener wrapper must appear before Caddy's `tls` wrapper. It sets `DynamicRecordSizingDisabled` on every TLS connection policy for that HTTP server, which keeps each packet WebSocket header and payload in separate TLS application records for released Outline clients. Keep the server protocols at `h1` and `h2`; WebSocket upgrades use HTTP/1.1, and HTTP/3 is not enabled by this configuration. Packet WebSockets over plain HTTP do not require this TLS wrapper.

TLS packet responses are limited to 16 KiB per encrypted packet so their payload fits in one TLS application record; larger responses return a short-buffer error without sending a partial packet. Incoming WebSocket messages are limited to 64 KiB. The listener setting applies to all HTTPS routes on that HTTP server, including its static file routes.

The adapter derives the client's address from Caddy's client IP variable, falling back to the request's remote address. If Caddy is behind a reverse proxy, configure trusted proxies with only that proxy's address ranges before accepting forwarded client IP headers.

## UDP association diagnostics

At DEBUG level, the Outline app reports packet association start and handler return, target `PacketConn` creation and `Close` return, and at most one activity event if packet metrics arrive after the handler returns. Events share a generated association ID and include the observed transport (`udp`, `ws`, or `wss`), handler or socket duration, packet and byte totals, and fixed error categories. They do not include client or target addresses, access keys, URLs, errors' raw text, or packet data, and they do not log once per packet.

These events describe observations at the Caddy adapter boundary. `udp_association_handler_complete` means `HandleAssociation` returned. `udp_target_socket_created` means the packet listener returned a `PacketConn`; `udp_target_socket_close_returned` means its wrapped `Close` call returned. Neither event claims that the relay completed. The aggregate `outline_udp_association_*` gauges count active handler calls, target packet connections whose wrapped `Close` has not returned, target connections whose wrapped `Close` had not returned when the handler completed, and target `ReadFrom` calls still in flight after handler return. The read gauge observes in-flight calls and does not determine whether a goroutine is blocked. Gauges have no association labels and return to baseline as the observed calls and wrapped `Close` methods return. The collector is reused by Caddy's metrics registry on reload and keeps no association or client-connection registry.

Packet totals exclude `ERR_READ` callbacks with no source bytes; successful zero-length UDP datagrams still count as packets. Directional byte totals use the byte counts reported by the core for each read and write.

On app provisioning, an INFO log reports the Go build module/version and revision, Caddy version, Go toolchain version, and effective tunnel-server module/version from build metadata. A source version is used when build metadata lacks a release version or VCS revision. The diagnostic target-listener wrapper delegates to the service's existing packet listener with the same public-IP validator and five-minute timeout as its default; DNS-specific deadlines and routing remain in the service implementation.

## Tests

Run the module and adapter unit tests from this directory:

```sh
go test ./...
go test -race ./...
```

The tests cover WebSocket packet boundaries, fragmented messages, invalid messages, TLS record boundaries, listener wrapper provisioning, multiple listeners, configuration reload instances, and concurrent listener wrapping.

Run the full compatibility review, including isolated clients built against the released and stock SDK manifests and a real loopback Caddy/TLS regression fixture, with:

```sh
./scripts/review.sh
```

The review script builds Caddy with Go 1.26.8 and the clients with Go 1.25.5 (downloaded by Go's toolchain selector if needed). It runs the integration and unit suite under the race detector.

## Dependency verification note

The inherited zip checksum for `github.com/google/go-tpm-tools v0.4.8` (`h1:q8LRQwaO79qVNywF/Hu38aI/+xRjAOPAp0CnMYU7Sro=`) did not match the signed checksum (`h1:V4oIYyAD3BykOycwYQzO29WefDouQMTsYZqmG3HxOfM=`) in [sum.golang.org](https://sum.golang.org/lookup/github.com/google/go-tpm-tools@v0.4.8). The stale line was replaced after Go verified the official checksum; sumdb verification remains enabled. Caddy v2.11.7 requires Go 1.26.0 and its newer transitive dependency graph, so `go mod tidy` updates the necessary indirect module versions. The module requirement remains `golang.getoutline.org/tunnel-server v1.9.3-rc2.0.20260904072137-2e9909e67173`; a versioned replacement resolves it to `github.com/DobbyVPN/outliner-tunnel-server-fork v1.9.3-rc2.0.20261021155211-530c7083b0dd`, pinned to core commit `530c7083b0ddfdb4407bf6c06236cee8556a05ce`.
