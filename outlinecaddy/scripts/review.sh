#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CLIENT_DIR="${MODULE_DIR}/internal/compat_client"
GO_BIN="${GO_SERVER_BIN:-$(command -v go || true)}"
if [[ -z "${GO_BIN}" || ! -x "${GO_BIN}" ]]; then
	echo "review: Go 1.26.8 is required (set GO_SERVER_BIN to its executable)" >&2
	exit 2
fi

SERVER_GO_VERSION="$(GOTOOLCHAIN=local "${GO_BIN}" version | awk '{print $3}')"
if [[ "${SERVER_GO_VERSION}" != "go1.26.8" ]]; then
	echo "review: server build requires Go 1.26.8; got ${SERVER_GO_VERSION}" >&2
	exit 2
fi

export GOMAXPROCS=2
export GOFLAGS=-p=1
export GOWORK=off
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/outline-caddy-review.XXXXXX")"
trap 'rm -rf "${TEMP_DIR}"' EXIT
RELEASED_CLIENT="${TEMP_DIR}/compat-released"
STOCK_CLIENT="${TEMP_DIR}/compat-stock"
CADDY_BINARY="${TEMP_DIR}/caddy"

echo "review: building isolated compatibility clients with Go 1.25.5"
(
	cd "${CLIENT_DIR}"
	GOTOOLCHAIN=go1.25.5 "${GO_BIN}" build -mod=readonly -o "${RELEASED_CLIENT}" .
	GOTOOLCHAIN=go1.25.5 "${GO_BIN}" build -mod=readonly -modfile=go.stock.mod -o "${STOCK_CLIENT}" .
)

RELEASED_INFO="$("${GO_BIN}" version -m "${RELEASED_CLIENT}")"
STOCK_INFO="$("${GO_BIN}" version -m "${STOCK_CLIENT}")"
module_version() {
	local build_info="$1"
	local module_path="$2"
	awk -v module_path="${module_path}" '$1 == "dep" && $2 == module_path { print $3; exit }' <<<"${build_info}"
}
RELEASED_GO="$(awk 'NR == 1 { print $2; exit }' <<<"${RELEASED_INFO}")"
STOCK_GO="$(awk 'NR == 1 { print $2; exit }' <<<"${STOCK_INFO}")"
if [[ "${RELEASED_GO}" != "go1.25.5" || "$(module_version "${RELEASED_INFO}" golang.getoutline.org/sdk)" != "v0.1.0-rc1" || "$(module_version "${RELEASED_INFO}" golang.getoutline.org/sdk/x)" != "v0.0.9-alpha.1" ]]; then
	echo "review: released compatibility client does not contain the expected Go/SDK pins" >&2
	exit 1
fi
if [[ "${STOCK_GO}" != "go1.25.5" || "$(module_version "${STOCK_INFO}" golang.getoutline.org/sdk)" != "v0.0.22" || "$(module_version "${STOCK_INFO}" golang.getoutline.org/sdk/x)" != "v0.2.2" ]]; then
	echo "review: stock-tools compatibility client does not contain the expected Go/SDK pins" >&2
	exit 1
fi

echo "review: building Caddy v2.11.7 with the Outline modules"
(
	cd "${MODULE_DIR}"
	GOTOOLCHAIN=local "${GO_BIN}" build -mod=readonly -tags=nomysql \
		-ldflags='-X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.7-r2-dbby' \
		-o "${CADDY_BINARY}" ./cmd/caddy
)
if [[ "$("${CADDY_BINARY}" version | awk '{print $1}')" != "v2.11.7-r2-dbby" ]]; then
	echo "review: built Caddy binary does not report the requested custom version" >&2
	exit 1
fi

echo "review: running serial Caddy compatibility and race tests"
(
	cd "${MODULE_DIR}"
	OUTLINE_COMPAT_RELEASED_CLIENT="${RELEASED_CLIENT}" \
	OUTLINE_COMPAT_STOCK_CLIENT="${STOCK_CLIENT}" \
	GOTOOLCHAIN=local "${GO_BIN}" test -mod=readonly -race -count=1 -timeout=30m -tags=integration -v ./...
)

echo "review: passed (Go 1.25.5 isolated SDK clients, Caddy v2.11.7, TLS 1.2/1.3 integration and race tests)"
