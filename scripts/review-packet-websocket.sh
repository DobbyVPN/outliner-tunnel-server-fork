#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_bin="${GO_BIN:-go}"
review_dir="$(mktemp -d)"
trap 'rm -rf "$review_dir"' EXIT

(
	cd "$repo_root/internal/compat_client"
	GOTOOLCHAIN=auto "$go_bin" build -o "$review_dir/outline-compat-client" .
)

cd "$repo_root"
"$go_bin" build -o "$review_dir/outline-ss-server" ./cmd/outline-ss-server
OUTLINE_COMPAT_CLIENT_BIN="$review_dir/outline-compat-client" "$go_bin" test -race -count=1 ./...
sha256sum "$review_dir/outline-ss-server" "$review_dir/outline-compat-client"
