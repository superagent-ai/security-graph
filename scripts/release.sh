#!/usr/bin/env bash
set -euo pipefail
: "${VERSION:?Set VERSION to a v-prefixed semantic version}"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo 'VERSION must be a semantic version such as v0.1.0' >&2
  exit 1
fi
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  suffix=""
  if [[ "$target_os" == windows ]]; then suffix=.exe; fi
  staging="$(mktemp -d)"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$staging/security-graph$suffix" ./cmd/security-graph
  tar -C "$staging" -czf "dist/security-graph-${VERSION}-${target_os}-${target_arch}.tar.gz" "security-graph$suffix"
  rm -rf "$staging"
done
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum security-graph-*.tar.gz | sort -k2 > checksums.txt)
else
  (cd dist && shasum -a 256 security-graph-*.tar.gz | sort -k2 > checksums.txt)
fi
