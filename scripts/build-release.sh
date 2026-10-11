#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  printf 'Invalid release version\n' >&2
  exit 1
fi
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$output"
output=$(cd "$output" && pwd)
if [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  printf 'Output directory must be empty\n' >&2
  exit 1
fi
cd "$root"

# 无 CGO 的预编译文件无需用户安装 Go；平台架构矩阵须与发布说明和下载页一致。
for target in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  platform=${target%/*}
  architecture=${target#*/}
  suffix=""
  asset_architecture=$architecture
  if [ "$architecture" = arm ]; then asset_architecture=armv7; fi
  if [ "$platform" = windows ]; then suffix=.exe; fi
  asset="xunara-relay_${platform}_${asset_architecture}${suffix}"
  printf 'Building %s\n' "$asset"
  CGO_ENABLED=0 GOOS="$platform" GOARCH="$architecture" GOARM=7 \
    go build -trimpath -buildvcs=true -ldflags "-s -w -X main.version=$version" -o "$output/$asset" ./cmd/xunara-relay
done
sed "s/^release_version=.*/release_version=\"$version\"/" scripts/install-private-relay.sh > "$output/install-private-relay.sh"
chmod 0755 "$output/install-private-relay.sh"
cd "$output"
sha256sum xunara-relay_* install-private-relay.sh > SHA256SUMS
printf 'Version: %s\nSource: %s\n' "$version" "$(git -C "$root" rev-parse HEAD)" > BUILD.txt
printf 'Precompiled release files: %s\n' "$output"
