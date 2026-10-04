#!/bin/sh
# Builds SIEMLite (and loggen, its test log generator) for every supported
# platform into dist/, packaged with the README and licence, plus SHA256SUMS. Used by the release workflow; run it
# locally to check a release builds. The version comes from VERSION.
set -eu
cd "$(dirname "$0")/.."
version=$(tr -d '[:space:]' < VERSION)
rm -rf dist && mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	os=${target%/*}
	arch=${target#*/}
	name="siemlite-$version-$os-$arch"
	ext=
	[ "$os" = windows ] && ext=.exe
	stage="dist/$name"
	mkdir -p "$stage"
	echo "building $name"
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$stage/siemlite$ext" .
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$stage/loggen$ext" ./cmd/loggen
	cp README.md LICENSE "$stage/"
	if [ "$os" = windows ]; then
		(cd dist && zip -qr "$name.zip" "$name")
	else
		tar -C dist -czf "dist/$name.tar.gz" "$name"
	fi
	rm -rf "$stage"
done
(cd dist && sha256sum siemlite-* > SHA256SUMS)
ls -l dist
