#!/bin/sh
set -eu

if [ "${VERSION:-}" = "" ] || [ "$VERSION" = "dev" ]; then
	echo "VERSION must be set to a release tag such as v1.1.0" >&2
	exit 1
fi

dist_dir=${DIST_DIR:-dist}
commit=$(git rev-parse --short HEAD)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ldflags="-s -w -X github.com/byjanke/ghostlink/internal/buildinfo.Version=$VERSION -X github.com/byjanke/ghostlink/internal/buildinfo.Commit=$commit -X github.com/byjanke/ghostlink/internal/buildinfo.Date=$build_date"

mkdir -p "$dist_dir"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
	goos=${target%/*}
	goarch=${target#*/}
	archive="ghostlink_${VERSION#v}_${goos}_${goarch}"
	stage="$dist_dir/$archive"
	mkdir -p "$stage"

	for command in demo server client bridge; do
		package="./cmd/$command"
		if [ "$command" = "bridge" ]; then
			package="./bridge"
		fi
		CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "$ldflags" -o "$stage/ghostlink-$command" "$package"
	done
	cp README.md LICENSE SECURITY.md "$stage/"
	tar -C "$dist_dir" -czf "$dist_dir/$archive.tar.gz" "$archive"
	rm -r "$stage"
done

(
	cd "$dist_dir"
	shasum -a 256 ./*.tar.gz > checksums.txt
)
