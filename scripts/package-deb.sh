#!/usr/bin/env bash
set -euo pipefail

VERSION="0.1.0"
ARCH="amd64"
PKG_NAME="xhip_${VERSION}_${ARCH}"
BUILD_DIR="target/debian/${PKG_NAME}"

echo "Building release binary..."
cargo build --release

echo "Preparing package structure..."
rm -rf "target/debian"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/local/bin"

cp target/release/xhip "${BUILD_DIR}/usr/local/bin/xhip"
chmod 755 "${BUILD_DIR}/usr/local/bin/xhip"

cat <<EOF > "${BUILD_DIR}/DEBIAN/control"
Package: xhip
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: onisajr@gmail.com
Description: Simple, secure code shipping CLI to any VPS
 Xhip is a lightweight CLI for transferring private project source code
 from a developer's local machine to any VPS using Cloudflare R2 object
 storage and temporary presigned download URLs.
EOF

echo "Building .deb package..."
dpkg-deb --build --root-owner-group "${BUILD_DIR}" "target/debian/${PKG_NAME}.deb"
cp "target/debian/${PKG_NAME}.deb" "./xhip.deb"

echo "Package created at ./xhip.deb"
ls -lh ./xhip.deb
