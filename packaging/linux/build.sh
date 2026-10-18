#!/usr/bin/env bash
# Build the NetworkVision .deb and .rpm for the architecture of this machine.
#
#   packaging/linux/build.sh <version> [out-dir]
#
# Needs: curl, tar, sha256sum, sudo (stages into /opt/networkvision, the install path,
# so the venv's absolute paths are right), nfpm on PATH, and frontend/dist already built.
set -euo pipefail

VERSION="${1:?usage: build.sh <version> [out-dir]}"
VERSION="${VERSION#v}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$(mkdir -p "${2:-$ROOT/dist}" && cd "${2:-$ROOT/dist}" && pwd)"
PREFIX=/opt/networkvision

# python-build-standalone (https://github.com/astral-sh/python-build-standalone). Pinned.
PBS_RELEASE="${PBS_RELEASE:-20261013}"
PBS_PYTHON="${PBS_PYTHON:-3.13.16}"

case "$(uname -m)" in
    x86_64) TRIPLE=x86_64-unknown-linux-gnu; NFPM_ARCH=amd64 ;;
    aarch64 | arm64) TRIPLE=aarch64-unknown-linux-gnu; NFPM_ARCH=arm64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

[ -f "$ROOT/frontend/dist/index.html" ] || { echo "build the frontend first (npm run build)" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Python $PBS_PYTHON ($PBS_RELEASE, $TRIPLE)"
ASSET="cpython-${PBS_PYTHON}+${PBS_RELEASE}-${TRIPLE}-install_only.tar.gz"
BASE="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}"
curl -fsSL --retry 3 -o "$WORK/$ASSET" "$BASE/${ASSET/+/%2B}"
curl -fsSL --retry 3 -o "$WORK/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$WORK" && grep " ${ASSET}\$" SHA256SUMS | sha256sum -c -)

sudo rm -rf "$PREFIX"
sudo install -d -o "$(id -u)" -g "$(id -g)" "$PREFIX"
tar -xzf "$WORK/$ASSET" -C "$PREFIX"   # -> $PREFIX/python

echo "==> venv + backend requirements"
"$PREFIX/python/bin/python3" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --no-cache-dir --upgrade pip
"$PREFIX/venv/bin/python" -m pip install --quiet --no-cache-dir --prefer-binary -r "$ROOT/backend/requirements.txt"

echo "==> app + web UI"
install -d "$PREFIX/lib" "$PREFIX/share"
cp -r "$ROOT/backend/app" "$PREFIX/lib/app"
find "$PREFIX/lib" -name __pycache__ -prune -exec rm -rf {} +
echo "VERSION = \"${VERSION}\"" > "$PREFIX/lib/app/_build_version.py"
SITE="$("$PREFIX/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo "$PREFIX/lib" > "$SITE/networkvision.pth"
cp -r "$ROOT/frontend/dist" "$PREFIX/static"
cp "$ROOT/packaging/networkvision.env" "$PREFIX/share/networkvision.env"
cp "$ROOT/LICENSE" "$PREFIX/share/LICENSE"

# The service runs with a read-only /opt, so ship the bytecode.
"$PREFIX/venv/bin/python" -m compileall -q -j 0 "$PREFIX/lib" "$SITE" >/dev/null || true

echo "==> smoke test"
CHECK_DIR="$(mktemp -d)"
NV_CONFIG=/nonexistent NV_DATA_DIR="$CHECK_DIR" NV_STATIC_DIR="$PREFIX/static" "$PREFIX/venv/bin/python" -m app --check
rm -rf "$CHECK_DIR"

echo "==> packages"
cd "$HERE"
for fmt in deb rpm; do
    NFPM_ARCH="$NFPM_ARCH" NFPM_VERSION="$VERSION" nfpm package --config nfpm.yaml --packager "$fmt" --target "$OUT/"
done
ls -l "$OUT"
