#!/usr/bin/env bash
# macOS (Apple Silicon) build. Same payload as the Windows release, laid out
# next to the app binary (Aether.app/Contents/MacOS/engine/…) so the code's
# `current_exe()/engine` lookup is unchanged:
#   aether               Rust core, built here with the `tor` feature
#   psiphon-tunnel-core  built here from the pinned Psiphon commit
#   tor/                 official Tor expert bundle (tor, lyrebird, conjure, geoip)
#   xray/xray            official Xray release (custom configs)
# Output: src-tauri/target/release/bundle/{macos/Aether.app,dmg/*.dmg}
set -euo pipefail

PSIPHON_COMMIT=83aa73b9b982e7421e00117f5b0c5aceb5dda452
TOR_VERSION=15.0.23
TOR_SHA256=e8ea3f667c83309abad34280f0f9e1cfae52843da6b8db111ca15d6221051db5
XRAY_VERSION=v25.12.8
XRAY_SHA256=cde3406670061f4b9fad672727d1e616e6c335db2fb414456991c0246a368c7c

root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/dist-engine-macos
tmp=${TMPDIR:-/tmp}/aether-macos
mkdir -p "$tmp"
rm -rf "$out" && mkdir -p "$out/tor" "$out/xray"

# A Command Line Tools SDK newer than Xcode's linker breaks BoringSSL's CMake
# ("tapi error: unknown architecture"); Xcode's own SDK always matches it.
xsdk=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
if [ -z "${SDKROOT:-}" ] && [ -d "$xsdk" ]; then export SDKROOT=$xsdk; fi

fetch() { # url sha256 file
  if ! { [ -f "$3" ] && echo "$2  $3" | shasum -a 256 -c --status; }; then
    curl -fsSL -o "$3" "$1"
    echo "$2  $3" | shasum -a 256 -c -
  fi
}

echo "==> Aether core"
(cd "$root/native/aether/aether" && cargo build --release --locked --features tor)
cp "$root/native/aether/aether/target/release/aether" "$root/CORE_VERSION" "$out/"

echo "==> Psiphon $PSIPHON_COMMIT"
src=$tmp/psiphon
[ -d "$src" ] || git clone -q --filter=blob:none --no-checkout https://github.com/CluvexStudio/psiphon-tunnel-core.git "$src"
git -C "$src" fetch -q --depth 1 origin $PSIPHON_COMMIT
git -C "$src" checkout -q --detach $PSIPHON_COMMIT
(cd "$src" && CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags "-s -w" -o "$out/psiphon-tunnel-core" ./ConsoleClient)
cp "$root/assets/psiphon/server_entries.txt" "$out/"
printf %s $PSIPHON_COMMIT > "$out/PSIPHON_VERSION"

echo "==> Tor $TOR_VERSION"
fetch "https://archive.torproject.org/tor-package-archive/torbrowser/$TOR_VERSION/tor-expert-bundle-macos-aarch64-$TOR_VERSION.tar.gz" $TOR_SHA256 "$tmp/tor.tar.gz"
rm -rf "$tmp/tor" && mkdir "$tmp/tor" && tar xzf "$tmp/tor.tar.gz" -C "$tmp/tor"
cp "$tmp"/tor/tor/{tor,libevent-*.dylib} "$tmp"/tor/tor/pluggable_transports/{lyrebird,conjure-client,pt_config.json} \
   "$tmp"/tor/data/{geoip,geoip6} "$out/tor/"

echo "==> Xray $XRAY_VERSION"
fetch "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-macos-arm64-v8a.zip" $XRAY_SHA256 "$tmp/xray.zip"
unzip -oq "$tmp/xray.zip" xray -d "$out/xray"

# Apple Silicon refuses to exec unsigned Mach-O (the Tor bundle ships unsigned).
find "$out" -type f | while read -r f; do
  if file -b "$f" | grep -q Mach-O; then codesign -s - -f "$f"; fi
done

echo "==> App bundle"
cd "$root"
npm ci
if [ ! -f src-tauri/icons/icon.icns ]; then
  npx tauri icon src-tauri/icons/512x512.png -o "$tmp/icons"
  cp "$tmp/icons/icon.icns" src-tauri/icons/
fi
npx tauri build
