#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(cd "$ROOT/../Arx-Plus-Ios" && pwd)/ArxIDKit.xcframework"
HEADER="$ROOT/mobile/arx-id-ffi/include"
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo build --release -p arx-id-ffi --target "$target" --manifest-path "$ROOT/Cargo.toml"
done
lipo -create \
  "$ROOT/target/aarch64-apple-ios-sim/release/libarx_id_ffi.a" \
  "$ROOT/target/x86_64-apple-ios/release/libarx_id_ffi.a" \
  -output "$TEMP/libarx_id_ffi_sim.a"
xcodebuild -create-xcframework \
  -library "$ROOT/target/aarch64-apple-ios/release/libarx_id_ffi.a" -headers "$HEADER" \
  -library "$TEMP/libarx_id_ffi_sim.a" -headers "$HEADER" \
  -output "$TEMP/ArxIDKit.xcframework"
# Only the named generated artifact is replaced; Xcode's file reference stays.
rm -rf "$OUT"
ditto "$TEMP/ArxIDKit.xcframework" "$OUT"
