#!/bin/sh
# Run from the arxium workspace. Pass the Website's public/verify-wasm path.
set -eu
if [ "$#" -ne 1 ]; then
  printf 'usage: %s <website/public/verify-wasm>\n' "$0" >&2
  exit 1
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)
CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}" \
  cargo build -p arx-verify --lib --release --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/arx_verify.wasm --target web --out-dir "$out"
cargo build -p arx-verify --release --bin arx-verify
node tools/arx-verify/tests/parity.mjs "$out" target/release/arx-verify
size=$(gzip -c "$out/arx_verify_bg.wasm" | wc -c)
printf 'gzipped WASM: %s bytes\n' "$size"
if [ "$size" -ge 1000000 ]; then
  printf 'WASM bundle exceeds 1 MB gzip budget\n' >&2
  exit 1
fi
