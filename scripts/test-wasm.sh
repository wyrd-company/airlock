#!/bin/sh
# Run the WebAssembly module's tests under Node: central sign-in against
# fakes, the host's clock and timers, and native parity on recorded
# responses. Build the module first with scripts/build-wasm.sh.
set -eu

cd "$(dirname "$0")/.."

cargo build --locked -p airlock-wasm --example parity_native
target_dir=$(cargo metadata --format-version 1 --no-deps |
  sed 's/.*"target_directory":"\([^"]*\)".*/\1/')

AIRLOCK_PARITY_NATIVE="$target_dir/debug/examples/parity_native" \
  node --test crates/wasm/tests/*.test.mjs
