#!/bin/sh
# Build the WebAssembly module and its JavaScript bindings.
#
# The module is airlock-wasm at the size-optimised wasm-release profile.
# wasm-bindgen writes airlock.js, airlock.d.ts and airlock_bg.wasm to
# $AIRLOCK_WASM_PKG (default target/wasm-pkg). Its version must equal the
# wasm-bindgen crate's in Cargo.lock; `task wasm:install` installs it.
set -eu

cd "$(dirname "$0")/.."

out="${AIRLOCK_WASM_PKG:-target/wasm-pkg}"

locked=$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' Cargo.lock)
installed=$(wasm-bindgen --version | sed 's/^wasm-bindgen //')
if [ "$locked" != "$installed" ]; then
  echo "wasm-bindgen $installed is installed, and Cargo.lock locks $locked. Run task wasm:install." >&2
  exit 1
fi

cargo build --locked -p airlock-wasm --target wasm32-unknown-unknown --profile wasm-release

target_dir=$(cargo metadata --format-version 1 --no-deps |
  sed 's/.*"target_directory":"\([^"]*\)".*/\1/')
wasm-bindgen --target web --out-dir "$out" --out-name airlock \
  "$target_dir/wasm32-unknown-unknown/wasm-release/airlock_wasm.wasm"

echo "built $out/airlock_bg.wasm"
