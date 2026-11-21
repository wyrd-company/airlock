#!/bin/sh
# Build the action's dist/: the WebAssembly module, then the bundle that
# loads it. Install the action's dependencies first with `task action:install`.
#
# dist/ is committed. CI runs this and fails when the result differs from
# the committed copy, so the module must be built by the toolchain
# docs/action.md names: the same rustc gives the same bytes.
set -eu

cd "$(dirname "$0")/.."

AIRLOCK_WASM_PKG=target/action-pkg scripts/build-wasm.sh
node action/build.mjs
