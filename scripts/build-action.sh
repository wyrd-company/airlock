#!/bin/sh
# Build the action's dist/: the WebAssembly module, then the bundle that
# loads it. Install the action's dependencies first with `task action:install`.
#
# dist/ is committed. CI runs this and fails when the result differs from
# the committed copy, so the module must be built by the toolchain
# docs/action.md names: the same rustc gives the same bytes.
set -eu

cd "$(dirname "$0")/.."

# The toolchain dist/ is built with. The action job in .github/workflows/ci.yml
# installs the same one; change both together, and commit the rebuilt dist/.
toolchain=1.100.0
installed=$(rustc --version | sed 's/^rustc \([^ ]*\).*/\1/')
if [ "$installed" != "$toolchain" ]; then
  echo "rustc $installed is installed, and dist/ is built with $toolchain, so the module would differ." >&2
  exit 1
fi

AIRLOCK_WASM_PKG=target/action-pkg scripts/build-wasm.sh
node action/build.mjs
