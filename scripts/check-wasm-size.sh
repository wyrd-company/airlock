#!/bin/sh
# Fail when the WebAssembly module is over the size budget docs/wasm.md
# states. The budget is read from that document, so the two cannot drift.
set -eu

cd "$(dirname "$0")/.."

module="${AIRLOCK_WASM_PKG:-target/wasm-pkg}/airlock_bg.wasm"
budget=$(sed -n 's/^Size budget: \*\*\([0-9][0-9]*\) bytes\*\*.*/\1/p' docs/wasm.md)
if [ -z "$budget" ]; then
  echo "docs/wasm.md states no size budget." >&2
  exit 1
fi

size=$(wc -c <"$module" | tr -d ' ')
gzipped=$(gzip -9c "$module" | wc -c | tr -d ' ')
echo "airlock_bg.wasm is $size bytes ($gzipped gzipped); the budget is $budget bytes."
if [ "$size" -gt "$budget" ]; then
  echo "The module is over its size budget by $((size - budget)) bytes." >&2
  exit 1
fi
