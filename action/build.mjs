// Bundle the action into dist/: index.mjs, with its dependencies, and the
// module it loads. The module is the one scripts/build-wasm.sh wrote to
// target/action-pkg; scripts/build-action.sh runs both. Both outputs are
// committed, and CI rebuilds them and fails on any difference
// (docs/action.md). Every path is fixed relative to the checkout, because
// the bundle's comments name each source file by its path.

import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = resolve(root, "target/action-pkg");
const dist = resolve(root, "dist");

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);

await build({
  absWorkingDir: resolve(root, "action"),
  entryPoints: [resolve(root, "action/src/index.mjs")],
  outfile: resolve(dist, "index.mjs"),
  bundle: true,
  platform: "node",
  target: "node24",
  format: "esm",
  alias: { "airlock-wasm": resolve(pkg, "airlock.js") },
  // Bundled CommonJS dependencies call require for Node's own modules.
  banner: {
    js: 'import { createRequire as __airlockCreateRequire } from "node:module";\n' +
      "const require = __airlockCreateRequire(import.meta.url);",
  },
  legalComments: "eof",
  charset: "utf8",
  logLevel: "warning",
});
copyFileSync(resolve(pkg, "airlock_bg.wasm"), resolve(dist, "airlock_bg.wasm"));
console.log(`built ${dist}`);
