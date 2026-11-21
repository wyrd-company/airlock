// The action's entry point: wires the runner and the module to main.mjs.
// Bundled into dist/index.mjs by build.mjs.

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import * as core from "@actions/core";

import { fetchHost } from "../../crates/wasm/js/host.mjs";
import { initSync, repositoryAudit } from "airlock-wasm";

import { ARTIFACT_PREFIX, run } from "./main.mjs";

let loaded = false;
function load() {
  if (!loaded) {
    // The module sits beside this file in dist/.
    initSync({ module: readFileSync(new URL("./airlock_bg.wasm", import.meta.url)) });
    loaded = true;
  }
}

// action.yml's step hands each input over as INPUT_<NAME>, with `-` as `_`.
const env = { ...process.env };
// Read once; no later code, and nothing this process starts, sees it.
delete process.env.AIRLOCK_RUN_TOKEN;

await run({
  input: (name) => (env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`] ?? "").trim(),
  env,
  setSecret: core.setSecret,
  setOutput: core.setOutput,
  exportVariable: core.exportVariable,
  info: core.info,
  error: core.error,
  warning: core.warning,
  setFailed: core.setFailed,
  writeFile: (path, text) => writeFileSync(path, text),
  audit: async (request) => {
    load();
    return repositoryAudit(fetchHost(), request);
  },
  stage: (path, extension) => {
    // One file under a fixed name, whatever the findings location is called,
    // so the artifact always holds airlock-findings.json (or .txt).
    const base = process.env.RUNNER_TEMP || process.env.TMPDIR || "/tmp";
    mkdirSync(base, { recursive: true });
    const directory = mkdtempSync(join(base, "airlock-artifact-"));
    copyFileSync(path, join(directory, `${ARTIFACT_PREFIX}.${extension}`));
    return directory;
  },
});
