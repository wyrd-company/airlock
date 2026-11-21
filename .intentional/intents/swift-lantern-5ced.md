---
airlock: major
---

The Airlock action is a JavaScript action on `node24` that runs the engine as WebAssembly from the committed `dist/`; no step installs Rust, and no Rust binary is published. It runs repository mode only, on the run's own `GITHUB_TOKEN`, which the engine admits only inside Actions, for the run's repository, when every permission the job declares is `read`. `mode: central` is refused with a message that names the Airlock Worker's scheduled central audit, and the central inputs (`app-id`, `key-name`, `installation-repositories`, `vault-url`, `azure-tenant-id`, `azure-client-id`) and the `airlock-central-report` artifact are removed. A local policy path is refused. The action uploads its report as the `airlock-findings` artifact. Tokens in GitHub's stateless `ghs_<app id>_<JWT>` format are accepted.
