---
airlock: minor
---

The engine builds as a WebAssembly module, `airlock-wasm`, for the Airlock Worker and the JavaScript action. Every request, wait and clock reading goes through one transport interface, which the host supplies in the module. Central sign-in runs in the module too: the host signs in to Entra ID with its own client secret or client assertion, then Key Vault signs Airlock Safe's JSON Web Token and the App, installation and token checks hold as before. CI builds the module on every pull request, holds it to the size budget `docs/wasm.md` states, and compares its findings with the native build's on recorded responses.
