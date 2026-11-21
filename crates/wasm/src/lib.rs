//! The Airlock engine as a WebAssembly module.
//!
//! The Airlock Worker and the JavaScript action load this module. The host
//! supplies every request, wait and clock reading through one object; see
//! `docs/wasm.md` for the interface, the build and its size budget.
//!
//! [`engine`] holds the entry points for every target, so the native parity
//! run executes the same code the module does.

pub mod engine;

#[cfg(target_arch = "wasm32")]
mod js;
