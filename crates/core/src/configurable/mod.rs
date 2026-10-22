// ---
// relationships:
//   implements: configurable-rules
// ---

//! Configuration-defined rules over generic read-only probes.
//!
//! This is an additive API for the isolated implementation. The existing CLI,
//! Action and agent-work routes still use their established audit engine.
//! Source snapshots must be pinned by the caller. No external evaluator,
//! credential discovery, configuration write or fix executor exists here.

pub mod config;
mod engine;
pub mod evaluation;
mod fix;
pub mod probe;
pub mod report;

pub use engine::{audit, RepositoryInput};

pub(crate) fn validate_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), String> {
    let validator = jsonschema::options()
        .offline()
        .build(schema)
        .map_err(|e| format!("invalid registered schema: {e}"))?;
    validator
        .validate(value)
        .map_err(|e| format!("schema mismatch at {}: {e}", e.instance_path()))
}
