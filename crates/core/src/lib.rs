//! Repository release-readiness auditing for the `airlock` command line tool.
//!
//! The crate is organised around the shape of one audit run: a [`policy`]
//! selects and parameterises [`checks`], each check interrogates a repository
//! through the [`github`] client, and every check contributes to the
//! [`findings`] document the command line front end renders.
//!
//! Everything in this crate is read-only by construction. Airlock never
//! mutates a repository it audits.
//!
//! Public modules support the workspace front end; they are not yet a
//! stability promise for third-party consumers.

mod audited_repository;

pub mod audit;
pub mod auth;
pub mod checks;
pub mod error;
pub mod findings;
pub mod github;
pub mod limits;
pub mod plan;
pub mod policy;
pub mod registry;
pub mod remediation;
pub mod render;
pub mod snapshot;
pub mod worklist;
pub mod worktree;
pub mod yaml;

pub use error::{Error, Result};
pub use remediation::ActionGroup;
