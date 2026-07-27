//! Repository release-readiness auditing for the `airlock` command line tool.
//!
//! The crate is organised around the shape of one audit run: a [`policy`]
//! selects and parameterises [`checks`], each check interrogates a repository
//! through the [`github`] client, and every check contributes to the
//! [`findings`] document the command line front end renders.
//!
//! Everything in this crate is read-only by construction. Airlock never
//! mutates a repository it audits.

pub mod checks;
pub mod error;
pub mod findings;
pub mod github;
pub mod limits;
pub mod policy;
pub mod yaml;

pub use error::{Error, Result};
