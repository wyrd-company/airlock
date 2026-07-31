//! The Airlock Admin write path.
//!
//! The interactive console runs entirely on this credential and reads with it
//! too, so it never acquires a second token. That leaves Airlock Safe as purely
//! the headless identity for CI, scheduled audits, and agents.
//!
//! The write credential has exactly one source — the OAuth device flow,
//! approved by the operator in a browser. There is no config file entry, no
//! environment variable, and no command-line flag. It is never stored, under
//! any circumstance, in any location, and never exported to child processes.
//!
//! The console is not a security boundary; it is an intent control that
//! guarantees a human is present. Its real enforcement is credential
//! ephemerality and the absence of any subcommand that mutates.
//!
//! Nothing in this module reads [`crate::credential`]. The read path resolves a
//! token from flags, the environment, and a stored profile; if any of that
//! could reach here, the prohibition above would be a convention rather than a
//! property. The two paths share the device flow, which is the one source the
//! write path is permitted, and nothing else.

pub mod bootstrap;
pub mod catalogue;
pub mod flow;
pub mod identity;
pub mod remediation;
pub mod scan;
pub mod session;
pub mod sign_in;
pub mod text;
