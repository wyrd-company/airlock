//! The check registry.
//!
//! Check identifiers, statements, and default severities are compiled into the
//! binary rather than loaded from the conformance document, so a released
//! binary always reports what it actually evaluated. A policy may select,
//! parameterise, and re-grade a registered check; it cannot define one.
//!
//! Checks are grouped into capabilities (`base`, `registry`) and each carries
//! an evaluation mode: mechanical checks run against the GitHub API, judgment
//! checks are registered as manual and surfaced for a human, and checks not yet
//! written are registered as unimplemented so they are visibly absent rather
//! than silently absent.
