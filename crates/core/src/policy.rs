//! Policy resolution and validation.
//!
//! A policy is YAML that selects capabilities, sets parameters a check
//! declares, and adjusts severity. It cannot express predicates — the checks
//! themselves are the only place logic lives.
//!
//! Policies resolve from an `owner/repo:path[@ref]` reference fetched through
//! the contents API, or from a local file for development and tests. Airlock
//! ships no built-in policy: an audit without a policy is meaningless, so an
//! unresolvable policy is an operational error rather than an empty run.
//!
//! Suppressions live in the audited repository at `.github/airlock.yml` and are
//! merged in at evaluation time. A suppressed finding is still reported, with
//! its reason attached.
