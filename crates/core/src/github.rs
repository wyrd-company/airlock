//! The GitHub API client.
//!
//! Access sits behind a trait so checks can be exercised against recorded
//! fixtures without a network. Airlock speaks REST and GraphQL directly and
//! never shells out to `git` or `gh`.
//!
//! Response classification lives here and nowhere else: authentication
//! failures, rate limiting, plan limitations, permission gaps, and the
//! ambiguous "not found or not visible" case are each distinguished once, so
//! every check inherits the same interpretation.
