//! Resource budgets for hostile input.
//!
//! Everything airlock parses comes from a repository it does not control, so
//! every parser runs under an explicit budget. A budget that is exceeded is
//! reported as an inconclusive result naming the limit — never as absence, and
//! never as a pass.

use std::time::Duration;

/// The budgets applied to one audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest single blob airlock will fetch and parse, in bytes.
    pub max_blob_bytes: usize,
    /// Total bytes of repository content one audit may fetch.
    pub max_total_bytes: usize,
    /// Largest number of tree entries airlock will consider.
    pub max_tree_entries: usize,
    /// Largest number of API result pages airlock will walk for one listing.
    pub max_pages: usize,
    /// Largest number of commits airlock will walk when scanning history.
    pub max_history_commits: usize,
    /// Largest number of workflow files airlock will parse.
    pub max_workflow_files: usize,
    /// Largest number of transitive policy references.
    pub max_policy_references: usize,
    /// Largest policy reference chain depth.
    pub max_policy_reference_depth: usize,
    /// Largest response body airlock will read from one request, in bytes.
    ///
    /// Enforced while the body is being read, so an endless response is
    /// abandoned rather than materialised.
    pub max_response_bytes: usize,
    /// How long airlock will wait to open a connection.
    pub connect_timeout: Duration,
    /// How long airlock will wait for one request to complete.
    pub request_timeout: Duration,
    /// The wall-clock budget for one audit, measured from the first request.
    pub audit_budget: Duration,
    /// YAML parse budget.
    pub yaml: YamlLimits,
}

/// The budget applied to a single YAML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YamlLimits {
    /// Largest document airlock will hand to the YAML parser, in bytes.
    pub max_bytes: usize,
    /// Deepest nesting airlock will accept.
    pub max_depth: usize,
    /// Largest number of nodes airlock will materialise.
    ///
    /// This is what bounds alias expansion: an alias bomb materialises nodes,
    /// and the budget is spent before the expansion becomes expensive.
    pub max_nodes: usize,
}

/// The default YAML budget.
pub const DEFAULT_YAML_LIMITS: YamlLimits = YamlLimits {
    max_bytes: 512 * 1024,
    max_depth: 32,
    max_nodes: 20_000,
};

/// The default audit budget.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_blob_bytes: 1024 * 1024,
    max_total_bytes: 16 * 1024 * 1024,
    max_tree_entries: 20_000,
    max_pages: 20,
    max_history_commits: 1_000,
    max_workflow_files: 100,
    max_policy_references: 16,
    max_policy_reference_depth: 4,
    max_response_bytes: 32 * 1024 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(30),
    audit_budget: Duration::from_secs(300),
    yaml: DEFAULT_YAML_LIMITS,
};

impl Default for Limits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

impl Default for YamlLimits {
    fn default() -> Self {
        DEFAULT_YAML_LIMITS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded() {
        let limits = Limits::default();
        assert!(limits.max_blob_bytes <= limits.max_total_bytes);
        assert!(limits.yaml.max_bytes <= limits.max_blob_bytes);
        assert!(limits.max_pages > 0);
        assert!(limits.max_history_commits > 0);
        assert!(limits.max_tree_entries > 0);
        assert!(limits.max_blob_bytes <= limits.max_response_bytes);
        assert!(limits.connect_timeout <= limits.request_timeout);
        assert!(limits.request_timeout <= limits.audit_budget);
    }
}
