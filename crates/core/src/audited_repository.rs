//! Inputs controlled by the repository being audited.

use crate::limits::Limits;
use crate::policy::SuppressionRequest;
use crate::yaml;
use crate::{Error, Result};

/// Read reasoned repository requests. Organization authority is applied separately.
pub(crate) fn parse_suppression_requests(
    text: &str,
    limits: &Limits,
) -> Result<Vec<SuppressionRequest>> {
    let document = yaml::parse_mapping(text, limits.yaml)
        .map_err(|e| Error::Policy(format!(".github/airlock.yml: {e}")))?;
    crate::policy::validate_document(&document)?;
    crate::policy::accepted_version(&document)?;
    Ok(crate::policy::repository_exceptions(&document)?
        .into_iter()
        .map(|(rule, exception)| SuppressionRequest {
            rule,
            reason: exception.reason,
        })
        .collect())
}
