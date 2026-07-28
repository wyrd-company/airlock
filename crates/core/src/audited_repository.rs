//! Inputs controlled by the repository being audited.

use crate::limits::Limits;
use crate::policy::SuppressionRequest;
use crate::yaml::{self, Yaml};
use crate::{Error, Result};

/// Parse an audited repository's `.github/airlock.yml` suppression requests.
///
/// # Errors
///
/// Returns a policy error only when the document is unparseable or malformed.
/// A request for a rule the policy did not authorise is not an error here — it
/// is reported as an unauthorised request.
pub(crate) fn parse_suppression_requests(
    text: &str,
    limits: &Limits,
) -> Result<Vec<SuppressionRequest>> {
    let document = yaml::parse_mapping(text, limits.yaml)
        .map_err(|error| Error::Policy(format!(".github/airlock.yml: {error}")))?;

    for key in document.keys() {
        if !["version", "suppress"].contains(&key) {
            return Err(Error::Policy(format!(
                "unknown key `{key}` in .github/airlock.yml; airlock accepts version, suppress"
            )));
        }
    }

    match document.get("version").and_then(Yaml::as_i64) {
        Some(1) | None => {}
        Some(other) => {
            return Err(Error::Policy(format!(
                ".github/airlock.yml declares version {other}; airlock understands version 1"
            )))
        }
    }

    let Some(entries) = document.get("suppress") else {
        return Ok(Vec::new());
    };
    let Some(items) = entries.as_seq() else {
        return Err(Error::Policy(format!(
            "`suppress` in .github/airlock.yml should be a sequence, found {}",
            entries.kind()
        )));
    };

    let mut requests = Vec::new();
    for item in items {
        for key in item.keys() {
            if !["rule", "reason"].contains(&key) {
                return Err(Error::Policy(format!(
                    "unknown key `{key}` in a .github/airlock.yml suppression request"
                )));
            }
        }
        let rule = item.get("rule").and_then(Yaml::as_str).ok_or_else(|| {
            Error::Policy(
                "every .github/airlock.yml suppression request must name a `rule`".to_owned(),
            )
        })?;
        requests.push(SuppressionRequest {
            rule: rule.to_owned(),
            reason: item
                .get("reason")
                .and_then(Yaml::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }
    Ok(requests)
}
