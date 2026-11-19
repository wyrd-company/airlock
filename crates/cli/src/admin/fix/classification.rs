//! Classification declarations through the existing session-owned writer.
//
// relationships:
//   implements: classification
//   references: terminal-interface

use super::*;
use airlock_core::classification::Property;

impl Session {
    /// Classification is an input, so its write does not require a Gap.
    /// Read the organization property before acting and again after the request.
    pub(super) async fn declare_classification(
        &self,
        owner: &str,
        repo: &str,
        rule: &str,
        argument: Option<&str>,
    ) -> Transcript {
        let started = Instant::now();
        let mut transcript = Transcript {
            rule: text::sanitize(rule, NAME_LIMIT),
            fix: "declare-classification".to_owned(),
            proposed_change: "declare organization-owned repository classification".to_owned(),
            steps: Vec::new(),
            observed: ObservedStatus::Inconclusive,
            undo: None,
        };
        let Some(property) = Property::required_by(rule).first().copied() else {
            transcript.steps.push(step(
                started,
                false,
                "the rule requires no classification declaration; no write was attempted",
            ));
            return transcript;
        };
        let Some(expected) = argument.filter(|value| !value.trim().is_empty()) else {
            transcript.steps.push(step(
                started,
                false,
                "classification requires an explicit operator answer; no write was attempted",
            ));
            return transcript;
        };
        transcript.proposed_change = text::sanitize(
            &format!(
                "set organization property `{}` to `{expected}` for `{owner}/{repo}`",
                property.name(),
            ),
            CAUSE_LIMIT,
        );
        let reader = match self.reader() {
            Ok(reader) => reader,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("could not observe classification: {error:#}"),
                ));
                return transcript;
            }
        };
        let before = match reader.custom_property_values(owner, repo).await {
            Ok(values) => values,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!(
                        "pre-change property observation failed; no write was attempted: {error:#}"
                    ),
                ));
                return transcript;
            }
        };
        let before = match property.read(&before) {
            Ok(value) => value,
            Err(error) => {
                transcript.steps.push(step(started, false, &format!("pre-change property observation was malformed; no write was attempted: {error}")));
                return transcript;
            }
        };
        transcript.steps.push(step(
            started,
            true,
            "re-observed organization-owned classification immediately before acting",
        ));
        if before == Some(expected) {
            transcript.steps.push(step(
                started,
                true,
                "the declared value already matches; no write was needed",
            ));
        } else {
            let changed = self
                .writer
                .set_custom_property(owner, repo, property.name(), expected)
                .await;
            transcript.steps.push(step(started, changed.is_ok(), &changed.map_or_else(
                |error| format!("the classification request failed: {error:#}"),
                |()| "GitHub accepted the classification request; the value must still be observed".to_owned(),
            )));
        }
        match reader.custom_property_values(owner, repo).await {
            Ok(values) => match property.read(&values) {
                Ok(Some(actual)) if actual == expected => {
                    transcript.observed = ObservedStatus::Pass;
                    transcript.steps.push(step(started, true, "re-observed the requested classification value; rule outcomes require a fresh audit"));
                }
                Ok(_) => {
                    transcript.observed = ObservedStatus::Fail;
                    transcript.steps.push(step(started, false, "the requested classification value was not observed; request acceptance alone does not establish it"));
                }
                Err(error) => transcript.steps.push(step(
                    started,
                    false,
                    &format!("post-change property observation was malformed: {error}"),
                )),
            },
            Err(error) => transcript.steps.push(step(
                started,
                false,
                &format!("post-change property observation failed: {error:#}"),
            )),
        }
        transcript
    }
}
