//! The confirmation and transcript screen for one settings remediation.

use ratatui::text::{Line, Span};

use super::chrome::wrap;
use super::theme::{Role, Styles};
use crate::admin::remediation::{ObservedStatus, Transcript};

/// A confirmed request that contains no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub owner: String,
    pub repo: String,
    pub items: Vec<Item>,
}

/// One rule in a single or bulk confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub rule: String,
    pub remediation: String,
    pub change: String,
    pub reversible: bool,
}

/// What the remediation screen currently knows.
#[derive(Debug, Clone, Default)]
pub enum State {
    /// No applicable row was selected.
    #[default]
    Empty,
    /// The change is named and awaits the operator's confirmation.
    Confirm { request: Request },
    /// The confirmed operation is in flight.
    Applying { request: Request },
    /// The worker returned the observed result.
    Complete {
        request: Request,
        transcripts: Vec<Transcript>,
    },
}

impl State {
    /// Build the confirmation from already-sanitized queue data.
    #[must_use]
    pub fn confirm(owner: String, repo: String, items: Vec<Item>) -> Self {
        Self::Confirm {
            request: Request { owner, repo, items },
        }
    }

    /// Confirm once. Repeated enter presses cannot queue repeated writes.
    pub fn take_confirmation(&mut self) -> Option<Request> {
        let Self::Confirm { request } = self else {
            return None;
        };
        let request = request.clone();
        *self = Self::Applying {
            request: request.clone(),
        };
        Some(request)
    }

    /// Close the in-flight operation with its transcript.
    pub fn complete(&mut self, transcript: Transcript) {
        self.complete_group(vec![transcript]);
    }

    /// Close a bulk operation with one transcript per rule.
    pub fn complete_group(&mut self, transcripts: Vec<Transcript>) {
        let Self::Applying { request } = self else {
            return;
        };
        *self = Self::Complete {
            request: request.clone(),
            transcripts,
        };
    }

    /// How many queue items remain after this one.
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self {
            Self::Empty => "no settings remediation selected",
            Self::Confirm { .. } => "confirmation required · re-observes before and after",
            Self::Applying { .. } => "applying · final status will follow re-observation",
            Self::Complete { transcripts, .. }
                if transcripts
                    .iter()
                    .all(|transcript| transcript.observed == ObservedStatus::Pass) =>
            {
                "observed pass · confirmed gaps closed"
            }
            Self::Complete { .. } => "one or more observed gaps remain open",
        }
    }
}

/// Draw the proposal before the transcript, so confirmation never happens
/// without the operator first seeing what will change.
#[must_use]
pub fn body(styles: Styles, width: usize, state: &State) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "SETTINGS REMEDIATION",
        styles.bold(Role::Accent),
    ))];
    let request = match state {
        State::Empty => {
            lines.push(Line::from(
                "would show      the proposed change and transcript",
            ));
            lines.push(Line::from(
                "empty because   no applicable settings remediation is selected",
            ));
            lines.push(Line::from(
                "next            return to findings and select a settings row",
            ));
            return lines;
        }
        State::Confirm { request }
        | State::Applying { request }
        | State::Complete { request, .. } => request,
    };
    for (label, value) in [
        ("repository", format!("{}/{}", request.owner, request.repo)),
        ("rules", request.items.len().to_string()),
    ] {
        for (index, part) in wrap(&value, width.saturating_sub(16).max(1))
            .into_iter()
            .enumerate()
        {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<16}", if index == 0 { label } else { "" }),
                    styles.of(Role::Faint),
                ),
                Span::styled(part, styles.of(Role::Text)),
            ]));
        }
    }
    for item in &request.items {
        lines.push(Line::from(format!(
            "{} · {} · {} · {}",
            item.rule,
            item.remediation,
            item.change,
            if item.reversible {
                "reversible"
            } else {
                "not reversible"
            }
        )));
    }
    lines.push(Line::default());
    match state {
        State::Confirm { .. } => lines.push(Line::from(Span::styled(
            "Press enter to confirm. No request has been made.",
            styles.bold(Role::Text),
        ))),
        State::Applying { .. } => lines.push(Line::from("Confirmed. Waiting for re-observation.")),
        State::Complete { transcripts, .. } => {
            lines.push(Line::from(Span::styled(
                "TRANSCRIPT",
                styles.bold(Role::Text),
            )));
            for transcript in transcripts {
                lines.push(Line::from(Span::styled(
                    format!("{} · {}", transcript.rule, transcript.remediation),
                    styles.bold(Role::Text),
                )));
                for step in &transcript.steps {
                    let glyph = if step.succeeded { "✓" } else { "!" };
                    lines.push(Line::from(format!(
                        "{glyph} +{:>6.2}s  {}",
                        step.elapsed.as_secs_f64(),
                        step.detail
                    )));
                }
            }
        }
        State::Empty => {}
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_is_single_use() {
        let mut state = State::confirm(
            "generic-owner".to_owned(),
            "sample-repository".to_owned(),
            vec![Item {
                rule: "REPO-GIT-04".to_owned(),
                remediation: "disable-merge-commits".to_owned(),
                change: "Disable merge commits.".to_owned(),
                reversible: true,
            }],
        );
        assert!(state.take_confirmation().is_some());
        assert!(state.take_confirmation().is_none());
    }
}
