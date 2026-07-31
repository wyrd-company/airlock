//! The confirmation and transcript screen for one settings remediation.

use ratatui::text::{Line, Span};

use super::chrome::{fit, wrap};
use super::theme::{Role, Styles};
use crate::admin::remediation::{ObservedStatus, Transcript};

pub(super) const SECRET_DEFERRAL_NOTICE: &str = "airlock cannot read a secret's value back, so this rename needs the value re-entered by a person; the gap stays in the queue until it is";

/// The input a remediation needs before it can be confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// No input: the compiled remediation names the complete change.
    None,
    /// A repository-name target authored in a focused text field.
    Text {
        draft: String,
        required_prefix: Option<String>,
        error: Option<String>,
    },
    /// A value selected from a fresh observation.
    Choice {
        values: Vec<String>,
        selected: usize,
        empty: String,
    },
    /// A non-secret Actions variable selected from fresh observation and
    /// renamed without exposing its value to the renderer.
    VariableRename {
        names: Vec<String>,
        selected: usize,
        draft: String,
        notice: String,
        error: Option<String>,
    },
    /// Transfer needs a selected destination and the repository name typed in full.
    Transfer {
        destinations: Vec<String>,
        selected: usize,
        typed_name: String,
    },
}

/// A confirmed request that contains no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub owner: String,
    pub repo: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub struct UndoRequest {
    pub owner: String,
    pub repo: String,
    pub rule: String,
    pub remediation: String,
    pub undo: crate::admin::remediation::UndoHandle,
    pub expected: ObservedStatus,
}

/// One rule in a single or bulk confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub rule: String,
    pub remediation: String,
    pub change: String,
    pub reversible: bool,
    pub input: Input,
}

impl Item {
    #[must_use]
    pub fn argument(&self) -> Option<String> {
        match &self.input {
            Input::None => None,
            Input::Text { draft, .. } => Some(draft.clone()),
            Input::Choice {
                values, selected, ..
            } => values.get(*selected).cloned(),
            Input::Transfer {
                destinations,
                selected,
                typed_name,
            } => destinations
                .get(*selected)
                .map(|destination| format!("{destination}\n{typed_name}")),
            Input::VariableRename {
                names,
                selected,
                draft,
                ..
            } => names.get(*selected).map(|name| format!("{name}\n{draft}")),
        }
    }
}

/// What the remediation screen currently knows.
#[derive(Debug, Clone, Default)]
pub enum State {
    /// No applicable row was selected.
    #[default]
    Empty,
    /// An input is being authored or selected before confirmation.
    Input { request: Request },
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
    #[must_use]
    pub const fn is_input(&self) -> bool {
        matches!(self, Self::Input { .. })
    }

    #[must_use]
    pub fn captures_text(&self) -> bool {
        matches!(
            self,
            Self::Input { request }
                if request.items.iter().any(|item| matches!(
                    item.input,
                    Input::Text { .. } | Input::Transfer { .. } | Input::VariableRename { .. }
                ))
        )
    }
    /// Build the confirmation from already-sanitized queue data.
    #[must_use]
    pub fn confirm(owner: String, repo: String, items: Vec<Item>) -> Self {
        let request = Request { owner, repo, items };
        if request
            .items
            .iter()
            .any(|item| !matches!(item.input, Input::None))
        {
            Self::Input { request }
        } else {
            Self::Confirm { request }
        }
    }

    /// Apply a key to the focused input. Returns true when the key was captured.
    pub fn input_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        let Self::Input { request } = self else {
            return false;
        };
        let Some(item) = request.items.first_mut() else {
            return false;
        };
        match (&mut item.input, code) {
            (Input::Text { draft, error, .. }, crossterm::event::KeyCode::Backspace) => {
                draft.pop();
                *error = None;
            }
            (Input::Text { draft, error, .. }, crossterm::event::KeyCode::Char(character)) => {
                draft.push(character);
                *error = None;
            }
            (
                Input::Choice {
                    values, selected, ..
                },
                crossterm::event::KeyCode::Up,
            )
            | (
                Input::Transfer {
                    destinations: values,
                    selected,
                    ..
                },
                crossterm::event::KeyCode::Up,
            )
            | (
                Input::VariableRename {
                    names: values,
                    selected,
                    ..
                },
                crossterm::event::KeyCode::Up,
            ) => {
                *selected = selected.saturating_sub(1);
                if values.is_empty() {
                    *selected = 0;
                }
            }
            (
                Input::Choice {
                    values, selected, ..
                },
                crossterm::event::KeyCode::Down,
            )
            | (
                Input::Transfer {
                    destinations: values,
                    selected,
                    ..
                },
                crossterm::event::KeyCode::Down,
            )
            | (
                Input::VariableRename {
                    names: values,
                    selected,
                    ..
                },
                crossterm::event::KeyCode::Down,
            ) => {
                *selected = (*selected + 1).min(values.len().saturating_sub(1));
            }
            (Input::Transfer { typed_name, .. }, crossterm::event::KeyCode::Backspace) => {
                typed_name.pop();
            }
            (Input::Transfer { typed_name, .. }, crossterm::event::KeyCode::Char(character)) => {
                typed_name.push(character);
            }
            (Input::VariableRename { draft, error, .. }, crossterm::event::KeyCode::Backspace) => {
                draft.pop();
                *error = None;
            }
            (
                Input::VariableRename { draft, error, .. },
                crossterm::event::KeyCode::Char(character),
            ) => {
                draft.push(character);
                *error = None;
            }
            (_, crossterm::event::KeyCode::Enter) => return self.validate_input(),
            _ => return false,
        }
        true
    }

    fn validate_input(&mut self) -> bool {
        let Self::Input { request } = self else {
            return false;
        };
        let Some(item) = request.items.first_mut() else {
            return false;
        };
        let remediation = item.remediation.clone();
        let valid = match &mut item.input {
            Input::None => true,
            Input::Text {
                draft,
                required_prefix,
                error,
            } => {
                match validate_repository_target(&remediation, draft, required_prefix.as_deref()) {
                    Ok(()) => true,
                    Err(cause) => {
                        *error = Some(cause);
                        false
                    }
                }
            }
            Input::Choice { values, .. } => !values.is_empty(),
            Input::VariableRename {
                names,
                draft,
                error,
                ..
            } => match validate_variable_name(draft) {
                Ok(()) if !names.is_empty() => true,
                Ok(()) => false,
                Err(cause) => {
                    *error = Some(cause);
                    false
                }
            },
            Input::Transfer {
                destinations,
                typed_name,
                ..
            } => !destinations.is_empty() && typed_name == &request.repo,
        };
        if valid {
            let request = request.clone();
            *self = Self::Confirm { request };
        }
        true
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

    pub fn take_undo(&mut self) -> Option<UndoRequest> {
        let Self::Complete {
            request,
            transcripts,
        } = self
        else {
            return None;
        };
        if transcripts.len() != 1 {
            return None;
        }
        let transcript = transcripts.first()?;
        let undo = transcript.undo?;
        let result = UndoRequest {
            owner: request.owner.clone(),
            repo: request.repo.clone(),
            rule: transcript.rule.clone(),
            remediation: transcript.remediation.clone(),
            undo,
            expected: transcript.observed,
        };
        *self = Self::Applying {
            request: request.clone(),
        };
        Some(result)
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
            Self::Input { .. } => "input required before confirmation",
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
        | State::Input { request }
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
        lines.push(Line::from(fit(
            &format!(
                "{} · {} · {} · {}",
                item.rule,
                item.remediation,
                item.change,
                if item.reversible {
                    "reversible"
                } else {
                    "not reversible"
                }
            ),
            width,
        )));
    }
    lines.push(Line::default());
    match state {
        State::Input { request } => match &request.items[0].input {
            Input::Text { draft, error, .. } => {
                lines.push(Line::from(format!("new name        {draft}")));
                if let Some(error) = error {
                    lines.push(Line::from(format!("invalid         {error}")));
                }
            }
            Input::Choice {
                values,
                selected,
                empty,
            } => {
                if values.is_empty() {
                    lines.push(Line::from(format!("empty           {empty}")));
                } else {
                    for (index, value) in values.iter().enumerate() {
                        lines.push(Line::from(format!(
                            "{} {value}",
                            if index == *selected { ">" } else { " " }
                        )));
                    }
                }
            }
            Input::VariableRename {
                names,
                selected,
                draft,
                notice,
                error,
            } => {
                lines.push(Line::from(format!("secret values   {notice}")));
                for (index, value) in names.iter().enumerate() {
                    lines.push(Line::from(format!(
                        "{} variable    {value}",
                        if index == *selected { ">" } else { " " }
                    )));
                }
                lines.push(Line::from(format!("new name        {draft}")));
                if let Some(error) = error {
                    lines.push(Line::from(format!("invalid         {error}")));
                }
            }
            Input::Transfer {
                destinations,
                selected,
                typed_name,
            } => {
                for (index, value) in destinations.iter().enumerate() {
                    lines.push(Line::from(format!(
                        "{} destination {value}",
                        if index == *selected { ">" } else { " " }
                    )));
                }
                lines.push(Line::from(format!("type name       {typed_name}")));
            }
            Input::None => {}
        },
        State::Confirm { request } => {
            for item in &request.items {
                for line in confirmed_input(item, &request.repo, width) {
                    lines.push(Line::from(line));
                }
            }
            lines.push(Line::from(Span::styled(
                "Press enter to confirm. No request has been made.",
                styles.bold(Role::Text),
            )));
        }
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
                if transcripts.len() == 1 {
                    lines.push(Line::from(if transcript.undo.is_some() {
                        "undo            press u to restore the observed previous value"
                    } else {
                        "undo            unavailable; this change is not safely reversible"
                    }));
                }
            }
            if transcripts.len() > 1 {
                lines.push(Line::from(
                    "undo            unavailable after a bulk confirmation",
                ));
            }
        }
        State::Empty => {}
    }
    lines
}

fn confirmed_input(item: &Item, repository: &str, width: usize) -> Vec<String> {
    match &item.input {
        Input::None => Vec::new(),
        Input::Text { draft, .. } => vec![format!("selected        {draft}")],
        Input::Choice {
            values, selected, ..
        } => {
            let Some(value) = values.get(*selected) else {
                return Vec::new();
            };
            let mut lines = vec![format!("selected        {value}")];
            if item.remediation == "attach-org-rulesets" && value.starts_with("create ") {
                for (index, part) in wrap(
                    &ruleset_preview(repository),
                    width.saturating_sub(16).max(1),
                )
                .into_iter()
                .enumerate()
                {
                    lines.push(format!(
                        "{:<16}{part}",
                        if index == 0 { "ruleset body" } else { "" }
                    ));
                }
            } else if item.remediation == "attach-org-rulesets" {
                lines.push(format!(
                    "change          add {repository} to the repositories this ruleset covers; preserve its rules"
                ));
            } else if item.remediation == "tighten-org-rulesets" {
                lines.push(
                    "change          allow only squash and rebase; require linear history; preserve every other observed rule and parameter"
                        .to_owned(),
                );
            }
            lines
        }
        Input::VariableRename {
            names,
            selected,
            draft,
            notice,
            ..
        } => vec![
            format!(
                "selected        {} → {draft}",
                names.get(*selected).map_or("", String::as_str)
            ),
            format!("secret values   {notice}"),
        ],
        Input::Transfer {
            destinations,
            selected,
            typed_name,
        } => vec![
            format!(
                "destination     {}",
                destinations.get(*selected).map_or("", String::as_str)
            ),
            format!("typed name      {typed_name}"),
            "undo             unavailable after transfer".to_owned(),
        ],
    }
}

fn ruleset_preview(repository: &str) -> String {
    serde_json::to_string(&crate::admin::remediation::ruleset_body(Some(repository)))
        .expect("the compiled ruleset body serializes")
}

/// GitHub repository-name validation used before a rename is offered.
pub fn validate_repository_name(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 100 {
        return Err("use between 1 and 100 characters".to_owned());
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err("a repository name cannot start or end with a dot".to_owned());
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err("use only letters, digits, hyphens, underscores, and dots".to_owned());
    }
    Ok(())
}

fn validate_repository_target(
    remediation: &str,
    value: &str,
    required_prefix: Option<&str>,
) -> Result<(), String> {
    validate_repository_name(value)?;
    match remediation {
        "rename-repository-kebab"
            if rename_candidate("rename-repository-kebab", value, None) != value =>
        {
            Err("use lowercase kebab-case".to_owned())
        }
        "rename-repository-undotted" if value.contains('.') => {
            Err("the repository name must not contain a dot".to_owned())
        }
        "rename-repository-family-prefix" => {
            let prefix = required_prefix.ok_or_else(|| {
                "airlock did not observe a family prefix, so it cannot validate this target"
                    .to_owned()
            })?;
            if value.starts_with(&format!("{prefix}-")) {
                Ok(())
            } else {
                Err(format!("the name must start with `{prefix}-`"))
            }
        }
        _ => Ok(()),
    }
}

/// The mechanical candidates the three rename rules can derive.
pub fn rename_candidate(code: &str, current: &str, family: Option<&str>) -> String {
    match code {
        "rename-repository-kebab" => current
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|part| !part.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("-"),
        "rename-repository-undotted" => current.replace('.', "-"),
        "rename-repository-family-prefix" => family.map_or_else(String::new, |family| {
            if current.starts_with(&format!("{family}-")) {
                current.to_owned()
            } else {
                format!("{family}-{current}")
            }
        }),
        _ => current.to_owned(),
    }
}

fn validate_variable_name(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("enter a variable name".to_owned());
    }
    if value.len() > 48 {
        return Err("variable names are at most 48 characters".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("use uppercase letters, digits, and underscores".to_owned());
    }
    Ok(())
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
                input: Input::None,
            }],
        );
        assert!(state.take_confirmation().is_some());
        assert!(state.take_confirmation().is_none());
    }

    #[test]
    fn repository_names_are_validated_before_confirmation() {
        assert!(validate_repository_name("sample-repository").is_ok());
        for invalid in ["", ".hidden", "ends.", "has space", "has/slash"] {
            assert!(validate_repository_name(invalid).is_err(), "{invalid}");
        }
        assert!(
            validate_repository_target("rename-repository-kebab", "double--hyphen", None).is_err()
        );
        assert!(validate_repository_target(
            "rename-repository-family-prefix",
            "sample-repository",
            None
        )
        .is_err());
        assert!(validate_repository_target(
            "rename-repository-family-prefix",
            "family-sample-repository",
            Some("family")
        )
        .is_ok());
    }

    #[test]
    fn only_text_bearing_inputs_capture_printable_keys() {
        let state = |input| {
            State::confirm(
                "generic-owner".to_owned(),
                "sample-repository".to_owned(),
                vec![Item {
                    rule: "REPO-SAMPLE-01".to_owned(),
                    remediation: "sample".to_owned(),
                    change: "sample".to_owned(),
                    reversible: true,
                    input,
                }],
            )
        };
        assert!(state(Input::Text {
            draft: String::new(),
            required_prefix: None,
            error: None,
        })
        .captures_text());
        assert!(!state(Input::Choice {
            values: vec!["observed".to_owned()],
            selected: 0,
            empty: String::new(),
        })
        .captures_text());
    }

    #[test]
    fn secret_deferral_notice_renders_the_person_and_queue_contract() {
        let state = State::confirm(
            "generic-owner".to_owned(),
            "sample-repository".to_owned(),
            vec![Item {
                rule: "REPO-SAMPLE-01".to_owned(),
                remediation: "rename-app-credentials".to_owned(),
                change: "sample".to_owned(),
                reversible: true,
                input: Input::VariableRename {
                    names: vec!["LEGACY_NAME".to_owned()],
                    selected: 0,
                    draft: "CURRENT_NAME".to_owned(),
                    notice: SECRET_DEFERRAL_NOTICE.to_owned(),
                    error: None,
                },
            }],
        );
        let rendered = body(
            Styles::new(
                super::super::theme::Theme::Dark,
                super::super::theme::ColorMode::Color,
            ),
            120,
            &state,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

        assert!(
            rendered.contains(&format!("secret values   {SECRET_DEFERRAL_NOTICE}")),
            "{rendered}"
        );
        assert!(!rendered.contains("task 97"), "{rendered}");
    }

    #[test]
    fn bulk_completion_offers_no_single_rule_undo() {
        let item = |rule: &str| Item {
            rule: rule.to_owned(),
            remediation: "disable-merge-commits".to_owned(),
            change: "change".to_owned(),
            reversible: true,
            input: Input::None,
        };
        let mut state = State::confirm(
            "generic-owner".to_owned(),
            "sample-repository".to_owned(),
            vec![item("REPO-SAMPLE-01"), item("REPO-SAMPLE-02")],
        );
        let _ = state.take_confirmation();
        state.complete_group(
            ["REPO-SAMPLE-01", "REPO-SAMPLE-02"]
                .into_iter()
                .enumerate()
                .map(|(index, rule)| Transcript {
                    rule: rule.to_owned(),
                    remediation: "disable-merge-commits".to_owned(),
                    proposed_change: "change".to_owned(),
                    steps: Vec::new(),
                    observed: ObservedStatus::Pass,
                    undo: Some(crate::admin::remediation::UndoHandle::fixture(
                        index as u64 + 1,
                    )),
                })
                .collect(),
        );
        assert!(state.take_undo().is_none());
        let rendered = body(
            Styles::new(
                super::super::theme::Theme::Dark,
                super::super::theme::ColorMode::Color,
            ),
            120,
            &state,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
        assert!(!rendered.contains("press u to restore"), "{rendered}");
        assert_eq!(
            rendered
                .matches("unavailable after a bulk confirmation")
                .count(),
            1
        );
    }
}
