//! Repository creation as the maximally unaligned align case.

use crossterm::event::KeyCode;
use ratatui::text::{Line, Span};

use crate::admin::remediation::{
    valid_repository_name, ScaffoldCapability, ScaffoldPlan, ScaffoldRequest,
};

use super::chrome::wrap;
use super::theme::{Role, Styles};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Visibility,
    Capabilities,
    Confirm,
}

#[derive(Debug, Clone)]
pub struct State {
    owner: String,
    owner_is_organization: bool,
    name: String,
    visibility: usize,
    capabilities: Vec<ScaffoldCapability>,
    selected: Vec<bool>,
    capability: usize,
    files: Vec<String>,
    field: Field,
    loading: bool,
    creating: bool,
    error: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            owner: String::new(),
            owner_is_organization: true,
            name: String::new(),
            visibility: 0,
            capabilities: Vec::new(),
            selected: Vec::new(),
            capability: 0,
            files: Vec::new(),
            field: Field::Name,
            loading: false,
            creating: false,
            error: None,
        }
    }
}

impl State {
    pub fn begin(&mut self, owner: String, owner_is_organization: bool) {
        *self = Self {
            owner,
            owner_is_organization,
            loading: true,
            ..Self::default()
        };
    }

    pub fn prepared(&mut self, plan: ScaffoldPlan) {
        self.owner = plan.owner;
        self.selected = vec![false; plan.capabilities.len()];
        self.capabilities = plan.capabilities;
        self.files = plan.files;
        self.loading = false;
        self.error = None;
    }

    pub fn failed(&mut self, cause: String) {
        self.loading = false;
        self.creating = false;
        self.error = Some(cause);
    }

    pub fn captures_text(&self) -> bool {
        !self.owner.is_empty() && !self.loading && !self.creating && self.field == Field::Name
    }

    pub fn started(&self) -> bool {
        !self.owner.is_empty()
    }

    pub fn key(&mut self, code: KeyCode) -> Option<ScaffoldRequest> {
        if self.loading || self.creating {
            return None;
        }
        self.error = None;
        if self.field == Field::Name {
            match code {
                KeyCode::Char(character) => self.name.push(character),
                KeyCode::Backspace => {
                    self.name.pop();
                }
                KeyCode::Enter | KeyCode::Down => {
                    if valid_repository_name(&self.name) {
                        self.field = Field::Visibility;
                    } else {
                        self.error = Some(
                            "enter a GitHub repository name before choosing settings".to_owned(),
                        );
                    }
                }
                _ => {}
            }
            return None;
        }
        match code {
            KeyCode::Up => {
                self.field = match self.field {
                    Field::Visibility => Field::Name,
                    Field::Capabilities => Field::Visibility,
                    Field::Confirm => Field::Capabilities,
                    Field::Name => Field::Name,
                }
            }
            KeyCode::Down | KeyCode::Enter if self.field != Field::Confirm => {
                self.field = match self.field {
                    Field::Name => Field::Visibility,
                    Field::Visibility => Field::Capabilities,
                    Field::Capabilities => Field::Confirm,
                    Field::Confirm => Field::Confirm,
                }
            }
            KeyCode::Left | KeyCode::Right if self.field == Field::Visibility => {
                self.visibility = if code == KeyCode::Left {
                    self.visibility.saturating_sub(1)
                } else {
                    (self.visibility + 1).min(if self.owner_is_organization { 2 } else { 1 })
                };
            }
            KeyCode::Left if self.field == Field::Capabilities => {
                self.capability = self.capability.saturating_sub(1);
            }
            KeyCode::Right if self.field == Field::Capabilities => {
                self.capability =
                    (self.capability + 1).min(self.capabilities.len().saturating_sub(1));
            }
            KeyCode::Char(' ') if self.field == Field::Capabilities => {
                if let Some(selected) = self.selected.get_mut(self.capability) {
                    *selected = !*selected;
                }
            }
            KeyCode::Enter if self.field == Field::Confirm => {
                if !valid_repository_name(&self.name) {
                    self.error =
                        Some("enter a GitHub repository name before confirming".to_owned());
                    self.field = Field::Name;
                    return None;
                }
                self.creating = true;
                return Some(ScaffoldRequest {
                    owner: self.owner.clone(),
                    owner_is_organization: self.owner_is_organization,
                    name: self.name.clone(),
                    visibility: ["public", "private", "internal"][self.visibility].to_owned(),
                    capabilities: self
                        .capabilities
                        .iter()
                        .zip(&self.selected)
                        .filter(|(_, selected)| **selected)
                        .map(|(capability, _)| capability.clone())
                        .collect(),
                });
            }
            _ => {}
        }
        None
    }

    pub fn status(&self) -> String {
        if self.loading {
            return "resolving the owner policy before offering choices".to_owned();
        }
        if self.creating {
            return "creating · the ordinary audit follows the first commit".to_owned();
        }
        self.error.clone().unwrap_or_else(|| {
            "first commit only · later file changes leave as pull requests".to_owned()
        })
    }
}

pub fn body(styles: Styles, width: usize, state: &State) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "SCAFFOLD AS ALIGN",
        styles.bold(Role::Accent),
    ))];
    for line in wrap(
        "Create the empty repository and its one branch-creating commit from the resolved owner policy. This exception ends when `main` exists.",
        width,
    ) {
        lines.push(Line::from(Span::styled(line, styles.of(Role::Text))));
    }
    lines.push(Line::default());
    if state.loading {
        lines.push(Line::from("Resolving policy…"));
        return lines;
    }
    let marker = |field| if state.field == field { "›" } else { " " };
    lines.push(Line::from(format!("  owner        {}", state.owner)));
    lines.push(Line::from(format!(
        "{} name         {}",
        marker(Field::Name),
        state.name
    )));
    lines.push(Line::from(format!(
        "{} visibility   {}",
        marker(Field::Visibility),
        ["public", "private", "internal"][state.visibility]
    )));
    let declarations = if state.capabilities.is_empty() {
        "none offered by the policy".to_owned()
    } else {
        state
            .capabilities
            .iter()
            .enumerate()
            .map(|(index, capability)| {
                format!(
                    "{}{}",
                    if state.selected[index] {
                        "[x] "
                    } else {
                        "[ ] "
                    },
                    capability.display_name
                )
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };
    lines.push(Line::from(format!(
        "{} capabilities {}",
        marker(Field::Capabilities),
        declarations
    )));
    lines.push(Line::from(format!(
        "  first commit {}",
        if state.files.is_empty() {
            "no files".to_owned()
        } else {
            state.files.join(", ")
        }
    )));
    lines.push(Line::default());
    lines.push(Line::from(format!(
        "{} confirm      press enter to create and audit",
        marker(Field::Confirm)
    )));
    if let Some(error) = &state.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            error.clone(),
            styles.bold(Role::Accent),
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ScaffoldPlan {
        ScaffoldPlan {
            owner: "generic-account".to_owned(),
            capabilities: vec![ScaffoldCapability {
                name: "package".to_owned(),
                display_name: "package".to_owned(),
                property: "publishes".to_owned(),
                value: "true".to_owned(),
            }],
            files: vec!["LICENSE".to_owned()],
        }
    }

    #[test]
    fn confirmation_carries_the_chosen_visibility_and_capabilities() {
        let mut state = State::default();
        state.begin("generic-account".to_owned(), true);
        state.prepared(plan());
        for character in "sample-repository".chars() {
            state.key(KeyCode::Char(character));
        }
        state.key(KeyCode::Enter);
        state.key(KeyCode::Right);
        state.key(KeyCode::Enter);
        state.key(KeyCode::Char(' '));
        state.key(KeyCode::Down);
        let request = state.key(KeyCode::Enter).expect("confirmed request");
        assert_eq!(request.name, "sample-repository");
        assert_eq!(request.visibility, "private");
        assert_eq!(request.capabilities, plan().capabilities);
    }

    #[test]
    fn an_empty_name_never_produces_a_request() {
        let mut state = State::default();
        state.begin("generic-account".to_owned(), true);
        state.prepared(plan());
        state.key(KeyCode::Enter);
        state.key(KeyCode::Enter);
        state.key(KeyCode::Down);
        assert!(state.key(KeyCode::Enter).is_none());
        assert!(state.status().contains("enter a GitHub repository name"));
    }

    #[test]
    fn an_invalid_name_stays_in_the_focused_text_input() {
        let mut state = State::default();
        state.begin("generic-account".to_owned(), true);
        state.prepared(plan());
        for character in "not accepted".chars() {
            state.key(KeyCode::Char(character));
        }

        state.key(KeyCode::Enter);

        assert!(state.captures_text());
        assert!(state.status().contains("enter a GitHub repository name"));
    }

    #[test]
    fn prepared_scaffold_fits_the_floor_without_eliding_policy_facts() {
        let mut state = State::default();
        state.begin("generic-account".to_owned(), true);
        state.prepared(plan());
        let lines = body(
            Styles::new(
                super::super::theme::Theme::Dark,
                super::super::theme::ColorMode::Color,
            ),
            80,
            &state,
        );
        assert!(lines.iter().all(|line| line.width() <= 80));
        let text = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        for fact in ["generic-account", "package", "LICENSE"] {
            assert!(text.contains(fact), "{fact}");
        }
    }

    #[test]
    fn confirmation_uses_raw_policy_data_not_its_drawable_copy() {
        let mut hostile = plan();
        hostile.capabilities[0].value = "tr\u{1b}ue".to_owned();
        hostile.capabilities[0].display_name = "package�".to_owned();
        let mut state = State::default();
        state.begin("generic-account".to_owned(), true);
        state.prepared(hostile);
        state.name = "sample-repository".to_owned();
        state.field = Field::Capabilities;
        state.key(KeyCode::Char(' '));
        state.field = Field::Confirm;
        let request = state.key(KeyCode::Enter).expect("confirmed request");
        assert_eq!(request.capabilities[0].value, "tr\u{1b}ue");
        assert_eq!(request.capabilities[0].display_name, "package�");
    }
}
