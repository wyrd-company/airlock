//! The organizations screen: choose which installation to work in.
//!
//! The screen is the list and nothing else. What an absent organization means,
//! and which of the three remedies closes it, is a reading an operator wants
//! once and only when something looks wrong — so it is on `h`, in the help
//! panel, rather than standing on every frame between them and the list they
//! came to choose from.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::admin::catalogue::{Installation, State};

use super::chrome::fit;
use super::panel;
use super::theme::{Role, Styles};

/// The mark on the selected row.
const SELECTED: &str = "\u{25b8} ";

/// The mark on every other row, so nothing moves when the selection does.
const UNSELECTED: &str = "  ";

/// The widest an account column grows to before names are elided into it.
const ACCOUNT_WIDTH: usize = 28;

/// The column the kind is printed in.
const KIND_WIDTH: usize = 16;

/// The whole screen.
#[must_use]
pub fn body(
    styles: Styles,
    width: u16,
    height: u16,
    state: &State,
    selected: usize,
) -> Vec<Line<'static>> {
    list(styles, width as usize, height as usize, state, selected)
}

/// The status line: what the screen knows that the list does not already say.
///
/// A ready list says its own count under its own heading, so there is nothing
/// left for this row to add and it says nothing. The three states that are not
/// ready are not the list at all, and each of them says which one it is.
#[must_use]
pub fn status(state: &State) -> String {
    match state {
        State::Unauthorized => "no authorization yet".to_owned(),
        State::Reading => "reading the installations".to_owned(),
        State::Failed(_) => "the installations could not be read".to_owned(),
        State::Ready(_) => String::new(),
    }
}

/// How many rows the list can be moved through.
#[must_use]
pub fn len(state: &State) -> usize {
    state.installations().len()
}

fn list(
    styles: Styles,
    width: usize,
    room: usize,
    state: &State,
    selected: usize,
) -> Vec<Line<'static>> {
    let installations = state.installations();
    let mut lines = vec![Line::from(vec![
        Span::styled("INSTALLED ORGANIZATIONS", styles.bold(Role::Text)),
        Span::styled(
            match state {
                State::Ready(_) => format!("  {}", counted(installations.len())),
                State::Unauthorized | State::Reading | State::Failed(_) => String::new(),
            },
            styles.of(Role::Faint),
        ),
    ])];
    let room = room.saturating_sub(1);

    match state {
        State::Unauthorized => {
            return note(
                lines,
                styles,
                width,
                "nothing has been asked for yet: no authorization exists, and the list \
                 is read with the session's own grant.",
            )
        }
        State::Reading => {
            return note(
                lines,
                styles,
                width,
                "reading. Airlock is asking GitHub which installations this account \
                 reaches, and what each of them covers.",
            )
        }
        State::Failed(cause) => {
            return note(
                lines,
                styles,
                width,
                &format!(
                    "the read failed, so this is not an empty list: {cause}. A failed \
                     read and an absent install look alike, which is why the failure \
                     is named here."
                ),
            )
        }
        State::Ready(_) if installations.is_empty() => {
            return note(
                lines,
                styles,
                width,
                "none. An empty list has three causes and three different remedies: \
                 press h for them.",
            )
        }
        State::Ready(_) => {}
    }

    let costs: Vec<usize> = installations
        .iter()
        .map(|installation| 1 + usize::from(installation.scope_note().is_some()))
        .collect();
    let (start, end) = fitting(&costs, selected, room.max(1));
    for (index, installation) in installations.iter().enumerate().take(end).skip(start) {
        lines.extend(row(styles, width, installation, index == selected));
    }
    if end - start < installations.len() {
        lines.push(Line::from(Span::styled(
            format!(
                "  showing {}\u{2013}{} of {}; \u{2191}\u{2193} moves through the rest",
                start + 1,
                end,
                installations.len()
            ),
            styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
    }
    lines
}

fn note(
    mut lines: Vec<Line<'static>>,
    styles: Styles,
    width: usize,
    text: &str,
) -> Vec<Line<'static>> {
    lines.extend(panel::field(styles, "", text, width));
    lines
}

fn row(
    styles: Styles,
    width: usize,
    installation: &Installation,
    selected: bool,
) -> Vec<Line<'static>> {
    let account_width = ACCOUNT_WIDTH.min(width.saturating_sub(KIND_WIDTH + 20).max(8));
    let mut lines = vec![Line::from(vec![
        Span::styled(
            if selected { SELECTED } else { UNSELECTED },
            styles.bold(Role::Accent),
        ),
        Span::styled(
            format!(
                "{:<account_width$}",
                fit(&installation.account, account_width)
            ),
            if selected {
                styles.bold(Role::Text)
            } else {
                styles.of(Role::Text)
            },
        ),
        Span::styled(
            format!("{:<KIND_WIDTH$}", installation.kind.label()),
            styles.of(Role::Dim),
        ),
        Span::styled(installation.listing.count(), styles.of(Role::Dim)),
    ])];
    // The scope note rides under its own row rather than in a column, because
    // it is a sentence about that installation and one of the three causes.
    if let Some(note) = installation.scope_note() {
        lines.push(Line::from(Span::styled(
            format!("    {}", fit(&note, width.saturating_sub(4))),
            styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
    }
    lines
}

/// The widest window around `selected` whose costs fit in `room`.
fn fitting(costs: &[usize], selected: usize, room: usize) -> (usize, usize) {
    if costs.is_empty() {
        return (0, 0);
    }
    let selected = selected.min(costs.len() - 1);
    let mut start = selected;
    let mut end = selected + 1;
    let mut used = costs[selected];
    loop {
        let before = start > 0 && used + costs[start - 1] <= room;
        let after = end < costs.len() && used + costs[end] <= room;
        if !before && !after {
            break;
        }
        // Forwards first, so a selection at the top of a long list reads as the
        // head of it rather than as the middle.
        if after {
            used += costs[end];
            end += 1;
        } else if before {
            start -= 1;
            used += costs[start];
        }
    }
    (start, end)
}

/// The count, in the noun it is a count of.
fn counted(installations: usize) -> String {
    let noun = if installations == 1 {
        "installation"
    } else {
        "installations"
    };
    format!("{installations} {noun}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::catalogue::{Catalogue, Listing, Repository};
    use crate::tui::theme::{ColorMode, Theme};
    use airlock_core::github::{AccountKind, RepositorySelection};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    pub(crate) fn installation(
        account: &str,
        kind: AccountKind,
        selection: RepositorySelection,
        names: &[&str],
    ) -> Installation {
        Installation {
            id: 7,
            account: account.to_owned(),
            kind,
            selection,
            listing: Listing::Read {
                repositories: names
                    .iter()
                    .map(|name| Repository {
                        owner: account.to_owned(),
                        name: (*name).to_owned(),
                        visibility: "private".to_owned(),
                    })
                    .collect(),
                total: names.len() as u64,
                truncated: false,
            },
        }
    }

    fn rendered(state: &State, width: u16, height: u16, selected: usize) -> String {
        // Padding and wrapping are layout, not text: the reading a person gets
        // is the words, so the words are what the assertions are made against.
        body(styles(), width, height, state, selected)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn ready(installations: Vec<Installation>) -> State {
        State::Ready(Box::new(Catalogue::of(installations)))
    }

    #[test]
    fn an_empty_list_says_what_it_can_mean_and_where_the_rest_of_it_is() {
        for width in [120, 80] {
            let text = rendered(&ready(Vec::new()), width, 40, 0);
            assert!(text.contains("three causes"), "{text}");
            assert!(text.contains("press h"), "{text}");
        }
    }

    #[test]
    fn the_screen_is_the_list_and_nothing_else() {
        let populated = rendered(
            &ready(vec![installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &["widget"],
            )]),
            120,
            40,
            0,
        );
        // The three causes moved onto `h`, the intersection sentence is gone,
        // and the credential is not this screen's to state.
        for absent in ["THREE CAUSES", "intersection", "CREDENTIAL", "device flow"] {
            assert!(!populated.contains(absent), "{absent}: {populated}");
        }
    }

    #[test]
    fn the_heading_names_the_installations_and_counts_them_in_the_noun() {
        let text = rendered(
            &ready(vec![installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &["widget"],
            )]),
            120,
            40,
            0,
        );
        assert!(text.contains("INSTALLED ORGANIZATIONS"), "{text}");
        assert!(text.contains("1 installation"), "{text}");
        assert!(!text.contains("REACHABLE"), "{text}");
    }

    #[test]
    fn a_row_states_its_kind_and_its_repository_count() {
        let text = rendered(
            &ready(vec![installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &["widget", "sprocket"],
            )]),
            120,
            40,
            0,
        );
        assert!(text.contains("acme-industries"), "{text}");
        assert!(text.contains("organization"), "{text}");
        assert!(text.contains("2 repositories"), "{text}");
    }

    #[test]
    fn a_scoped_installation_says_so_on_its_row() {
        let text = rendered(
            &ready(vec![installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::Selected,
                &["widget"],
            )]),
            120,
            40,
            0,
        );
        assert!(text.contains("scoped to 1 selected repository"), "{text}");
    }

    #[test]
    fn a_user_account_beside_an_organization_is_told_apart_on_the_screen() {
        let text = rendered(
            &ready(vec![
                installation(
                    "acme-industries",
                    AccountKind::Organization,
                    RepositorySelection::All,
                    &["widget"],
                ),
                installation(
                    "sample-operator",
                    AccountKind::UserAccount,
                    RepositorySelection::All,
                    &["notes"],
                ),
            ]),
            120,
            40,
            0,
        );
        assert!(text.contains("organization"), "{text}");
        assert!(text.contains("user account"), "{text}");
        assert!(text.contains("sample-operator"), "{text}");
    }

    #[test]
    fn a_failed_read_is_never_drawn_as_an_empty_list() {
        let text = rendered(
            &State::Failed("rate_limit on GET /user".to_owned()),
            120,
            40,
            0,
        );
        assert!(text.contains("the read failed"), "{text}");
        assert!(text.contains("rate_limit"), "{text}");
    }

    #[test]
    fn a_list_longer_than_the_screen_says_what_it_is_showing() {
        let many: Vec<_> = (0..40)
            .map(|index| {
                installation(
                    &format!("account-{index}"),
                    AccountKind::Organization,
                    RepositorySelection::All,
                    &[],
                )
            })
            .collect();
        let state = ready(many);
        let text = rendered(&state, 80, 24, 0);
        assert!(text.contains("of 40"), "{text}");
        // The selection is always in view, wherever it is.
        let text = rendered(&state, 80, 24, 39);
        assert!(text.contains("account-39"), "{text}");
    }

    #[test]
    fn the_status_line_says_nothing_the_list_has_already_said() {
        let line = status(&ready(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &[],
        )]));
        assert!(line.is_empty(), "{line}");
        // The three states that are not a list are not silent about it.
        assert!(status(&State::Reading).contains("reading"));
        assert!(status(&State::Unauthorized).contains("no authorization"));
        assert!(status(&State::Failed("rate_limit".to_owned())).contains("could not be read"));
    }
}
