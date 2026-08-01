//! The organizations screen: choose which installation to work in.
//!
//! The list is an intersection — where airlock is installed, crossed with what
//! this account can reach — and the screen says so, because the difference
//! between "not there" and "not visible from here" is the whole reason this
//! screen has prose on it at all.
//!
//! The three causes of an absent organization are printed whether or not the
//! list is empty. They have three different remedies, airlock cannot tell them
//! apart from here, and each one hides the evidence of itself, so a screen that
//! guessed between them would be guessing on the operator's behalf.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::admin::catalogue::{Installation, State};
use crate::admin::identity;
use crate::admin::sign_in::Density;

use super::chrome::{fit, wrap};
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
    let width = width as usize;
    let density = panel::density(width);

    // Everything below the list is built first, because the list is what gives
    // up rows when there are not enough. The three causes and the credential do
    // not: they are the two things this screen exists to state.
    // At the floor the sections sit against each other rather than taking a
    // blank row each: a row here is a row the installation list needs, and the
    // headings already separate them.
    let spacer = |lines: &mut Vec<Line<'static>>| {
        if density == Density::Full {
            lines.push(Line::default());
        }
    };
    let mut tail = Vec::new();
    spacer(&mut tail);
    tail.extend(intersection(styles, width, density));
    spacer(&mut tail);
    tail.extend(causes(styles, width, density));
    spacer(&mut tail);
    tail.extend(panel::credential(styles, identity::bound(), width, density));

    let room = (height as usize).saturating_sub(tail.len()).max(2);
    let mut lines = list(styles, width, room, state, selected);
    lines.extend(tail);
    lines
}

/// The status line: what the count is, and what the list is a list of.
#[must_use]
pub fn status(state: &State) -> String {
    let reach = "the list is the intersection of install and access";
    match state {
        State::Unauthorized => format!("no authorization yet \u{b7} {reach}"),
        State::Reading => format!("reading the installations \u{b7} {reach}"),
        State::Failed(_) => format!("the installations could not be read \u{b7} {reach}"),
        State::Ready(catalogue) => {
            let count = catalogue.installations().len();
            let noun = if count == 1 {
                "installation"
            } else {
                "installations"
            };
            format!("{count} {noun} \u{b7} {reach}")
        }
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
        Span::styled("REACHABLE INSTALLATIONS", styles.bold(Role::Text)),
        Span::styled(
            match state {
                State::Ready(_) => format!("  {}", installations.len()),
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
                    "the read failed, so this is not an empty list: {cause}. Nothing \
                     below distinguishes a failed read from an absent install, which is \
                     why the failure is named here."
                ),
            )
        }
        State::Ready(_) if installations.is_empty() => {
            return note(
                lines,
                styles,
                width,
                "none. An empty list is not evidence that nothing is there: the three \
                 causes below are the whole of what it can mean, and they have three \
                 different remedies.",
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

fn intersection(styles: Styles, width: usize, density: Density) -> Vec<Line<'static>> {
    let text = match density {
        Density::Full => {
            "This list is the intersection of where airlock is installed and what this \
             account can reach. An organization that is absent from it is not evidence \
             of absence: airlock cannot see what it is not installed on, and it cannot \
             see what this account cannot reach."
        }
        Density::Tight => {
            "The list is where airlock is installed crossed with what this account \
             reaches. An absent organization is not evidence of absence."
        }
    };
    wrap(text, width)
        .into_iter()
        .map(|line| Line::from(Span::styled(line, styles.of(Role::Text))))
        .collect()
}

/// The three causes, and the three remedies they take.
///
/// Printed whether or not the list is empty. Each cause hides the evidence of
/// itself, so from here they are indistinguishable — and a screen that showed
/// only the likeliest would send the operator to the wrong owner.
fn causes(styles: Styles, width: usize, density: Density) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "AN ABSENT ORGANIZATION HAS THREE CAUSES, AND THREE DIFFERENT REMEDIES",
        styles.bold(Role::Text),
    ))];
    let entries: [&str; 3] = match density {
        Density::Full => [
            "The app is not installed on that organization. Install airlock on it; an \
             owner or an admin can do this.",
            "It is installed, but this account is not a member, or its role does not \
             reach it. Ask an owner to add the account, or to grant the role.",
            "Both are fine, but the installation was scoped to repositories this \
             account cannot see. Widen the installation's repository selection.",
        ],
        Density::Tight => [
            "not installed there \u{2014} install airlock; an owner or admin can.",
            "installed, but this account is not a member or lacks the role \u{2014} ask \
             an owner.",
            "installed and reachable, but scoped away from those repositories \u{2014} \
             widen the selection.",
        ],
    };
    for (index, entry) in entries.iter().enumerate() {
        let room = width.saturating_sub(3).max(1);
        for (part, text) in wrap(entry, room).into_iter().enumerate() {
            let label = if part == 0 {
                format!("{}  ", index + 1)
            } else {
                "   ".to_owned()
            };
            lines.push(Line::from(vec![
                Span::styled(label, styles.of(Role::Accent)),
                Span::styled(text, styles.of(Role::Dim)),
            ]));
        }
    }
    lines
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
                        default_branch: Some("main".to_owned()),
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
    fn an_empty_list_never_stands_alone() {
        for width in [120, 80] {
            let text = rendered(&ready(Vec::new()), width, 40, 0);
            assert!(text.contains("An empty list is not evidence"), "{text}");
            assert!(text.contains("THREE CAUSES"), "{text}");
            assert!(text.contains("Install airlock") || text.contains("install airlock"));
            assert!(text.contains("role"), "{text}");
            assert!(
                text.contains("selection"),
                "the third remedy is missing: {text}"
            );
        }
    }

    #[test]
    fn the_three_causes_are_printed_whether_or_not_the_list_is_empty() {
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
        assert!(populated.contains("THREE CAUSES"), "{populated}");
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
    fn the_credential_is_shown_by_source_and_grant_and_never_by_value() {
        let text = rendered(&ready(Vec::new()), 120, 40, 0);
        assert!(text.contains("CREDENTIAL"), "{text}");
        assert!(text.contains("device flow"), "{text}");
        for permission in identity::bound().grant {
            assert!(text.contains(permission.name), "{}", permission.name);
        }
        assert!(!text.contains(identity::bound().client_id), "{text}");
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
    fn the_status_line_states_the_count_and_the_intersection() {
        let line = status(&ready(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &[],
        )]));
        assert!(line.contains("1 installation"), "{line}");
        assert!(
            line.contains("intersection of install and access"),
            "{line}"
        );
    }
}
