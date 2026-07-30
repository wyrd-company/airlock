//! The repositories screen: choose a repository to observe.
//!
//! The table shows a prior verdict, and the prior verdict is orientation and
//! nothing else. Opening a repository re-observes it in full — the request the
//! screen produces is built from the row's coordinates alone, so there is no
//! path by which a remembered verdict could shorten, skip, or steer what
//! follows.
//!
//! What airlock can remember is only what this session observed. There is no
//! store, no cache, and nothing on disk, so a session that has just started has
//! never observed anything and every row says exactly that rather than showing
//! a blank where a verdict would be.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::admin::catalogue::{Catalogue, Installation, Listing, Row};
use crate::admin::sign_in::Density;

use super::chrome::{fit, wrap};
use super::panel;
use super::theme::{Role, Styles};

/// The mark on the selected row.
const SELECTED: &str = "\u{25b8} ";

/// The mark on every other row.
const UNSELECTED: &str = "  ";

/// The visibility column.
const VISIBILITY_WIDTH: usize = 12;

/// The default-branch column.
const BRANCH_WIDTH: usize = 16;

/// The last-audit column. Wide enough for an ISO date and the gap after it.
const AUDIT_WIDTH: usize = 12;

/// The prior-verdict column.
const VERDICT_WIDTH: usize = 14;

/// The blank columns between two columns.
const GAP: usize = 2;

/// Everything the table costs a row that is not the name.
///
/// Every column but the name is fixed, and each carries its own trailing gap,
/// so the name takes whatever the width leaves and is elided into it.
const FIXED: usize =
    UNSELECTED.len() + VISIBILITY_WIDTH + BRANCH_WIDTH + AUDIT_WIDTH + VERDICT_WIDTH;

/// The incremental filter over the repository name.
///
/// The text is state and the entry is a mode. `/` opens the entry, `esc` closes
/// it and clears the filter, and while it is open a printable key types into it
/// rather than acting as a screen key. The screen names that state and says how
/// to leave it, because a key that silently does something else is worse than a
/// key that is documented as doing it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    text: String,
    open: bool,
}

impl Filter {
    /// Begin typing.
    pub fn open(&mut self) {
        self.open = true;
    }

    /// Stop typing, and clear what was typed.
    ///
    /// Clearing rather than keeping: the whole list is what the screen returns
    /// to, and a filter still in force with no visible entry is a list that
    /// looks short for no stated reason.
    pub fn close(&mut self) {
        self.open = false;
        self.text.clear();
    }

    /// Whether the entry is taking keys.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.open
    }

    /// Add a character.
    pub fn push(&mut self, character: char) {
        self.text.push(character);
    }

    /// Remove the last character.
    pub fn backspace(&mut self) {
        self.text.pop();
    }

    /// What has been typed.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether a repository name is in the filtered set.
    ///
    /// Case-insensitive and by substring: the filter is for finding a
    /// repository whose name is half-remembered, not for writing a pattern.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.text.is_empty() || name.to_lowercase().contains(&self.text.to_lowercase())
    }
}

/// What the screen is drawing: an installation, its rows, and the selection.
///
/// One value rather than five parameters, because they are five facts about one
/// thing and a caller that could pass the rows of one installation with the
/// count of another would be a caller that could report the wrong number.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// The installation whose repositories these are.
    pub installation: Option<&'a Installation>,
    /// The catalogue the installation came from.
    ///
    /// Carried so that a repository the operator looked for and did not find
    /// can be told apart from one that is not there: only the catalogue knows
    /// whether the installation was scoped away from it.
    pub catalogue: Option<&'a Catalogue>,
    /// The rows to draw, already narrowed by the filter.
    pub rows: &'a [Row],
    /// How many the installation reaches in all.
    pub available: usize,
    /// The filter in force.
    pub filter: &'a Filter,
    /// Which row is selected.
    pub selected: usize,
}

/// The whole screen.
#[must_use]
pub fn body(styles: Styles, width: u16, height: u16, view: &View<'_>) -> Vec<Line<'static>> {
    let View {
        installation,
        catalogue,
        rows,
        available,
        filter,
        selected,
    } = *view;
    let width = width as usize;
    let density = panel::density(width);

    let mut head = vec![Line::from(vec![
        Span::styled("REPOSITORIES", styles.bold(Role::Text)),
        Span::styled(
            installation.map_or_else(String::new, |installation| {
                format!("  {}  {}", installation.account, installation.kind.label())
            }),
            styles.of(Role::Faint),
        ),
    ])];
    head.extend(filter_line(styles, width, filter, rows.len(), available));
    head.push(Line::default());

    let mut tail = vec![Line::default()];
    tail.extend(orientation(styles, width, density));

    let Some(installation) = installation else {
        head.extend(panel::field(
            styles,
            "",
            "no installation is selected. Choose one on the organizations screen; the \
             repositories shown here are the ones that installation reaches, and that \
             is not the same set as the ones the account has.",
            width,
        ));
        head.extend(tail);
        return head;
    };

    if let Listing::Refused(cause) = &installation.listing {
        head.extend(panel::field(
            styles,
            "",
            &format!(
                "the repository listing failed, so this is not an empty installation: \
                 {cause}. What is missing is the listing, not the repositories."
            ),
            width,
        ));
        head.extend(tail);
        return head;
    }

    if rows.is_empty() {
        head.extend(panel::field(
            styles,
            "",
            &empty(installation, catalogue, filter, available),
            width,
        ));
        head.extend(tail);
        return head;
    }

    let room = (height as usize)
        .saturating_sub(head.len() + tail.len() + 1)
        .max(1);
    let (start, end) = panel::window(selected, rows.len(), room);
    head.push(header(styles, width));
    for (index, row) in rows.iter().enumerate().take(end).skip(start) {
        head.push(line(styles, width, row, index == selected));
    }
    if end - start < rows.len() {
        head.push(Line::from(Span::styled(
            format!(
                "  showing {}\u{2013}{} of {}; \u{2191}\u{2193} moves through the rest",
                start + 1,
                end,
                rows.len()
            ),
            styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
    }
    head.extend(tail);
    head
}

/// The status line: what is shown against what is available, and the standing
/// statement that a prior verdict is orientation only.
#[must_use]
pub fn status(shown: usize, available: usize) -> String {
    format!("{shown} of {available} shown \u{b7} prior verdicts are shown for orientation only")
}

/// The rows of one installation, narrowed by the filter.
#[must_use]
pub fn visible(rows: &[Row], filter: &Filter) -> Vec<Row> {
    rows.iter()
        .filter(|row| filter.matches(&row.repository.name))
        .cloned()
        .collect()
}

fn empty(
    installation: &Installation,
    catalogue: Option<&Catalogue>,
    filter: &Filter,
    available: usize,
) -> String {
    if !filter.text().is_empty() {
        // What the filter hid, and — for a name typed in full — whether not
        // finding it here means scope or absence. The two are the same 404 from
        // the API, and this is the one place with the context to separate them.
        let absence = catalogue.map_or_else(String::new, |catalogue| {
            format!(
                " If you were looking for {}/{}: {}",
                installation.account,
                filter.text(),
                catalogue
                    .absence(&installation.account, filter.text())
                    .statement(&installation.account, filter.text())
            )
        });
        return format!(
            "no repository in {} has `{}` in its name. {available} are reachable here; \
             esc clears the filter and shows them.{absence}",
            installation.account,
            filter.text()
        );
    }
    format!(
        "this installation reaches no repository. That is what it covers rather than \
         what {} has: an installation scoped to a selection shows only the selection, \
         and widening the installation's repository selection is what changes it.",
        installation.account
    )
}

fn filter_line(
    styles: Styles,
    width: usize,
    filter: &Filter,
    shown: usize,
    available: usize,
) -> Vec<Line<'static>> {
    let value = if filter.is_open() {
        format!(
            "{}\u{2588}   typing filters as you go \u{b7} esc closes the filter and \
             clears it \u{b7} ctrl-c exits",
            filter.text()
        )
    } else if filter.text().is_empty() {
        format!("/ to filter by name \u{b7} showing all {available}")
    } else {
        format!(
            "{} \u{b7} {shown} of {available} \u{b7} / to edit, esc to clear",
            filter.text()
        )
    };
    panel::field(styles, "filter", &fit(&value, width), width)
}

fn header(styles: Styles, width: usize) -> Line<'static> {
    let name_width = name_width(width);
    Line::from(Span::styled(
        format!(
            "{:UNSELECTED_WIDTH$}{:<name_width$}{:<VISIBILITY_WIDTH$}{:<BRANCH_WIDTH$}\
             {:<AUDIT_WIDTH$}{}",
            "",
            "NAME",
            "VISIBILITY",
            "DEFAULT BRANCH",
            "LAST AUDIT",
            "PRIOR VERDICT",
            UNSELECTED_WIDTH = UNSELECTED.len(),
        ),
        styles.bold(Role::Faint),
    ))
}

fn line(styles: Styles, width: usize, row: &Row, selected: bool) -> Line<'static> {
    let name_width = name_width(width);
    Line::from(vec![
        Span::styled(
            if selected { SELECTED } else { UNSELECTED },
            styles.bold(Role::Accent),
        ),
        Span::styled(
            format!(
                "{:<name_width$}",
                fit(&row.repository.name, name_width.saturating_sub(GAP))
            ),
            if selected {
                styles.bold(Role::Text)
            } else {
                styles.of(Role::Text)
            },
        ),
        Span::styled(
            format!(
                "{:<VISIBILITY_WIDTH$}",
                fit(&row.repository.visibility, VISIBILITY_WIDTH - GAP)
            ),
            styles.of(Role::Dim),
        ),
        Span::styled(
            format!(
                "{:<BRANCH_WIDTH$}",
                fit(row.repository.branch(), BRANCH_WIDTH - GAP)
            ),
            styles.of(Role::Dim),
        ),
        Span::styled(
            format!("{:<AUDIT_WIDTH$}", fit(row.prior.date(), AUDIT_WIDTH - GAP)),
            styles.of(Role::Faint),
        ),
        Span::styled(
            fit(row.prior.verdict(), VERDICT_WIDTH),
            styles.of(Role::Faint),
        ),
    ])
}

fn name_width(width: usize) -> usize {
    width.saturating_sub(FIXED).max(12)
}

/// The standing statement about what a prior verdict is for.
fn orientation(styles: Styles, width: usize, density: Density) -> Vec<Line<'static>> {
    let text = match density {
        Density::Full => {
            "A prior verdict is shown for orientation only, and it is one this session \
             made: airlock keeps no audit history, so a repository it has not observed \
             in this session says so rather than showing a blank. Nothing is acted upon \
             from memory \u{2014} opening a repository re-observes it in full."
        }
        Density::Tight => {
            "Prior verdicts are orientation only, and only from this session. Opening a \
             repository re-observes it in full; nothing is acted on from memory."
        }
    };
    wrap(text, width)
        .into_iter()
        .map(|line| Line::from(Span::styled(line, styles.of(Role::Text))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::catalogue::{Observations, Observe, PriorAudit, Repository};
    use crate::tui::theme::{ColorMode, Theme};
    use airlock_core::github::{AccountKind, RepositorySelection};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn installation(names: &[&str]) -> Installation {
        Installation {
            id: 7,
            account: "acme-industries".to_owned(),
            kind: AccountKind::Organization,
            selection: RepositorySelection::All,
            listing: Listing::Read {
                repositories: names
                    .iter()
                    .map(|name| Repository {
                        owner: "acme-industries".to_owned(),
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

    fn rendered(
        installation: Option<&Installation>,
        rows: &[Row],
        available: usize,
        filter: &Filter,
        width: u16,
    ) -> String {
        let catalogue = installation.map(|installation| Catalogue::of(vec![installation.clone()]));
        body(
            styles(),
            width,
            40,
            &View {
                installation,
                catalogue: catalogue.as_ref(),
                rows,
                available,
                filter,
                selected: 0,
            },
        )
        .iter()
        .flat_map(|line| line.spans.iter())
        .map(|span| span.content.as_ref())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
    }

    #[test]
    fn a_repository_never_audited_says_so_rather_than_showing_a_blank() {
        let installation = installation(&["widget"]);
        let rows = Row::of(&installation, &Observations::default());
        let text = rendered(Some(&installation), &rows, 1, &Filter::default(), 120);
        assert!(text.contains("never observed"), "{text}");
        assert!(text.contains("NAME"), "{text}");
        assert!(text.contains("VISIBILITY"), "{text}");
        assert!(text.contains("DEFAULT BRANCH"), "{text}");
        assert!(text.contains("LAST AUDIT"), "{text}");
        assert!(text.contains("PRIOR VERDICT"), "{text}");
        assert!(text.contains("private"), "{text}");
        assert!(text.contains("main"), "{text}");
    }

    #[test]
    fn the_prior_verdict_is_labelled_as_orientation_at_both_sizes() {
        let installation = installation(&["widget"]);
        let rows = Row::of(&installation, &Observations::default());
        for width in [120, 80] {
            let text = rendered(Some(&installation), &rows, 1, &Filter::default(), width);
            assert!(text.contains("orientation only"), "{text}");
            assert!(text.contains("re-observes it in full"), "{text}");
        }
    }

    #[test]
    fn an_observation_from_this_session_is_shown_with_its_date() {
        let installation = installation(&["widget"]);
        let mut observations = Observations::default();
        observations.record(
            &Observe {
                owner: "acme-industries".to_owned(),
                name: "widget".to_owned(),
            },
            "2026-01-02",
            "nonconformant",
        );
        let rows = Row::of(&installation, &observations);
        assert_eq!(
            rows[0].prior,
            PriorAudit::Observed {
                at: "2026-01-02".to_owned(),
                verdict: "nonconformant".to_owned()
            }
        );
        let text = rendered(Some(&installation), &rows, 1, &Filter::default(), 120);
        assert!(text.contains("2026-01-02"), "{text}");
        assert!(text.contains("nonconformant"), "{text}");
    }

    #[test]
    fn the_filter_narrows_by_substring_and_ignores_case() {
        let installation = installation(&["widget", "sprocket", "Widget-Two"]);
        let all = Row::of(&installation, &Observations::default());
        let mut filter = Filter::default();
        filter.open();
        for character in "WIDG".chars() {
            filter.push(character);
        }
        let shown = visible(&all, &filter);
        assert_eq!(shown.len(), 2);
        let text = rendered(Some(&installation), &shown, all.len(), &filter, 120);
        assert!(text.contains("widget"), "{text}");
        assert!(!text.contains("sprocket"), "{text}");
    }

    #[test]
    fn a_filter_that_matches_nothing_says_what_it_hid_and_how_to_undo_it() {
        let installation = installation(&["widget"]);
        let all = Row::of(&installation, &Observations::default());
        let mut filter = Filter::default();
        filter.push('z');
        let shown = visible(&all, &filter);
        assert!(shown.is_empty());
        let text = rendered(Some(&installation), &shown, all.len(), &filter, 120);
        assert!(text.contains("no repository"), "{text}");
        assert!(text.contains("esc clears the filter"), "{text}");
    }

    #[test]
    fn an_installation_that_reaches_nothing_says_what_that_means() {
        let installation = installation(&[]);
        let text = rendered(Some(&installation), &[], 0, &Filter::default(), 120);
        assert!(text.contains("reaches no repository"), "{text}");
        assert!(text.contains("repository selection"), "{text}");
    }

    #[test]
    fn a_refused_listing_is_never_drawn_as_an_empty_installation() {
        let refused = Installation {
            listing: Listing::Refused("rate_limit on GET /user/installations".to_owned()),
            ..installation(&[])
        };
        let text = rendered(Some(&refused), &[], 0, &Filter::default(), 120);
        assert!(text.contains("listing failed"), "{text}");
        assert!(text.contains("rate_limit"), "{text}");
    }

    #[test]
    fn no_installation_selected_says_which_set_this_screen_is_about() {
        let text = rendered(None, &[], 0, &Filter::default(), 120);
        assert!(text.contains("no installation is selected"), "{text}");
    }

    #[test]
    fn an_open_filter_says_that_a_key_types_and_how_to_leave() {
        let installation = installation(&["widget"]);
        let rows = Row::of(&installation, &Observations::default());
        let mut filter = Filter::default();
        filter.open();
        let text = rendered(Some(&installation), &rows, 1, &filter, 120);
        assert!(text.contains("typing filters as you go"), "{text}");
        assert!(text.contains("esc closes the filter"), "{text}");
        assert!(text.contains("ctrl-c exits"), "{text}");
    }

    #[test]
    fn closing_the_filter_clears_it() {
        let mut filter = Filter::default();
        filter.open();
        filter.push('w');
        filter.push('x');
        filter.backspace();
        assert_eq!(filter.text(), "w");
        filter.close();
        assert!(!filter.is_open());
        assert_eq!(filter.text(), "");
        assert!(filter.matches("anything"));
    }

    #[test]
    fn the_status_line_states_what_is_shown_against_what_is_available() {
        let line = status(2, 12);
        assert!(line.contains("2 of 12 shown"), "{line}");
        assert!(line.contains("orientation only"), "{line}");
    }

    #[test]
    fn no_row_overflows_the_floor() {
        let installation = installation(&["a-repository-with-a-very-long-name-indeed"]);
        let rows = Row::of(&installation, &Observations::default());
        for line in body(
            styles(),
            80,
            24,
            &View {
                installation: Some(&installation),
                catalogue: None,
                rows: &rows,
                available: 1,
                filter: &Filter::default(),
                selected: 0,
            },
        ) {
            let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            assert!(rendered.chars().count() <= 80, "{rendered:?}");
        }
    }
}
