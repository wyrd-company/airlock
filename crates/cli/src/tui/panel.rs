//! The pieces more than one screen draws: labelled fields, the credential
//! region, and the rule that decides how much prose a width can carry.
//!
//! The credential region is here rather than on one screen because two screens
//! show it and they must show the same thing. What it holds is the identity —
//! a compile-time constant — and never the credential: the grant is printed by
//! permission list and by source, and there is no value in scope to print.

use ratatui::text::{Line, Span};

use airlock_core::findings::Report;

use crate::admin::identity::WriteIdentity;
use crate::admin::sign_in::Density;
use crate::admin::text::sanitize;

use super::chrome::wrap;
use super::theme::{Role, Styles};

/// The column a labelled field's value starts in.
pub const LABEL_WIDTH: usize = 14;

/// The most a provenance value may be.
///
/// Generous, because a digest is 71 columns and a commit is 40, and the point
/// of the block is that both are readable in full.
const PROVENANCE_LIMIT: usize = 200;

/// How much of a digest the status lines quote.
///
/// Enough to tell two registries apart at a glance, and never enough to be
/// mistaken for the digest itself — which is why the abbreviation is marked.
const DIGEST_PREFIX: usize = 8;

/// The width below which prose is written tightly.
///
/// The reference layout carries the full sentences and the floor does not. The
/// threshold is where the fuller readings stop fitting on one line each, and a
/// screen that wrapped them instead would spend rows it needs for its list.
pub const FULL_PROSE_NEEDS_WIDTH: usize = 100;

/// How much room there is for words.
#[must_use]
pub const fn density(width: usize) -> Density {
    if width < FULL_PROSE_NEEDS_WIDTH {
        Density::Tight
    } else {
        Density::Full
    }
}

/// A region heading, drawn the one way every region draws one.
#[must_use]
pub fn heading(styles: Styles, text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, styles.bold(Role::Text)))
}

/// The run's provenance: what produced this reading, and what it was of.
///
/// Two screens print it and neither may print a different account of the same
/// run, so it is built once, from the run, at the boundary that builds
/// everything else the interface draws — which is where a string the run did
/// not write itself is made safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The version of airlock that produced the run.
    pub airlock_version: String,
    /// The registry version the run attests to.
    pub registry_version: String,
    /// The digest over the compiled registry.
    pub registry_digest: String,
    /// The version of the findings schema the run emitted.
    pub schema_version: u32,
    /// The commit the audit was of.
    pub audited_commit: String,
    /// When the settings were observed, where the observation established it.
    pub settings_observed_at: Option<String>,
}

impl Provenance {
    /// Take the provenance off a run.
    #[must_use]
    pub fn of(report: &Report) -> Self {
        Self {
            airlock_version: sanitize(&report.airlock.version, PROVENANCE_LIMIT),
            registry_version: sanitize(&report.airlock.registry_version, PROVENANCE_LIMIT),
            registry_digest: sanitize(&report.airlock.registry_digest, PROVENANCE_LIMIT),
            schema_version: report.schema_version,
            audited_commit: sanitize(&report.repository.audited_commit, PROVENANCE_LIMIT),
            settings_observed_at: report
                .repository
                .settings_observed_at
                .as_ref()
                .map(|at| sanitize(at, PROVENANCE_LIMIT)),
        }
    }

    /// The block, in the order both screens print it.
    ///
    /// The observation time is stated as unestablished rather than left blank
    /// where the run did not carry one: a missing time and a time of nothing
    /// are two different facts, and only one of them is true.
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("airlock", self.airlock_version.clone()),
            ("registry", self.registry_version.clone()),
            ("digest", self.registry_digest.clone()),
            ("schema", self.schema_version.to_string()),
            ("commit", self.audited_commit.clone()),
            (
                "observed",
                self.settings_observed_at.clone().unwrap_or_else(|| {
                    "not established \u{2014} this observation did not record when the \
                     settings were read"
                        .to_owned()
                }),
            ),
        ]
    }

    /// The block as lines, under its heading.
    #[must_use]
    pub fn lines(&self, styles: Styles, width: usize) -> Vec<Line<'static>> {
        let mut lines = vec![heading(styles, "RUN PROVENANCE")];
        for (label, value) in self.fields() {
            lines.extend(field(styles, label, &value, width));
        }
        lines
    }

    /// The digest as a status line quotes it: enough to tell two apart, marked
    /// so it is never read as the digest itself.
    #[must_use]
    pub fn abbreviated_digest(&self) -> String {
        let (algorithm, value) = self
            .registry_digest
            .split_once(':')
            .unwrap_or(("", self.registry_digest.as_str()));
        if value.chars().count() <= DIGEST_PREFIX {
            return self.registry_digest.clone();
        }
        let head: String = value.chars().take(DIGEST_PREFIX).collect();
        if algorithm.is_empty() {
            format!("{head}\u{2026}")
        } else {
            format!("{algorithm}:{head}\u{2026}")
        }
    }
}

/// A labelled field, wrapped under its value rather than under its label.
#[must_use]
pub fn field(styles: Styles, label: &str, text: &str, width: usize) -> Vec<Line<'static>> {
    let room = width.saturating_sub(LABEL_WIDTH).max(1);
    wrap(text, room)
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            let label = if index == 0 { label } else { "" };
            Line::from(vec![
                Span::styled(format!("{label:<LABEL_WIDTH$}"), styles.of(Role::Faint)),
                Span::styled(part, styles.of(Role::Dim)),
            ])
        })
        .collect()
}

/// The credential region: what the grant is and where it came from.
///
/// Never a value. The source names the app and the flow, the grant names every
/// permission the app registration declares, and the storage line states that
/// there is nothing to display and nowhere it is kept.
#[must_use]
pub fn credential(
    styles: Styles,
    identity: WriteIdentity,
    width: usize,
    density: Density,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "CREDENTIAL",
        styles.bold(Role::Text),
    ))];
    lines.extend(field(styles, "source", &identity.source(), width));
    lines.extend(field(styles, "grant", &grant(identity, density), width));
    lines.extend(field(
        styles,
        "storage",
        match density {
            Density::Full => {
                "none. No credential of any kind is stored: not in a file, not in \
                 the environment, not in a child process, and not after this \
                 session ends. Its value is never displayed."
            }
            Density::Tight => {
                "none. No credential of any kind is stored, anywhere, ever. Its \
                 value is never displayed."
            }
        },
        width,
    ));
    lines
}

/// The grant, by permission and level.
///
/// Every permission is named at both densities, because the grant is the
/// screen's answer to what this credential can do and a summary of it is not
/// that answer. What the tight reading drops is the repetition: the permissions
/// are gathered under their level instead of each carrying it.
#[must_use]
pub fn grant(identity: WriteIdentity, density: Density) -> String {
    if density == Density::Full {
        return identity
            .grant
            .iter()
            .map(|permission| format!("{} {}", permission.name, permission.level))
            .collect::<Vec<_>>()
            .join(" \u{b7} ");
    }
    let mut levels: Vec<(&str, Vec<&str>)> = Vec::new();
    for permission in identity.grant {
        match levels
            .iter_mut()
            .find(|(level, _)| *level == permission.level)
        {
            Some((_, names)) => names.push(permission.name),
            None => levels.push((permission.level, vec![permission.name])),
        }
    }
    levels
        .into_iter()
        .map(|(level, names)| format!("{level}: {}", names.join(", ")))
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

/// The slice of a list to draw, and whether anything sits outside it.
///
/// A list longer than the rows it has is windowed rather than cut at the top:
/// the selected row is always in view, and the caller says how many rows are
/// outside the window so a short list is never read as the whole one.
#[must_use]
pub fn window(selected: usize, len: usize, room: usize) -> (usize, usize) {
    if room == 0 || len == 0 {
        return (0, 0);
    }
    if len <= room {
        return (0, len);
    }
    let half = room / 2;
    let start = selected.saturating_sub(half).min(len - room);
    (start, start + room)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::identity;
    use crate::tui::theme::{ColorMode, Theme};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn the_credential_region_names_every_permission_and_no_value() {
        for density in [Density::Full, Density::Tight] {
            let rendered = text(&credential(styles(), identity::bound(), 120, density));
            for permission in identity::bound().grant {
                assert!(rendered.contains(permission.name), "{}", permission.name);
            }
            assert!(rendered.contains("device flow"), "{rendered}");
            assert!(
                !rendered.contains(identity::bound().client_id),
                "{rendered}"
            );
            assert!(rendered.contains("never displayed"), "{rendered}");
        }
    }

    #[test]
    fn a_window_always_contains_the_selected_row() {
        for selected in 0..20 {
            let (start, end) = window(selected, 20, 5);
            assert!(start <= selected && selected < end, "{selected}");
            assert_eq!(end - start, 5);
        }
    }

    #[test]
    fn the_provenance_block_states_every_fact_the_run_carries() {
        let report = crate::tui::findings::fixture::mixed();
        let provenance = Provenance::of(&report);
        let rendered = text(&provenance.lines(styles(), 120));
        assert!(rendered.contains(&provenance.airlock_version));
        assert!(rendered.contains(&provenance.registry_digest));
        assert!(rendered.contains(&provenance.audited_commit));
        assert!(rendered.contains(&provenance.schema_version.to_string()));
    }

    #[test]
    fn an_unestablished_observation_time_is_stated_rather_than_left_blank() {
        let mut report = crate::tui::findings::fixture::mixed();
        report.repository.settings_observed_at = None;
        let rendered = text(&Provenance::of(&report).lines(styles(), 120));
        assert!(rendered.contains("not established"), "{rendered}");
    }

    #[test]
    fn an_abbreviated_digest_is_marked_as_one_and_keeps_its_algorithm() {
        let mut report = crate::tui::findings::fixture::mixed();
        report.airlock.registry_digest = format!("sha256:{}", "a".repeat(64));
        let provenance = Provenance::of(&report);
        assert_eq!(provenance.abbreviated_digest(), "sha256:aaaaaaaa\u{2026}");
        // Short enough to be whole is printed whole: a mark that said
        // something was dropped when nothing was would be a lie.
        report.airlock.registry_digest = "sha256:abcd".to_owned();
        assert_eq!(Provenance::of(&report).abbreviated_digest(), "sha256:abcd");
    }

    #[test]
    fn a_list_that_fits_is_never_windowed() {
        assert_eq!(window(0, 3, 10), (0, 3));
        assert_eq!(window(0, 0, 10), (0, 0));
        assert_eq!(window(0, 5, 0), (0, 0));
    }
}
