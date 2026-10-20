//! The status-lane primitive, implemented once and reused everywhere.
//!
//! An evaluated finding carries Met or Gap. The outcome sits in one
//! of three lanes. The lane is a physical column position on every row that
//! shows a status: position carries the meaning, and hue only confirms it.
//!
//! The three lanes read as three shape families — the gating lane uses stroke
//! marks, the inert lane closed outlines, and the undecided lane enclosed
//! forms. The undecided lane is ruled off on both sides on every row that shows
//! it, so nothing standing in it can be mistaken for a pass in any theme or
//! with colour removed.
//!
//! Severity is a three-cell bar plus its name, for the same reason: it reads at
//! a glance and it survives monochrome.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use airlock_core::findings::Status;
use airlock_core::registry::Severity;

use super::theme::{Role, Styles};

/// The width of one lane cell, glyph centred.
const CELL: usize = 3;

/// The rule drawn down both sides of the undecided lane.
const RAIL: &str = "\u{2502}";

/// The rail a row carries when it actually gates the run.
pub const GATING_RAIL: &str = "\u{258C}";

/// The total printed width of the three-lane strip, rails included. Counted in
/// columns, not bytes: every glyph here is one cell wide.
pub const LANES_WIDTH: usize = CELL * 3 + 2;

/// One of the three columns a status can stand in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Counts toward the verdict.
    Gating,
    /// Never gates, never affects completeness.
    Inert,
    /// Makes the run incomplete at a gating severity, unless the fact requires
    /// admin access to verify.
    Undecided,
}

impl Lane {
    /// Every lane, left to right, in the order they are printed.
    pub const ALL: [Lane; 3] = [Lane::Gating, Lane::Inert, Lane::Undecided];

    /// The heading the status summary groups its counts under.
    #[must_use]
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Gating => "DECIDED \u{b7} GATING",
            Self::Inert => "DECIDED \u{b7} INERT",
            Self::Undecided => "UNDECIDED",
        }
    }

    /// The qualifier the heading carries, which says what standing in this lane
    /// does to the run.
    #[must_use]
    pub const fn qualifier(self) -> &'static str {
        match self {
            Self::Gating => "counts toward the verdict",
            Self::Inert => "never gates",
            Self::Undecided => {
                "no outcome: read the waived, routed, unbuilt, out-of-scope, or run-error label"
            }
        }
    }
}

/// The lane a status stands in.
#[must_use]
pub const fn lane_of(status: Option<Status>) -> Lane {
    match status {
        Some(_) => Lane::Gating,
        None => Lane::Undecided,
    }
}
#[must_use]
pub const fn glyph_of(status: Option<Status>) -> &'static str {
    match status {
        Some(Status::Met) => "✓",
        Some(Status::Gap) => "✗",
        None => "?",
    }
}
#[must_use]
pub const fn gloss_of(status: Option<Status>) -> &'static str {
    match status {
        Some(Status::Met) => "the compiled requirement is met",
        Some(Status::Gap) => "the compiled requirement is not met",
        None => "not evaluated: read the result label and reason",
    }
}

/// The three lanes as spans, coloured only where colour is being emitted.
///
/// The rails are drawn whatever the status, so the undecided lane is a physical
/// fence rather than a decoration that appears only when something stands in
/// it.
#[must_use]
pub fn lanes_spans(status: Option<Status>, styles: Styles) -> Vec<Span<'static>> {
    let mut spans = Vec::with_capacity(7);
    let rail = Span::styled(RAIL, styles.of(Role::Border));
    for lane in Lane::ALL {
        if lane == Lane::Undecided {
            spans.push(rail.clone());
        }
        match status.filter(|s| lane_of(Some(*s)) == lane) {
            Some(status) => spans.push(Span::styled(
                format!(" {} ", glyph_of(Some(status))),
                styles.of(Role::Status(Some(status))),
            )),
            None => spans.push(Span::raw(" ".repeat(CELL))),
        }
        if lane == Lane::Undecided {
            spans.push(rail.clone());
        }
    }
    spans
}

/// The three-cell severity bar.
#[must_use]
pub const fn severity_bar(severity: Severity) -> &'static str {
    match severity {
        Severity::Blocking => "\u{2588}\u{2588}\u{2588}",
        Severity::Advisory => "\u{2588}\u{2588}\u{2591}",
        Severity::None => "\u{2591}\u{2591}\u{2591}",
    }
}

/// The severity bar followed by the severity's own name, which is how severity
/// is always printed: the bar reads at a glance, the name is unambiguous.
#[must_use]
pub fn severity_spans(severity: Severity, styles: Styles) -> Vec<Span<'static>> {
    vec![
        Span::styled(severity_bar(severity), styles.of(Role::Text)),
        Span::raw(" "),
        Span::styled(severity.code(), styles.of(Role::Dim)),
    ]
}

/// The column the gloss starts in on a legend row.
const NAME_WIDTH: usize = 14;

/// One legend row: the lanes, the status name, and its gloss, on one line.
///
/// The findings screen prints the whole vocabulary this way, and the shell
/// prints it as the reference reading of the primitive. The gloss is elided to
/// the room left rather than wrapped, because a legend whose rows wrap stops
/// aligning, and the alignment is the point.
#[must_use]
pub fn legend_row(status: Status, styles: Styles, width: usize) -> Line<'static> {
    let mut spans = lanes_spans(Some(status), styles);
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("{:<NAME_WIDTH$}", status.code()),
        styles
            .of(Role::Status(Some(status)))
            .add_modifier(Modifier::BOLD),
    ));
    let room = width.saturating_sub(LANES_WIDTH + 2 + NAME_WIDTH);
    spans.push(Span::styled(
        super::chrome::fit(gloss_of(Some(status)), room),
        styles.of(Role::Dim),
    ));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::{ColorMode, Theme};

    /// The lane strip as the reading a monochrome terminal gets: glyph and
    /// position, nothing else.
    fn lanes_text(status: Option<Status>) -> String {
        lanes_spans(status, Styles::new(Theme::Dark, ColorMode::NoColor))
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn every_status_has_exactly_one_lane_and_one_glyph() {
        let mut glyphs = Vec::new();
        for status in Status::ALL {
            let glyph = glyph_of(Some(*status));
            assert!(!glyphs.contains(&glyph), "{status:?} repeats a glyph");
            glyphs.push(glyph);
        }
        assert_eq!(glyphs.len(), 2, "the vocabulary is Met and Gap");
    }

    #[test]
    fn the_lane_matches_what_the_status_does_to_the_run() {
        for status in Status::ALL {
            let expected = Lane::Gating;
            assert_eq!(lane_of(Some(*status)), expected, "{status:?}");
        }
    }

    #[test]
    fn the_glyph_stands_in_its_own_lane_and_nowhere_else() {
        for status in Status::ALL {
            let text = lanes_text(Some(*status));
            let glyph = glyph_of(Some(*status));
            assert_eq!(text.matches(glyph).count(), 1, "{status:?}");
            let column = text
                .char_indices()
                .position(|(index, _)| text[index..].starts_with(glyph))
                .expect("the glyph is drawn");
            let lane = lane_of(Some(*status));
            // Gating and inert lanes precede the opening rail; the undecided
            // lane follows it.
            let index = Lane::ALL.iter().position(|l| *l == lane).expect("a lane");
            let expected = index * CELL + 1 + usize::from(lane == Lane::Undecided);
            assert_eq!(column, expected, "{status:?} stands in {lane:?}");
        }
    }

    #[test]
    fn the_undecided_lane_is_fenced_on_every_row_including_empty_ones() {
        let empty = lanes_text(None);
        assert_eq!(empty.matches(RAIL).count(), 2);
        for status in Status::ALL {
            assert_eq!(
                lanes_text(Some(*status)).matches(RAIL).count(),
                2,
                "{status:?}"
            );
        }
    }

    #[test]
    fn the_strip_is_one_width_whatever_stands_in_it() {
        assert_eq!(lanes_text(None).chars().count(), LANES_WIDTH);
        for status in Status::ALL {
            assert_eq!(
                lanes_text(Some(*status)).chars().count(),
                LANES_WIDTH,
                "{status:?}"
            );
        }
    }

    #[test]
    fn the_coloured_reading_prints_the_same_text_the_monochrome_one_does() {
        let styles = Styles::new(Theme::Dark, ColorMode::Color);
        for status in Status::ALL {
            let joined: String = lanes_spans(Some(*status), styles)
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            assert_eq!(joined, lanes_text(Some(*status)), "{status:?}");
        }
    }

    #[test]
    fn severity_bars_differ_in_length_of_fill() {
        assert_eq!(
            severity_bar(Severity::Blocking).matches('\u{2588}').count(),
            3
        );
        assert_eq!(
            severity_bar(Severity::Advisory).matches('\u{2588}').count(),
            2
        );
        assert_eq!(severity_bar(Severity::None).matches('\u{2588}').count(), 0);
        for severity in Severity::ALL {
            assert_eq!(severity_bar(*severity).chars().count(), 3, "{severity:?}");
        }
    }

    #[test]
    fn every_status_has_a_gloss() {
        for status in Status::ALL {
            assert!(!gloss_of(Some(*status)).is_empty(), "{status:?}");
        }
    }

    #[test]
    fn a_legend_row_is_one_line_that_fits_at_both_sizes() {
        let styles = Styles::new(Theme::Dark, ColorMode::Color);
        for width in [120usize, 80] {
            for status in Status::ALL {
                let row = legend_row(*status, styles, width);
                let text: String = row.spans.iter().map(|s| s.content.as_ref()).collect();
                assert!(
                    text.chars().count() <= width,
                    "{status:?} at {width}: {text}"
                );
                assert!(text.contains(status.code()), "{status:?} at {width}");
            }
        }
    }
}
