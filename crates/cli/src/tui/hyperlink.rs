//! Making the address on screen clickable, without opening anything.
//!
//! The binary starts no child process, here or anywhere: it does not run
//! `xdg-open`, `open`, or `start`, and it does not link a crate that would. What
//! it does instead is the same trick the clipboard offer uses — it writes a
//! request to the terminal and lets the terminal decide. `OSC 52` asks the
//! terminal to hold a value; `OSC 8` tells it that a run of cells it is about to
//! draw stands for an address. Following that address is then the operator
//! clicking it and their terminal opening their browser, which is a thing they
//! did rather than a thing airlock did.
//!
//! The sequence is terminated with `BEL` rather than `ST`, which is what the
//! clipboard offer already uses and what every terminal that implements either
//! accepts.
//!
//! Two properties are worth stating because the rest of the module exists to
//! hold them:
//!
//! * **Only an address airlock chose is ever made clickable.** A link is
//!   followed without being read, exactly as a scan code is, so it is gated on
//!   the same origin test — see `sign_in::Screen::address_link`. An address a
//!   response chose is printed as the text it is.
//! * **Nothing visible changes.** The escape bytes are wrapped around the cells
//!   the address was already going to be drawn in. The characters, their
//!   columns, and their styles are the ones the widget produced; the cell is
//!   told to keep its own width so the escape bytes are not mistaken for
//!   columns and do not push the rest of the row along.

use std::num::NonZeroU16;

use ratatui::buffer::{Buffer, CellDiffOption};
use ratatui::layout::Rect;
use ratatui::text::Line;

/// What tells the terminal the cells that follow stand for an address.
fn opening(url: &str) -> String {
    format!("\u{1b}]8;;{url}\u{7}")
}

/// What tells it they have stopped.
const CLOSING: &str = "\u{1b}]8;;\u{7}";

/// Where a clickable address is drawn, and where it points.
///
/// Computed from the lines before they are drawn, so the decision is a pure one
/// the suite can read, and applied to the cells afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The column the address starts in.
    x: u16,
    /// The row it is drawn on.
    y: u16,
    /// How many columns it occupies.
    columns: u16,
    /// Where it points.
    url: String,
}

impl Placement {
    /// Where it points.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The cells it covers, as a rectangle one row tall.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn area(&self) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            width: self.columns,
            height: 1,
        }
    }
}

/// Whether an address may be written into the sequence at all.
///
/// The address reaching here has already been sanitized where it left the
/// network worker and has already passed the origin test. This is the third
/// check, and it is deliberately not a fourth reading of the same evidence: it
/// is a property of the slot rather than of the sender. `OSC 8` takes its
/// address as a run of printable ASCII, so anything else — an escape, a bell, a
/// control character, a byte outside that range — is not an address this
/// sequence can carry, and a value that is not one is not linked at all rather
/// than linked after being repaired. That closes the injection question by
/// construction: there is no character left with which to end the sequence
/// early and start another.
fn writable(url: &str) -> bool {
    !url.is_empty()
        && url
            .chars()
            .all(|character| ('\u{21}'..='\u{7e}').contains(&character))
}

/// Find the address among the lines about to be drawn.
///
/// The address is linked only where it is drawn whole on one row, because a
/// span is the unit the widget will draw and a wrapped address is two of them.
/// Where it wrapped, nothing is linked and the address is on screen as the text
/// it is, which is what it was before any of this existed.
#[must_use]
pub fn locate(lines: &[Line<'_>], area: Rect, url: &str) -> Option<Placement> {
    if !writable(url) {
        return None;
    }
    let columns = u16::try_from(url.chars().count()).ok()?;
    for (row, line) in lines.iter().enumerate() {
        let y = u16::try_from(row).ok()?;
        if y >= area.height {
            return None;
        }
        let mut column: u16 = 0;
        for span in &line.spans {
            let width = u16::try_from(span.content.chars().count()).ok()?;
            if span.content == url && column.saturating_add(columns) <= area.width {
                return Some(Placement {
                    x: area.x + column,
                    y: area.y + y,
                    columns,
                    url: url.to_owned(),
                });
            }
            column = column.saturating_add(width);
        }
    }
    None
}

/// Wrap the cells the address was drawn in.
///
/// The symbols are the ones already there. Each altered cell is told to keep
/// the width it has, so the escape bytes are not counted as columns: without
/// that, the character after the opening sequence would be taken for a very
/// wide one and the rest of the row would be skipped.
pub fn place(buffer: &mut Buffer, placement: &Placement) {
    let one = NonZeroU16::new(1).expect("one is not zero");
    let last = placement.x + placement.columns - 1;
    // Whether the whole address fits in a single cell, in which case one cell
    // carries both halves of the sequence.
    if last == placement.x {
        if let Some(cell) = buffer.cell_mut((placement.x, placement.y)) {
            let symbol = format!("{}{}{CLOSING}", opening(&placement.url), cell.symbol());
            cell.set_symbol(&symbol)
                .set_diff_option(CellDiffOption::ForcedWidth(one));
        }
        return;
    }
    if let Some(cell) = buffer.cell_mut((placement.x, placement.y)) {
        let symbol = format!("{}{}", opening(&placement.url), cell.symbol());
        cell.set_symbol(&symbol)
            .set_diff_option(CellDiffOption::ForcedWidth(one));
    }
    if let Some(cell) = buffer.cell_mut((last, placement.y)) {
        let symbol = format!("{}{CLOSING}", cell.symbol());
        cell.set_symbol(&symbol)
            .set_diff_option(CellDiffOption::ForcedWidth(one));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Style;
    use ratatui::text::Span;

    const ADDRESS: &str = "https://github.com/login/device";

    fn area() -> Rect {
        Rect::new(0, 0, 80, 21)
    }

    fn field(address: &str) -> Vec<Line<'static>> {
        vec![
            Line::from(Span::raw("LOGIN TO AIRLOCK")),
            Line::from(vec![Span::raw("address   "), Span::raw(address.to_owned())]),
        ]
    }

    /// What the terminal is actually shown, with the sequences taken back out.
    fn visible(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| {
                        buffer[(x, y)]
                            .symbol()
                            .replace(&opening(ADDRESS), "")
                            .replace(CLOSING, "")
                    })
                    .collect()
            })
            .collect()
    }

    fn drawn(lines: &[Line<'static>], area: Rect) -> Buffer {
        let mut buffer = Buffer::empty(area);
        for (row, line) in lines.iter().enumerate() {
            let mut x = area.x;
            for span in &line.spans {
                buffer.set_string(
                    x,
                    area.y + u16::try_from(row).expect("a row"),
                    span.content.as_ref(),
                    Style::default(),
                );
                x += u16::try_from(span.content.chars().count()).expect("a width");
            }
        }
        buffer
    }

    #[test]
    fn the_address_is_found_where_it_is_drawn() {
        let placement = locate(&field(ADDRESS), area(), ADDRESS).expect("the address is on screen");
        assert_eq!(placement.url(), ADDRESS);
        assert_eq!(
            placement.area(),
            Rect::new(10, 1, ADDRESS.len() as u16, 1),
            "the columns the address itself occupies, after its label"
        );
    }

    #[test]
    fn the_offset_of_the_region_is_carried_into_the_placement() {
        // The body is not the whole terminal: it starts under the header, and a
        // placement that forgot as much would underline the wrong row.
        let placement =
            locate(&field(ADDRESS), Rect::new(0, 2, 80, 19), ADDRESS).expect("the address");
        assert_eq!(placement.area(), Rect::new(10, 3, ADDRESS.len() as u16, 1));
    }

    #[test]
    fn the_sequence_wraps_the_address_and_nothing_else() {
        let lines = field(ADDRESS);
        let mut buffer = drawn(&lines, area());
        let before = visible(&buffer);
        let placement = locate(&lines, area(), ADDRESS).expect("the address is on screen");
        place(&mut buffer, &placement);

        let first = buffer[(placement.x, placement.y)].symbol().to_owned();
        let last = buffer[(placement.x + placement.columns - 1, placement.y)]
            .symbol()
            .to_owned();
        assert_eq!(first, format!("{}h", opening(ADDRESS)));
        assert_eq!(last, format!("e{CLOSING}"));

        // Every character the operator reads is the character that was there,
        // in the column it was in. The sequences are the whole of the change.
        assert_eq!(
            visible(&buffer),
            before,
            "the rendering changed where it must not"
        );
    }

    #[test]
    fn a_linked_cell_keeps_its_own_width() {
        // Without this the escape bytes are counted as columns, the diff skips
        // the rest of the row, and the address is drawn as one character
        // followed by nothing.
        let lines = field(ADDRESS);
        let mut buffer = drawn(&lines, area());
        let placement = locate(&lines, area(), ADDRESS).expect("the address");
        place(&mut buffer, &placement);
        for x in [placement.x, placement.x + placement.columns - 1] {
            assert_eq!(
                buffer[(x, placement.y)].diff_option,
                CellDiffOption::ForcedWidth(NonZeroU16::new(1).expect("one")),
                "the cell at {x} would be read as {} columns",
                buffer[(x, placement.y)].symbol().chars().count()
            );
        }
    }

    #[test]
    fn an_address_carrying_a_sequence_of_its_own_is_never_linked() {
        // The address reaching here is sanitized and origin-checked already.
        // This is the slot refusing anything it cannot carry, so that the
        // question "could a value end the sequence early" has a structural
        // answer rather than an inherited one.
        for hostile in [
            "https://github.com/login/device\u{1b}]8;;https://attacker.example\u{7}",
            "https://github.com/\u{7}login",
            "https://github.com/login\ndevice",
            "https://github.com/login device",
            "https://github.com/login\u{202e}device",
            "",
        ] {
            assert!(!writable(hostile), "{hostile:?}");
            assert!(
                locate(&field(hostile), area(), hostile).is_none(),
                "{hostile:?} was made clickable"
            );
        }
    }

    #[test]
    fn an_address_that_wrapped_is_left_as_the_text_it_is() {
        // Two spans, neither of which is the address, so there is no single run
        // of cells to wrap. Nothing is linked and nothing is altered.
        let lines = vec![Line::from(vec![
            Span::raw("address   "),
            Span::raw("https://github.com/login/"),
            Span::raw("device"),
        ])];
        assert!(locate(&lines, area(), ADDRESS).is_none());
    }

    #[test]
    fn an_address_past_the_bottom_of_the_region_is_not_linked() {
        let mut lines = vec![Line::default(); 4];
        lines.extend(field(ADDRESS));
        assert!(locate(&lines, Rect::new(0, 0, 80, 3), ADDRESS).is_none());
    }
}
