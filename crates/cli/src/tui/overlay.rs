//! A modal panel drawn over the body: what a screen can say on request rather
//! than on every frame.
//!
//! A reading an operator needs once, and only when something looks wrong, is a
//! reading that costs rows on every other frame if the screen carries it
//! standing. The panel is where such a reading lives: it is asked for by a key,
//! it takes every key while it is up, and it leaves nothing behind when it
//! closes.
//!
//! The panel is general and the wiring is not. [`help_of`] is the whole of what
//! offers one, and a screen gains a panel by naming it there — so the key that
//! opens one is advertised exactly where one exists.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Widget as _};

use super::chrome::wrap;
use super::screen::Screen;
use super::theme::{Role, Styles};

/// The columns of body left either side of the panel.
const MARGIN: u16 = 4;

/// The widest the panel grows to, however wide the terminal is.
const MAX_WIDTH: u16 = 76;

/// The columns between the border and the text.
const PADDING: u16 = 2;

/// A panel: a heading, the sentence that frames it, and the points it makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlay {
    /// The heading, in the register every region heading uses.
    pub heading: &'static str,
    /// One sentence saying what the points are points about.
    pub lead: &'static str,
    /// The points, numbered as they are drawn.
    pub points: &'static [&'static str],
}

/// The help a screen offers, where it offers any.
///
/// The one place a screen is given a panel. A screen absent from here has no
/// panel and does not advertise the key that would open one.
#[must_use]
pub const fn help_of(screen: Screen) -> Option<Overlay> {
    match screen {
        Screen::Organizations => Some(TROUBLESHOOTING),
        _ => None,
    }
}

/// What an absent organization means, and what closes each case.
///
/// Three causes with three different remedies. Each one hides the evidence of
/// itself, so airlock cannot tell them apart from here and does not guess: the
/// panel states all three and the operator knows which of them they are in.
const TROUBLESHOOTING: Overlay = Overlay {
    heading: "TROUBLESHOOTING",
    lead: "An organization missing from the list is in one of three states, and \
           each takes a different remedy.",
    points: &[
        "airlock is not installed on it. An owner or an admin installs it.",
        "It is installed, but this account is not a member or its role does not \
         reach the installation. An owner adds the account, or grants the role.",
        "The installation is scoped to repositories this account cannot see. \
         Widen the installation's repository selection.",
    ],
};

impl Overlay {
    /// The panel's text, wrapped to the room inside its border.
    #[must_use]
    pub fn lines(&self, styles: Styles, width: usize) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from(Span::styled(
            self.heading,
            styles.bold(Role::Text),
        ))];
        lines.push(Line::default());
        lines.extend(
            wrap(self.lead, width)
                .into_iter()
                .map(|part| Line::from(Span::styled(part, styles.of(Role::Text)))),
        );
        for (index, point) in self.points.iter().enumerate() {
            lines.push(Line::default());
            let room = width.saturating_sub(3).max(1);
            for (part, text) in wrap(point, room).into_iter().enumerate() {
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
}

/// Draw a panel over the body.
///
/// The cells under it are cleared rather than blended: a panel that let the
/// screen behind it show through would be two readings in one column, and a
/// column that carries meaning cannot carry two.
pub fn render(panel: &Overlay, styles: Styles, body: Rect, buffer: &mut Buffer) {
    let width = body
        .width
        .saturating_sub(MARGIN * 2)
        .clamp(PADDING * 2 + 3, MAX_WIDTH);
    let room = width.saturating_sub(2 + PADDING * 2);
    let lines = panel.lines(styles, room as usize);
    let height = (lines.len() as u16 + 2).min(body.height.max(1));
    let area = Rect {
        x: body.x + (body.width.saturating_sub(width)) / 2,
        y: body.y + (body.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    Clear.render(area, buffer);
    let block = Block::bordered()
        .border_style(styles.of(Role::BorderStrong))
        .style(styles.canvas())
        .padding(ratatui::widgets::Padding::horizontal(PADDING));
    let inner = block.inner(area);
    block.render(area, buffer);
    Paragraph::new(lines).render(inner, buffer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::{ColorMode, Theme};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn text(panel: &Overlay, width: usize) -> String {
        panel
            .lines(styles(), width)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_organizations_panel_states_all_three_remedies() {
        let panel = help_of(Screen::Organizations).expect("organizations offers help");
        let reading = text(&panel, 70);
        assert!(reading.contains("TROUBLESHOOTING"), "{reading}");
        assert!(reading.contains("installs it"), "{reading}");
        assert!(reading.contains("grants the role"), "{reading}");
        assert!(reading.contains("repository selection"), "{reading}");
        assert!(reading.contains("1 ") && reading.contains("2 ") && reading.contains("3 "));
    }

    #[test]
    fn only_the_screen_that_was_wired_offers_a_panel() {
        for screen in Screen::ALL {
            assert_eq!(
                help_of(screen).is_some(),
                screen == Screen::Organizations,
                "{screen:?}"
            );
        }
    }

    #[test]
    fn the_panel_wraps_to_the_room_it_is_given() {
        let panel = help_of(Screen::Organizations).expect("organizations offers help");
        for width in [40, 60, 70] {
            for line in panel.lines(styles(), width) {
                let drawn: String = line
                    .spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect();
                assert!(drawn.chars().count() <= width, "{width}: {drawn:?}");
            }
        }
    }
}
