//! The application state and everything it draws.
//!
//! Nothing here touches a terminal. The state is a plain value, the drawing
//! takes a ratatui frame, and key handling is a pure transition, so the whole
//! interface can be rendered into a buffer and compared.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget as _, Wrap};

/// The column the emptiness values start in.
const FIELD_LABEL_WIDTH: usize = 16;

use airlock_core::findings::Status;
use airlock_core::registry::Severity;

use super::chrome::{self, wrap};
use super::lane::{self, Lane};
use super::screen::Screen;
use super::theme::{ColorMode, Role, Styles, Theme};

/// What the application does after handling an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep running.
    Continue,
    /// Restore the terminal and leave.
    Exit,
}

/// The whole interface state.
#[derive(Debug, Clone)]
pub struct App {
    screen: Screen,
    theme: Theme,
    color: ColorMode,
    version: String,
}

impl App {
    /// Open the interface at its entry screen.
    #[must_use]
    pub fn new(version: impl Into<String>, color: ColorMode) -> Self {
        Self {
            screen: Screen::ENTRY,
            theme: Theme::Dark,
            color,
            version: version.into(),
        }
    }

    /// Open the interface on a given screen and palette.
    ///
    /// The snapshot suite must reach every screen without a session, and a
    /// session is exactly what this build does not have.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn at(mut self, screen: Screen, theme: Theme) -> Self {
        self.screen = screen;
        self.theme = theme;
        self
    }

    /// The screen currently open.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn screen(&self) -> Screen {
        self.screen
    }

    /// The palette in force.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn theme(&self) -> Theme {
        self.theme
    }

    fn styles(&self) -> Styles {
        Styles::new(self.theme, self.color)
    }

    /// Apply a key.
    ///
    /// Two keys are live on every screen in every state: `t` switches theme and
    /// `ctrl-c` exits. Everything else is the open screen's own.
    pub fn handle_key(&mut self, event: KeyEvent) -> Flow {
        // A terminal that reports key releases would otherwise act twice.
        if event.kind == KeyEventKind::Release {
            return Flow::Continue;
        }
        if event.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(event.code, KeyCode::Char('c'))
        {
            return Flow::Exit;
        }
        match event.code {
            KeyCode::Char('t') => self.theme = self.theme.toggled(),
            KeyCode::Enter => {
                if let Some(next) = self.screen.forward() {
                    self.screen = next;
                }
            }
            KeyCode::Esc => {
                if let Some(previous) = self.screen.back() {
                    self.screen = previous;
                }
            }
            KeyCode::Char('a') if self.screen.remediation_reachable() => {
                self.screen = Screen::Remediation;
            }
            KeyCode::Char('p') if self.screen == Screen::Findings => {
                self.screen = Screen::PolicyInspector;
            }
            KeyCode::Char('b') if self.screen == Screen::Findings => {
                self.screen = Screen::PublishingBootstrap;
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Draw the whole interface.
    pub fn render(&self, area: Rect, buffer: &mut ratatui::buffer::Buffer) {
        let styles = self.styles();
        if styles.colored() {
            Paragraph::new("")
                .style(styles.canvas())
                .render(area, buffer);
        }
        if !chrome::fits(area) {
            self.render_undersized(area, buffer);
            return;
        }
        let frame = chrome::layout(area);
        Paragraph::new(chrome::header_line(
            self.screen,
            &self.version,
            styles,
            area.width,
        ))
        .render(frame.header, buffer);
        for rule in [frame.rule_top, frame.rule_bottom].into_iter().flatten() {
            Paragraph::new(chrome::rule_line(styles, area.width)).render(rule, buffer);
        }
        Paragraph::new(chrome::keymap_line(self.screen, styles, area.width))
            .render(frame.keymap, buffer);
        Paragraph::new(chrome::status_line(self.screen, styles, area.width))
            .render(frame.status, buffer);
        // The body is wrapped here rather than by the paragraph, so a
        // continuation line lands under the text it continues instead of under
        // the label, and so a column that carries meaning cannot be reflowed
        // out of position.
        let body = self.withhold(self.body(frame.body.width), frame.body.height);
        Paragraph::new(body).render(frame.body, buffer);
    }

    /// Cut the body to the rows available, saying so on the last of them.
    ///
    /// Content that runs past the bottom is withheld rather than clipped: a
    /// reader who cannot see that a region continues will read what is on
    /// screen as the whole of it. The note is not a scroll indicator — this
    /// frame does not scroll — it is the statement that something is missing.
    fn withhold(&self, mut lines: Vec<Line<'static>>, height: u16) -> Vec<Line<'static>> {
        let height = height as usize;
        if lines.len() <= height || height == 0 {
            return lines;
        }
        let withheld = lines.len() - (height - 1);
        lines.truncate(height - 1);
        lines.push(Line::from(Span::styled(
            format!(
                "\u{2014} {withheld} more lines withheld: this screen needs {} rows and has {height} \u{2014}",
                withheld + height - 1
            ),
            self.styles().of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
        lines
    }

    fn render_undersized(&self, area: Rect, buffer: &mut ratatui::buffer::Buffer) {
        let styles = self.styles();
        let lines: Vec<Line<'static>> = chrome::undersized_message(area)
            .into_iter()
            .enumerate()
            .map(|(index, text)| {
                let style = if index == 0 {
                    styles.bold(Role::Accent)
                } else {
                    styles.of(Role::Text)
                };
                Line::from(Span::styled(text, style))
            })
            .collect();
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .render(area, buffer);
    }

    /// The body of the open screen.
    ///
    /// Every screen here is a stub, and each one says so in the terms the
    /// emptiness rule requires: what would have populated the region, why it is
    /// empty, and what can be done next. Only the findings screen draws
    /// anything more, because the status vocabulary is the one thing this task
    /// does own.
    fn body(&self, width: u16) -> Vec<Line<'static>> {
        let styles = self.styles();
        let width = width as usize;
        let mut lines = vec![Line::from(Span::styled(
            self.screen.label().to_uppercase(),
            styles.bold(Role::Accent),
        ))];
        for line in wrap(self.screen.purpose(), width) {
            lines.push(Line::from(Span::styled(line, styles.of(Role::Text))));
        }
        lines.push(Line::default());
        // The vocabulary comes first because it is content this build actually
        // has. The emptiness statement describes what is absent, and a reading
        // of what is absent is worth less than a reading of what is present
        // when the two compete for the same rows.
        if self.screen == Screen::Findings {
            lines.extend(self.vocabulary(width));
            lines.push(Line::default());
        }
        lines.extend(self.emptiness(width));
        lines
    }

    fn emptiness(&self, width: usize) -> Vec<Line<'static>> {
        let styles = self.styles();
        let mut lines = vec![Line::from(Span::styled(
            "NOTHING OBSERVED YET",
            styles.bold(Role::Text),
        ))];
        for (label, text) in [
            ("would show", self.screen_content()),
            (
                "empty because",
                "this build is the interface shell. It draws the frame, the \
                 status vocabulary, and the navigation between screens. No \
                 authorization is requested and no repository is observed, so \
                 there is nothing for this region to hold.",
            ),
            (
                "next",
                "navigate with \u{21b5} and esc to read the frame on every \
                 screen, press t to compare the palettes, and ctrl-c to leave.",
            ),
        ] {
            let room = width.saturating_sub(FIELD_LABEL_WIDTH).max(1);
            for (index, part) in wrap(text, room).into_iter().enumerate() {
                let label = if index == 0 { label } else { "" };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{label:<FIELD_LABEL_WIDTH$}"),
                        styles.of(Role::Faint),
                    ),
                    Span::styled(part, styles.of(Role::Dim)),
                ]));
            }
        }
        lines
    }

    fn screen_content(&self) -> &'static str {
        match self.screen {
            Screen::SignIn => {
                "the device code, the address to enter it at, and the scan code \
                 where width allows"
            }
            Screen::Organizations => {
                "the reachable installations, each with its kind and its \
                 repository count"
            }
            Screen::Repositories => {
                "a filter over the repository name, and a table of name, \
                 visibility, last audit, verdict, and default branch"
            }
            Screen::Findings => {
                "the verdict, the status summary, and the eight groups of the \
                 work queue"
            }
            Screen::FindingDetail => {
                "one finding's evidence, error, suppression, remediation, and \
                 effect on the run"
            }
            Screen::Remediation => {
                "the proposed change, the transcript of carrying it out, and \
                 the re-observation that follows it"
            }
            Screen::PolicyInspector => {
                "every rule the run asked about, the registry digest, and where \
                 each rule came from"
            }
            Screen::PublishingBootstrap => {
                "the five steps, the one the observation places you at, and any \
                 outstanding credential"
            }
        }
    }

    /// The status vocabulary, drawn from the one primitive.
    fn vocabulary(&self, width: usize) -> Vec<Line<'static>> {
        let styles = self.styles();
        let mut lines = vec![Line::from(Span::styled(
            "STATUS VOCABULARY",
            styles.bold(Role::Text),
        ))];
        let narrow = width < chrome::REFERENCE_WIDTH as usize;
        for lane in Lane::ALL {
            lines.push(Line::from(vec![
                Span::styled(lane.heading(), styles.bold(Role::Dim)),
                Span::styled(
                    if narrow {
                        String::new()
                    } else {
                        format!("  {}", lane.qualifier())
                    },
                    styles.of(Role::Faint),
                ),
            ]));
            for status in Status::ALL.iter().filter(|s| lane::lane_of(**s) == lane) {
                // A legend that wraps stops being a legend, so the gloss is
                // elided to the room the lanes and the status name leave.
                lines.push(lane::legend_row(*status, styles, width));
            }
        }
        lines.push(Line::default());
        let mut severities = vec![
            Span::styled("SEVERITY", styles.bold(Role::Dim)),
            Span::raw("  "),
        ];
        for (index, severity) in Severity::ALL.iter().enumerate() {
            if index > 0 {
                severities.push(Span::styled("   ", styles.of(Role::Faint)));
            }
            severities.extend(lane::severity_spans(*severity, styles));
        }
        lines.push(Line::from(severities));
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", lane::GATING_RAIL),
                styles.of(Role::Status(Status::Fail)),
            ),
            Span::styled(
                "a solid left rail marks a row that actually gates the run",
                styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
            ),
        ]));
        lines
    }
}

impl Screen {
    /// Whether `a` reaches the remediation transcript from here.
    const fn remediation_reachable(self) -> bool {
        matches!(self, Screen::Findings | Screen::FindingDetail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new("0.0.0", ColorMode::Color)
    }

    fn press(app: &mut App, code: KeyCode) -> Flow {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn the_interface_opens_on_sign_in_in_the_dark_palette() {
        let app = app();
        assert_eq!(app.screen(), Screen::SignIn);
        assert_eq!(app.theme(), Theme::Dark);
    }

    #[test]
    fn ctrl_c_exits_from_every_screen() {
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            let flow = app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert_eq!(flow, Flow::Exit, "{screen:?}");
        }
    }

    #[test]
    fn t_switches_theme_on_every_screen_and_never_exits() {
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            assert_eq!(press(&mut app, KeyCode::Char('t')), Flow::Continue);
            assert_eq!(app.theme(), Theme::Light, "{screen:?}");
            press(&mut app, KeyCode::Char('t'));
            assert_eq!(app.theme(), Theme::Dark, "{screen:?}");
            assert_eq!(app.screen(), screen, "theme is not navigation");
        }
    }

    #[test]
    fn enter_and_esc_walk_the_chain_and_stop_at_its_ends() {
        let mut app = app();
        for expected in [
            Screen::Organizations,
            Screen::Repositories,
            Screen::Findings,
            Screen::FindingDetail,
        ] {
            press(&mut app, KeyCode::Enter);
            assert_eq!(app.screen(), expected);
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail, "the chain ends here");
        for expected in [
            Screen::Findings,
            Screen::Repositories,
            Screen::Organizations,
            Screen::SignIn,
        ] {
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), expected);
        }
        press(&mut app, KeyCode::Esc);
        assert_eq!(
            app.screen(),
            Screen::SignIn,
            "sign-in has nothing behind it"
        );
    }

    #[test]
    fn the_screens_hung_off_findings_are_reachable_and_return_to_it() {
        for (code, expected) in [
            (KeyCode::Char('a'), Screen::Remediation),
            (KeyCode::Char('p'), Screen::PolicyInspector),
            (KeyCode::Char('b'), Screen::PublishingBootstrap),
        ] {
            let mut app = app().at(Screen::Findings, Theme::Dark);
            press(&mut app, code);
            assert_eq!(app.screen(), expected);
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), Screen::Findings);
        }
    }

    #[test]
    fn apply_is_inert_where_the_specification_says_it_is() {
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            press(&mut app, KeyCode::Char('a'));
            let moved = app.screen() != screen;
            assert_eq!(
                moved,
                matches!(screen, Screen::Findings | Screen::FindingDetail),
                "{screen:?}"
            );
            if moved {
                assert_eq!(app.screen(), Screen::Remediation, "{screen:?}");
            }
        }
    }

    #[test]
    fn a_key_release_does_nothing() {
        let mut app = app();
        let mut event = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        event.kind = KeyEventKind::Release;
        assert_eq!(app.handle_key(event), Flow::Continue);
        assert_eq!(app.theme(), Theme::Dark);
    }

    #[test]
    fn every_screen_states_what_would_have_populated_it() {
        for screen in Screen::ALL {
            let app = app().at(screen, Theme::Dark);
            let text: String = app
                .body(chrome::REFERENCE_WIDTH)
                .iter()
                .flat_map(|line| line.spans.iter())
                .map(|span| span.content.as_ref())
                .collect();
            assert!(text.contains("would show"), "{screen:?}");
            assert!(text.contains("empty because"), "{screen:?}");
            assert!(text.contains("next"), "{screen:?}");
        }
    }

    #[test]
    fn content_that_runs_past_the_bottom_is_withheld_and_says_so() {
        let app = app();
        let lines: Vec<Line<'static>> = (0..30).map(|_| Line::raw("x")).collect();
        let kept = app.withhold(lines.clone(), 10);
        assert_eq!(kept.len(), 10);
        let note: String = kept[9].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(note.contains("21 more lines withheld"), "{note}");
        assert!(note.contains("30 rows"), "{note}");
        assert_eq!(
            app.withhold(lines.clone(), 30).len(),
            30,
            "an exact fit is untouched"
        );
        assert_eq!(
            app.withhold(lines, 40).len(),
            30,
            "room to spare is untouched"
        );
    }

    #[test]
    fn the_findings_screen_prints_all_nine_statuses_with_their_glosses() {
        let app = app().at(Screen::Findings, Theme::Dark);
        let text: String = app
            .body(chrome::REFERENCE_WIDTH)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        for status in Status::ALL {
            assert!(text.contains(status.code()), "{status:?} is missing");
            assert!(text.contains(lane::glyph_of(*status)), "{status:?} glyph");
            // The gloss is elided to the room the row leaves, so its opening is
            // what the row is asserted to carry.
            let opening: String = lane::gloss_of(*status).chars().take(24).collect();
            assert!(text.contains(&opening), "{status:?} gloss");
        }
        for lane in Lane::ALL {
            assert!(text.contains(lane.heading()), "{lane:?}");
        }
    }
}
