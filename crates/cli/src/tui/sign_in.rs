//! The sign-in screen.
//!
//! It draws the five states of the device flow, the code frame that is drawn
//! empty rather than absent so nothing moves when the code arrives, the scan
//! code where there is room for all of it, and the standing statement that no
//! credential of any kind is stored.
//!
//! The credential region shows the grant by permission list and by source. It
//! never shows a value, and there is no value here to show: the screen is given
//! the identity, which is a compile-time constant, and never the credential.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::admin::identity::{self, WriteIdentity};
use crate::admin::scan::{self, ScanCode};
use crate::admin::sign_in::{humanize, Density, SignIn};
use crate::admin::{flow, text};

use super::chrome::wrap;
use super::panel;
use super::theme::{Role, Styles};

/// The columns a scan code occupies, quiet zone included.
const SCAN_COLUMNS: usize = 33;

/// The blank columns between the text column and a scan code beside it.
const SCAN_GUTTER: usize = 2;

/// The narrowest text column worth keeping beside a scan code.
const TEXT_MINIMUM: usize = 60;

/// The width at which the scan code for the expected address sits alongside the
/// device code.
///
/// The budget the specification states, and the threshold the prose density is
/// keyed off. The layout itself measures the symbol it is about to draw rather
/// than trusting this: the symbol grows with the address, and a constant would
/// be right until the day the address changed.
pub const ALONGSIDE_WIDTH: usize = TEXT_MINIMUM + SCAN_GUTTER + SCAN_COLUMNS;

/// The light field a scan code paints for itself.
const FIELD: Color = Color::Rgb(0xFF, 0xFF, 0xFF);

/// The dark modules a scan code paints for itself.
const MODULE: Color = Color::Rgb(0x00, 0x00, 0x00);

/// Where the operator has asked for the scan code.
///
/// `q` cycles it. `Auto` is the specification's default — beside the device
/// code where there is width for it, withheld where there is not. `Below` is
/// what the withheld state offers instead, and `Hidden` is the other half of
/// "show or hide".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    /// Beside the device code, where there is room.
    #[default]
    Auto,
    /// Under the device code.
    Below,
    /// Not drawn.
    Hidden,
}

impl ScanMode {
    /// What `q` selects next.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Auto => Self::Below,
            Self::Below => Self::Hidden,
            Self::Hidden => Self::Auto,
        }
    }

    /// What `q` will do, said on the screen rather than left to be discovered.
    #[must_use]
    pub const fn offer(self, density: Density) -> &'static str {
        match (self, density) {
            (Self::Auto, Density::Full) => "q draws the scan code below the device code instead",
            (Self::Auto, Density::Tight) => "q draws it below",
            (Self::Below, Density::Full) => "q hides the scan code",
            (Self::Below, Density::Tight) => "q hides it",
            (Self::Hidden, Density::Full) => "q shows the scan code again",
            (Self::Hidden, Density::Tight) => "q shows it",
        }
    }
}

/// Why a scan code is not drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Withheld {
    /// There is no code yet, so there is no address to encode.
    NoCode,
    /// The operator hid it.
    Hidden,
    /// The terminal is too narrow for it to sit alongside: the columns it
    /// needs beside a readable text column, and the columns there are.
    TooNarrow {
        /// What the whole layout would take.
        needed: usize,
        /// What the terminal has.
        have: usize,
    },
    /// The terminal is too short for all of it: the rows it needs, and the rows
    /// left to give it.
    TooShort {
        /// What the symbol takes.
        needed: usize,
        /// What is left.
        have: usize,
    },
    /// Colour is off, and the code paints its own field in colour.
    NoColor,
    /// The address is not at the origin airlock asked, or would not encode.
    Elsewhere,
}

impl Withheld {
    fn statement(&self, density: Density) -> String {
        let tight = density == Density::Tight;
        match self {
            Self::NoCode if tight => "none yet: it encodes the address.".to_owned(),
            Self::NoCode => {
                "no scan code yet: it encodes the address, and the address arrives with \
                 the code."
                    .to_owned()
            }
            Self::Hidden => "hidden. The address above is the whole of what it encodes.".to_owned(),
            Self::TooNarrow { needed, have } if tight => {
                format!("withheld: needs {needed} columns, this has {have}.")
            }
            Self::TooNarrow { needed, have } => format!(
                "withheld: it needs {} columns beside a readable text column, which is \
                 {needed} in all, and this terminal has {have}. A partly drawn scan code \
                 is never rendered, because a code that cannot be scanned is worse than \
                 an address you type.",
                needed - TEXT_MINIMUM - SCAN_GUTTER
            ),
            Self::TooShort { needed, have } if tight => {
                format!("withheld: it needs {needed} rows and has {have}.")
            }
            Self::TooShort { needed, have } => format!(
                "withheld: it needs {needed} rows and this screen has {have} left to give \
                 it. It is withheld rather than cut off, for the same reason."
            ),
            Self::NoColor if tight => {
                "withheld: it paints its own field in colour, and NO_COLOR is in force.".to_owned()
            }
            Self::NoColor => {
                "withheld: it paints its own light field and quiet zone so that it scans \
                 on either palette, and NO_COLOR is in force. The address above is the \
                 whole of what it encodes."
                    .to_owned()
            }
            Self::Elsewhere => format!(
                "withheld: the address above is not at {}, which is where airlock asked. \
                 A scan code is followed without being read, so airlock will not point \
                 one somewhere the response chose. Read the address before you act on it.",
                flow::login_origin()
            ),
        }
    }
}

/// How much room there is for words, from the terminal's own width.
///
/// The terminal's, not the text column's: at the reference the scan code takes
/// a third of the row, and prose that shortened itself because a scan code
/// moved in beside it would be answering the wrong question. Keyed off width
/// rather than height so the screen has two settled readings rather than one
/// that changes as the terminal grows a row.
const fn density(width: usize) -> Density {
    if width < ALONGSIDE_WIDTH {
        Density::Tight
    } else {
        Density::Full
    }
}

/// The sign-in screen: the flow's state, and where the scan code is drawn.
#[derive(Debug, Clone)]
pub struct Screen {
    state: SignIn,
    scan: ScanMode,
    identity: WriteIdentity,
}

impl Default for Screen {
    fn default() -> Self {
        Self {
            state: SignIn::opening(),
            scan: ScanMode::default(),
            identity: identity::bound(),
        }
    }
}

impl Screen {
    /// Open the screen on a given state, for the snapshot suite.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn at(state: SignIn) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }

    /// The flow's state.
    #[must_use]
    pub const fn state(&self) -> &SignIn {
        &self.state
    }

    /// The flow's state, to advance it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn state_mut(&mut self) -> &mut SignIn {
        &mut self.state
    }

    /// Where the scan code is being drawn.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn scan_mode(&self) -> ScanMode {
        self.scan
    }

    /// Handle `q`.
    ///
    /// Inert until a code exists, because until then there is no address to
    /// encode. The keymap says so rather than the key silently doing nothing.
    pub const fn cycle_scan(&mut self) {
        if self.state.has_code() {
            self.scan = self.scan.next();
        }
    }

    /// The screen's body.
    ///
    /// The whole of it, at both sizes. Nothing here is allowed to run off the
    /// bottom and be withheld by the frame: the credential statement is the one
    /// thing this screen exists to make, and a statement about storage that the
    /// operator has to make the terminal bigger to read is not one.
    pub fn body(&self, styles: Styles, width: u16, height: u16) -> Vec<Line<'static>> {
        let width = width as usize;
        let density = density(width);
        let placement = self.placement(styles, width, height as usize);
        // Measured from the symbol that will actually be drawn, not from the
        // budget. The symbol grows with the address, and a layout that assumed
        // one size would push a wider one off the edge — which is the clipping
        // the withholding rule exists to prevent.
        let text_width = match &placement {
            Ok(Placement::Alongside(code)) => width.saturating_sub(code.columns() + SCAN_GUTTER),
            _ => width,
        };
        let mut lines = self.text(styles, text_width, density, &placement);
        match &placement {
            Ok(Placement::Alongside(code)) => {
                self.overlay(styles, &mut lines, code, text_width + SCAN_GUTTER);
            }
            Ok(Placement::Below(code)) => {
                lines.push(Line::default());
                lines.extend(paint(code, styles));
            }
            Err(_) => {}
        }
        lines
    }

    /// Where the scan code goes, or why it does not go anywhere.
    ///
    /// The vertical test is what keeps a scan code from being drawn into rows
    /// the frame will then cut off. Beside the code it needs its own rows; below
    /// it, it needs them after everything the screen already says, and the
    /// screen says how many it is short rather than drawing what fits.
    fn placement(
        &self,
        styles: Styles,
        width: usize,
        height: usize,
    ) -> Result<Placement, Withheld> {
        if !self.state.has_code() {
            return Err(Withheld::NoCode);
        }
        if self.scan == ScanMode::Hidden {
            return Err(Withheld::Hidden);
        }
        if !styles.colored() {
            return Err(Withheld::NoColor);
        }
        let Some(code) = self.encoded() else {
            return Err(Withheld::Elsewhere);
        };
        let (rows, columns) = (code.lines(), code.columns());
        match self.scan {
            ScanMode::Below => {
                // Measured against the text as it will actually be drawn, at
                // the full width, with one blank row between the two.
                let text = self
                    .text(styles, width, density(width), &Err(Withheld::Hidden))
                    .len();
                let have = height.saturating_sub(text + 1);
                if have < rows {
                    return Err(Withheld::TooShort { needed: rows, have });
                }
                Ok(Placement::Below(code))
            }
            _ if height < rows => Err(Withheld::TooShort {
                needed: rows,
                have: height,
            }),
            _ if width >= TEXT_MINIMUM + SCAN_GUTTER + columns => Ok(Placement::Alongside(code)),
            _ => Err(Withheld::TooNarrow {
                needed: TEXT_MINIMUM + SCAN_GUTTER + columns,
                have: width,
            }),
        }
    }

    /// The scan code for the address on screen, where there is one that may be
    /// encoded.
    ///
    /// The address is checked for origin as well as for characters. A scan code
    /// is followed without being read, so encoding an address only because a
    /// response carried it would hand the destination to whoever wrote the
    /// response. It is encoded only when it sits at the origin airlock sent its
    /// own request to; otherwise it is printed as text and the screen says why.
    fn encoded(&self) -> Option<ScanCode> {
        let address = &self.state.code()?.verification_uri;
        if !text::is_at_origin(address, &flow::login_origin()) {
            return None;
        }
        ScanCode::encode(address).ok()
    }

    /// Paint the scan code into the right-hand columns of the lines already
    /// built, padding each to the column it starts in.
    fn overlay(
        &self,
        styles: Styles,
        lines: &mut Vec<Line<'static>>,
        code: &ScanCode,
        column: usize,
    ) {
        let scan = paint(code, styles);
        while lines.len() < scan.len() {
            lines.push(Line::default());
        }
        for (line, painted) in lines.iter_mut().zip(scan) {
            let used: usize = line
                .spans
                .iter()
                .map(|span| span.content.chars().count())
                .sum();
            line.spans.push(Span::styled(
                " ".repeat(column.saturating_sub(used)),
                styles.of(Role::Text),
            ));
            line.spans.extend(painted.spans);
        }
    }

    fn text(
        &self,
        styles: Styles,
        width: usize,
        density: Density,
        placement: &Result<Placement, Withheld>,
    ) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from(Span::styled(
            self.state.heading(),
            styles.bold(Role::Accent),
        ))];
        lines.extend(paragraph(
            &self.state.statement(density),
            styles,
            Role::Text,
            width,
        ));
        lines.push(Line::default());
        lines.extend(self.code_frame(styles));
        if density == Density::Full {
            lines.push(Line::default());
        }
        lines.extend(self.facts(styles, width, placement, density));
        if density == Density::Full {
            lines.push(Line::default());
        }
        lines.extend(panel::field(
            styles,
            "remedy",
            &self.state.remedy(density),
            width,
        ));
        if density == Density::Full {
            lines.push(Line::default());
        }
        lines.extend(panel::credential(styles, self.identity, width, density));
        lines
    }

    /// The code frame.
    ///
    /// Drawn empty rather than absent while the code is being requested, so
    /// nothing shifts position when the code arrives.
    ///
    /// The characters are spaced apart. GitHub's alphabet already excludes `0`,
    /// `O`, `1`, and `I`, and spacing is the layout half of the same
    /// requirement: a reader transcribing eight characters reads them one at a
    /// time, and a run of them set solid invites a doubled or dropped letter.
    fn code_frame(&self, styles: Styles) -> Vec<Line<'static>> {
        let code = self.state.code().map(|code| code.user_code.clone());
        let spaced = code.as_deref().map_or_else(
            || " ".repeat(15),
            |code| {
                code.chars()
                    .map(|character| character.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        );
        let inner = spaced.chars().count().max(15) + 4;
        let border = styles.of(Role::BorderStrong);
        let value = if code.is_some() {
            styles.bold(Role::Accent).add_modifier(Modifier::UNDERLINED)
        } else {
            styles.of(Role::Faint)
        };
        let pad = inner.saturating_sub(spaced.chars().count());
        let left = pad / 2;
        vec![
            Line::from(Span::styled(
                format!("\u{250c}{}\u{2510}", "\u{2500}".repeat(inner)),
                border,
            )),
            Line::from(vec![
                Span::styled("\u{2502}", border),
                Span::styled(" ".repeat(left), value),
                Span::styled(spaced, value),
                Span::styled(" ".repeat(pad - left), value),
                Span::styled("\u{2502}", border),
            ]),
            Line::from(Span::styled(
                format!("\u{2514}{}\u{2518}", "\u{2500}".repeat(inner)),
                border,
            )),
        ]
    }

    fn facts(
        &self,
        styles: Styles,
        width: usize,
        placement: &Result<Placement, Withheld>,
        density: Density,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        let address = self
            .state
            .code()
            .map_or("not issued yet", |code| code.verification_uri.as_str())
            .to_owned();
        lines.extend(panel::field(styles, "address", &address, width));
        lines.extend(panel::field(
            styles,
            "code",
            match density {
                Density::Full => {
                    "eight characters, case-insensitive. The alphabet excludes 0, O, 1, \
                     and I, so there is no character here that another can be mistaken \
                     for."
                }
                Density::Tight => "eight characters, case-insensitive; no 0, O, 1, or I.",
            },
            width,
        ));
        match &self.state {
            SignIn::Awaiting {
                poll,
                interval,
                remaining,
                ..
            } => {
                lines.extend(panel::field(
                    styles,
                    "polling",
                    &format!("attempt {poll}, every {}", humanize(*interval)),
                    width,
                ));
                lines.extend(panel::field(
                    styles,
                    "code expires",
                    &format!("in {}", humanize(*remaining)),
                    width,
                ));
            }
            SignIn::Interrupted {
                poll,
                backoff,
                remaining,
                code,
                ..
            } => {
                lines.extend(panel::field(
                    styles,
                    "polling",
                    &format!("attempt {poll} failed, retrying in {}", humanize(*backoff)),
                    width,
                ));
                if code.is_some() {
                    lines.extend(panel::field(
                        styles,
                        "code expires",
                        &match density {
                            Density::Full => {
                                format!("in {}, and it is still valid", humanize(*remaining))
                            }
                            Density::Tight => format!("in {}, still valid", humanize(*remaining)),
                        },
                        width,
                    ));
                }
            }
            SignIn::Requesting { .. } | SignIn::Expired | SignIn::Denied => {}
        }
        let scan = match placement {
            Ok(Placement::Alongside(_)) => "drawn beside the code. It encodes the address \
                 only, because the device flow offers no address that carries the code."
                .to_owned(),
            Ok(Placement::Below(_)) => {
                "drawn below the code. It encodes the address only.".to_owned()
            }
            Err(reason) => reason.statement(density),
        };
        // At the floor the offer rides on the same line rather than taking one
        // of its own, because a row here is a row the credential statement
        // needs.
        match density {
            Density::Full => {
                lines.extend(panel::field(styles, "scan code", &scan, width));
                if self.state.has_code() {
                    lines.extend(panel::field(styles, "", self.scan.offer(density), width));
                }
            }
            Density::Tight => {
                let offer = if self.state.has_code() {
                    format!(" {}.", self.scan.offer(density))
                } else {
                    String::new()
                };
                lines.extend(panel::field(
                    styles,
                    "scan code",
                    &format!("{scan}{offer}"),
                    width,
                ));
            }
        }
        lines
    }
}

/// Where a scan code was drawn, and the symbol that was drawn there.
///
/// The symbol is carried rather than re-encoded, so the size the layout was
/// decided against and the size that is painted are the same one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement {
    /// Beside the device code.
    Alongside(ScanCode),
    /// Under it.
    Below(ScanCode),
}

/// Draw a scan code, painting both halves of every cell.
///
/// Neither half inherits the terminal background, which is what makes the code
/// scan identically on both palettes.
fn paint(code: &ScanCode, styles: Styles) -> Vec<Line<'static>> {
    let _ = styles;
    (0..code.lines())
        .map(|line| {
            Line::from(
                code.row(line)
                    .into_iter()
                    .map(|cell| {
                        Span::styled(
                            scan::glyph(),
                            Style::default()
                                .fg(if cell.upper_dark { MODULE } else { FIELD })
                                .bg(if cell.lower_dark { MODULE } else { FIELD }),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn paragraph(text: &str, styles: Styles, role: Role, width: usize) -> Vec<Line<'static>> {
    wrap(text, width)
        .into_iter()
        .map(|line| Line::from(Span::styled(line, styles.of(role))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::flow::Issued;
    use crate::admin::scan::ScanCode;
    use crate::admin::sign_in::Reason;
    use crate::tui::chrome::{FLOOR_WIDTH, REFERENCE_WIDTH};
    use crate::tui::theme::{ColorMode, Theme};

    /// The rows the frame leaves the body at the floor: 24 less the header,
    /// the keymap, and the status line.
    const FLOOR_BODY: u16 = 21;

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn issued() -> Issued {
        Issued {
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: std::time::Duration::from_secs(900),
            interval: std::time::Duration::from_secs(5),
        }
    }

    fn awaiting() -> Screen {
        let mut screen = Screen::default();
        screen.state_mut().code_issued(&issued());
        screen
    }

    /// The rendering with its wrapping collapsed, so an assertion about a
    /// sentence is not an assertion about where the sentence broke.
    fn flat(screen: &Screen, styles: Styles, width: u16, height: u16) -> String {
        screen
            .body(styles, width, height)
            .iter()
            .flat_map(|line| line.spans.iter())
            // The scan code is not prose and would otherwise land in the middle
            // of a sentence it happens to sit beside.
            .filter(|span| span.content != scan::glyph())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn rendered(screen: &Screen, styles: Styles, width: u16, height: u16) -> String {
        screen
            .body(styles, width, height)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn every_screen() -> Vec<Screen> {
        let mut expired = awaiting();
        expired.state_mut().expired();
        let mut denied = awaiting();
        denied.state_mut().denied();
        let mut interrupted = awaiting();
        interrupted.state_mut().interrupted("connection reset");
        vec![Screen::default(), awaiting(), expired, denied, interrupted]
    }

    #[test]
    fn every_state_draws_and_names_itself_and_its_remedy() {
        for screen in every_screen() {
            let text = flat(&screen, styles(), REFERENCE_WIDTH, 35);
            assert!(text.contains(screen.state().heading()), "{text}");
            assert!(text.contains("remedy"), "{text}");
            assert!(text.contains("CREDENTIAL"), "{text}");
        }
    }

    #[test]
    fn no_state_ever_shows_a_credential_value() {
        for screen in every_screen() {
            let text = flat(&screen, styles(), REFERENCE_WIDTH, 35);
            assert!(!text.contains("never-shown"), "the device code leaked");
            assert!(!text.contains(identity::bound().client_id), "{text}");
            assert!(text.contains("value is never displayed"), "{text}");
        }
    }

    #[test]
    fn every_state_states_that_nothing_is_stored() {
        for screen in every_screen() {
            let text = flat(&screen, styles(), REFERENCE_WIDTH, 35);
            assert!(
                text.contains("No credential of any kind is stored"),
                "{text}"
            );
        }
    }

    #[test]
    fn the_grant_is_shown_by_permission_list_and_source() {
        let text = flat(&awaiting(), styles(), REFERENCE_WIDTH, 35);
        for permission in identity::bound().grant {
            assert!(
                text.contains(&format!("{} {}", permission.name, permission.level)),
                "{} is missing",
                permission.name
            );
        }
        assert!(text.contains(&identity::bound().source()), "{text}");
    }

    #[test]
    fn the_code_frame_is_drawn_empty_rather_than_absent_while_requesting() {
        let requesting = rendered(&Screen::default(), styles(), REFERENCE_WIDTH, 35);
        let awaiting = rendered(&awaiting(), styles(), REFERENCE_WIDTH, 35);
        let frame = |text: &str| {
            text.lines()
                .position(|line| line.starts_with('\u{250c}'))
                .expect("the frame is drawn")
        };
        assert_eq!(
            frame(&requesting),
            frame(&awaiting),
            "the code frame must not move when the code arrives"
        );
    }

    #[test]
    fn the_device_code_is_spaced_so_no_two_characters_run_together() {
        let text = flat(&awaiting(), styles(), REFERENCE_WIDTH, 35);
        assert!(text.contains("W D J B - M J H T"), "{text}");
        assert!(
            text.contains("excludes 0, O, 1, and I"),
            "the alphabet is stated: {text}"
        );
    }

    #[test]
    fn the_scan_code_sits_alongside_at_the_reference_and_is_withheld_at_the_floor() {
        let wide = rendered(&awaiting(), styles(), REFERENCE_WIDTH, 35);
        assert!(wide.contains("drawn beside the code"), "{wide}");
        assert_eq!(
            wide.lines()
                .filter(|line| line.contains(scan::glyph()))
                .count(),
            17,
            "all of it, or none of it"
        );

        let narrow = flat(&awaiting(), styles(), FLOOR_WIDTH, 21);
        assert!(narrow.contains("withheld"), "{narrow}");
        assert!(narrow.contains("needs 95 columns, this has 80"), "{narrow}");
        assert!(
            !narrow.contains(scan::glyph()),
            "a partly drawn scan code is never rendered"
        );
    }

    #[test]
    fn a_withheld_scan_code_offers_to_be_drawn_below_and_q_does_it() {
        let mut screen = awaiting();
        let narrow = flat(&screen, styles(), FLOOR_WIDTH, 21);
        assert!(narrow.contains("q draws it below"), "{narrow}");

        screen.cycle_scan();
        assert_eq!(screen.scan_mode(), ScanMode::Below);
        // At the floor there is no vertical room for it either, and the screen
        // says which dimension is short rather than drawing part of it.
        let below = flat(&screen, styles(), FLOOR_WIDTH, 21);
        assert!(below.contains("needs 17 rows"), "{below}");
        assert!(!below.contains(scan::glyph()));

        // Given the rows, it is drawn, whole.
        let tall = rendered(&screen, styles(), FLOOR_WIDTH, 50);
        assert!(tall.contains("drawn below the code"), "{tall}");
        assert_eq!(
            tall.lines()
                .filter(|line| line.contains(scan::glyph()))
                .count(),
            17
        );
        assert!(
            tall.lines().count() <= 50,
            "the whole body still fits the rows it was given"
        );
    }

    #[test]
    fn q_cycles_and_hides_and_is_inert_until_a_code_exists() {
        let mut screen = Screen::default();
        screen.cycle_scan();
        assert_eq!(
            screen.scan_mode(),
            ScanMode::Auto,
            "there is nothing to encode yet"
        );

        let mut screen = awaiting();
        for expected in [ScanMode::Below, ScanMode::Hidden, ScanMode::Auto] {
            screen.cycle_scan();
            assert_eq!(screen.scan_mode(), expected);
        }
        screen.cycle_scan();
        screen.cycle_scan();
        let hidden = flat(&screen, styles(), REFERENCE_WIDTH, 35);
        assert!(hidden.contains("hidden"), "{hidden}");
        assert!(!hidden.contains(scan::glyph()));
    }

    #[test]
    fn the_scan_code_is_withheld_without_colour_and_says_why() {
        let text = flat(
            &awaiting(),
            Styles::new(Theme::Dark, ColorMode::NoColor),
            REFERENCE_WIDTH,
            35,
        );
        assert!(text.contains("NO_COLOR is in force"), "{text}");
        assert!(!text.contains(scan::glyph()));
    }

    #[test]
    fn the_scan_code_paints_its_own_field_rather_than_inheriting_the_palette() {
        for theme in [Theme::Dark, Theme::Light] {
            let painted: Vec<Style> = awaiting()
                .body(Styles::new(theme, ColorMode::Color), REFERENCE_WIDTH, 35)
                .iter()
                .flat_map(|line| line.spans.clone())
                .filter(|span| span.content == scan::glyph())
                .map(|span| span.style)
                .collect();
            assert!(!painted.is_empty(), "{theme:?}");
            for style in painted {
                assert!(
                    matches!(style.fg, Some(MODULE) | Some(FIELD)),
                    "{theme:?}: {style:?}"
                );
                assert!(
                    matches!(style.bg, Some(MODULE) | Some(FIELD)),
                    "{theme:?}: {style:?}"
                );
            }
        }
    }

    #[test]
    fn every_state_fits_the_floor_whole() {
        // No screen requires more than the floor to be usable, and for this one
        // "usable" includes the statement that nothing is stored. If any state
        // needs a row it has not got, the frame withholds the tail of it, and
        // the tail is where that statement is.
        for screen in every_screen() {
            let lines = screen.body(styles(), FLOOR_WIDTH, FLOOR_BODY);
            assert!(
                lines.len() <= FLOOR_BODY as usize,
                "{} needs {} rows and the floor has {FLOOR_BODY}",
                screen.state().heading(),
                lines.len()
            );
            let text = flat(&screen, styles(), FLOOR_WIDTH, FLOOR_BODY);
            assert!(
                text.contains("No credential of any kind is stored"),
                "{text}"
            );
            for permission in identity::bound().grant {
                assert!(
                    text.contains(permission.name),
                    "{} is missing",
                    permission.name
                );
            }
        }
    }

    /// A screen holding a given address.
    fn screen_at(verification_uri: &str) -> Screen {
        let mut screen = Screen::default();
        screen.state_mut().code_issued(&Issued {
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: verification_uri.to_owned(),
            expires_in: std::time::Duration::from_secs(900),
            interval: std::time::Duration::from_secs(5),
        });
        screen
    }

    #[test]
    fn an_address_the_server_chose_is_printed_and_never_encoded() {
        // The regression: a well-formed https host is still a destination
        // somebody else picked, and a scan code is followed without being read.
        // Looking like a link was never the test; being where airlock asked is.
        for hostile in [
            "https://attacker.example",
            "https://attacker.example/login/device",
            "https://github.com.attacker.example/login/device",
            "https://github.com@attacker.example/login/device",
            "http://github.com/login/device",
            "javascript:alert(1)",
        ] {
            let screen = screen_at(hostile);
            let text = flat(&screen, styles(), REFERENCE_WIDTH, 35);
            assert!(
                text.contains("is not at https://github.com, which is where airlock asked"),
                "{hostile}: {text}"
            );
            assert!(
                !rendered(&screen, styles(), REFERENCE_WIDTH, 35).contains(scan::glyph()),
                "{hostile}: a scanner was pointed somewhere the response chose"
            );
            // The address itself is still printed: reading it is the
            // operator's, and hiding it would not help them.
            assert!(text.contains(hostile), "{hostile}: {text}");
        }
    }

    #[test]
    fn an_address_at_the_origin_airlock_asked_is_still_encoded() {
        // The other half: the check must not have closed the door on the real
        // address, including a path GitHub is free to change. The longer of the
        // two needs a bigger symbol, which is why the layout measures what it is
        // about to draw rather than trusting the budget.
        for expected in [
            "https://github.com/login/device",
            "https://github.com/login/device/somewhere-else",
        ] {
            let code = ScanCode::encode(expected).expect("the address encodes");
            let drawn = rendered(&screen_at(expected), styles(), 160, 40);
            let rows: Vec<&str> = drawn
                .lines()
                .filter(|line| line.contains(scan::glyph()))
                .collect();
            assert_eq!(rows.len(), code.lines(), "{expected}: all of it, or none");
            for row in rows {
                assert_eq!(
                    row.matches(scan::glyph()).count(),
                    code.columns(),
                    "{expected}: a row was cut"
                );
            }
        }
    }

    #[test]
    fn a_wider_symbol_still_fits_the_terminal_it_is_drawn_in() {
        // The symbol grows with the address. If the layout kept assuming the
        // expected one's width, a longer address would push every row it sits
        // beside past the edge — the clipping the withholding rule exists to
        // prevent, arriving by the back door.
        let long = "https://github.com/login/device/a-rather-longer-path-than-today";
        for width in [REFERENCE_WIDTH, 160, FLOOR_WIDTH] {
            for line in screen_at(long).body(styles(), width, 40) {
                let printed: usize = line
                    .spans
                    .iter()
                    .map(|span| span.content.chars().count())
                    .sum();
                assert!(printed <= width as usize, "at {width}: {printed} columns");
            }
        }
    }

    #[test]
    fn a_hostile_server_cannot_put_a_control_character_on_the_terminal() {
        // The whole rendering, cell by cell, for the two states that carry
        // server-supplied text — given a server that answers with terminal
        // instructions rather than with a code and a cause. The scan code path
        // is included, because the address it encodes is server-supplied too.
        let mut screen = Screen::default();
        screen.state_mut().code_issued(&Issued {
            user_code: "WD\u{1b}[2J\u{202e}JB".to_owned(),
            verification_uri: "https://github.com\u{1b}]0;pwned\u{7}/login/device".to_owned(),
            expires_in: std::time::Duration::from_secs(900),
            interval: std::time::Duration::from_secs(5),
        });
        let mut interrupted = screen.clone();
        interrupted
            .state_mut()
            .interrupted("\u{1b}[1;1Hno credential stored\u{1b}[2J");

        for candidate in [screen, interrupted] {
            for mode in [ScanMode::Auto, ScanMode::Below, ScanMode::Hidden] {
                let mut candidate = candidate.clone();
                while candidate.scan_mode() != mode {
                    candidate.cycle_scan();
                }
                for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
                    for line in candidate.body(styles(), width, 60) {
                        for span in &line.spans {
                            assert!(
                                !span.content.chars().any(char::is_control),
                                "a control character reached a cell: {:?}",
                                span.content
                            );
                            for forbidden in ['\u{202e}', '\u{200e}', '\u{2066}'] {
                                assert!(
                                    !span.content.contains(forbidden),
                                    "a bidirectional control reached a cell: {:?}",
                                    span.content
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn no_line_overflows_the_terminal_at_either_size() {
        for screen in every_screen() {
            for (width, height) in [(REFERENCE_WIDTH, 35), (FLOOR_WIDTH, FLOOR_BODY)] {
                for line in screen.body(styles(), width, height) {
                    let printed: usize = line
                        .spans
                        .iter()
                        .map(|span| span.content.chars().count())
                        .sum();
                    assert!(
                        printed <= width as usize,
                        "{} at {width}: {printed} columns",
                        screen.state().heading()
                    );
                }
            }
        }
    }

    #[test]
    fn a_reissue_keeps_the_screen_rather_than_restarting_the_session() {
        let mut screen = awaiting();
        screen.cycle_scan();
        screen.state_mut().expired();
        screen.state_mut().reissue(Reason::Asked);
        assert_eq!(
            screen.scan_mode(),
            ScanMode::Below,
            "nothing else on the screen is lost"
        );
        let text = flat(&screen, styles(), REFERENCE_WIDTH, 35);
        assert!(text.contains("asking GitHub for a new code"), "{text}");
    }
}
