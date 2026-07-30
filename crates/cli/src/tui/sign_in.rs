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

use super::chrome::wrap;
use super::theme::{Role, Styles};

/// The column the field values start in.
const LABEL_WIDTH: usize = 14;

/// The columns a scan code occupies, quiet zone included.
const SCAN_COLUMNS: usize = 33;

/// The blank columns between the text column and a scan code beside it.
const SCAN_GUTTER: usize = 2;

/// The narrowest text column worth keeping beside a scan code.
const TEXT_MINIMUM: usize = 60;

/// The width at which the scan code sits alongside the device code.
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
    /// The terminal is too narrow for it to sit alongside.
    TooNarrow(usize),
    /// The terminal is too short for all of it.
    TooShort(usize),
    /// Colour is off, and the code paints its own field in colour.
    NoColor,
    /// The address would not encode. It always does; this is the arm that
    /// keeps a change of address from taking the screen down.
    Unencodable,
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
            Self::TooNarrow(width) if tight => {
                format!("withheld: needs {ALONGSIDE_WIDTH} columns, this has {width}.")
            }
            Self::TooNarrow(width) => format!(
                "withheld: it needs {SCAN_COLUMNS} columns beside a readable text column, \
                 which is {ALONGSIDE_WIDTH} in all, and this terminal has {width}. A \
                 partly drawn scan code is never rendered, because a code that cannot be \
                 scanned is worse than an address you type."
            ),
            Self::TooShort(rows) if tight => {
                format!("withheld: it needs {} rows and has {rows}.", lines_needed())
            }
            Self::TooShort(rows) => format!(
                "withheld: it needs {} rows and this screen has {rows} left to give it. \
                 It is withheld rather than cut off, for the same reason.",
                lines_needed()
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
            Self::Unencodable => {
                "withheld: the address did not encode. Type it from the line above.".to_owned()
            }
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

/// How many text rows a scan code needs.
fn lines_needed() -> usize {
    SCAN_COLUMNS.div_ceil(2)
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
        let text_width = match placement {
            Ok(Placement::Alongside) => width.saturating_sub(SCAN_COLUMNS + SCAN_GUTTER),
            _ => width,
        };
        let mut lines = self.text(styles, text_width, density, &placement);
        match placement {
            Ok(Placement::Alongside) => self.overlay(styles, &mut lines, text_width + SCAN_GUTTER),
            Ok(Placement::Below) => {
                lines.push(Line::default());
                lines.extend(self.scan_lines(styles));
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
        if self.encoded().is_none() {
            return Err(Withheld::Unencodable);
        }
        match self.scan {
            ScanMode::Below => {
                // Measured against the text as it will actually be drawn, at
                // the full width, with one blank row between the two.
                let text = self
                    .text(styles, width, density(width), &Err(Withheld::Hidden))
                    .len();
                let room = height.saturating_sub(text + 1);
                if room < lines_needed() {
                    return Err(Withheld::TooShort(room));
                }
                Ok(Placement::Below)
            }
            _ if height < lines_needed() => Err(Withheld::TooShort(height)),
            _ if width >= ALONGSIDE_WIDTH => Ok(Placement::Alongside),
            _ => Err(Withheld::TooNarrow(width)),
        }
    }

    fn encoded(&self) -> Option<ScanCode> {
        let address = &self.state.code()?.verification_uri;
        ScanCode::encode(address).ok()
    }

    /// Paint the scan code into the right-hand columns of the lines already
    /// built, padding each to the column it starts in.
    fn overlay(&self, styles: Styles, lines: &mut Vec<Line<'static>>, column: usize) {
        let scan = self.scan_lines(styles);
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

    fn scan_lines(&self, styles: Styles) -> Vec<Line<'static>> {
        let Some(code) = self.encoded() else {
            return Vec::new();
        };
        let _ = styles;
        (0..code.lines())
            .map(|line| {
                Line::from(
                    code.row(line)
                        .into_iter()
                        .map(|cell| {
                            // Both halves are painted explicitly. Neither
                            // inherits the terminal background, which is what
                            // makes the code scan identically on both palettes.
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
        lines.extend(self.field(styles, "remedy", &self.state.remedy(density), width));
        if density == Density::Full {
            lines.push(Line::default());
        }
        lines.extend(self.credential(styles, width, density));
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
        lines.extend(self.field(styles, "address", &address, width));
        lines.extend(self.field(
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
                lines.extend(self.field(
                    styles,
                    "polling",
                    &format!("attempt {poll}, every {}", humanize(*interval)),
                    width,
                ));
                lines.extend(self.field(
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
                lines.extend(self.field(
                    styles,
                    "polling",
                    &format!("attempt {poll} failed, retrying in {}", humanize(*backoff)),
                    width,
                ));
                if code.is_some() {
                    lines.extend(self.field(
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
            Ok(Placement::Alongside) => "drawn beside the code. It encodes the address only, \
                 because the device flow offers no address that carries the code."
                .to_owned(),
            Ok(Placement::Below) => "drawn below the code. It encodes the address only.".to_owned(),
            Err(reason) => reason.statement(density),
        };
        // At the floor the offer rides on the same line rather than taking one
        // of its own, because a row here is a row the credential statement
        // needs.
        match density {
            Density::Full => {
                lines.extend(self.field(styles, "scan code", &scan, width));
                if self.state.has_code() {
                    lines.extend(self.field(styles, "", self.scan.offer(density), width));
                }
            }
            Density::Tight => {
                let offer = if self.state.has_code() {
                    format!(" {}.", self.scan.offer(density))
                } else {
                    String::new()
                };
                lines.extend(self.field(styles, "scan code", &format!("{scan}{offer}"), width));
            }
        }
        lines
    }

    fn credential(&self, styles: Styles, width: usize, density: Density) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from(Span::styled(
            "CREDENTIAL",
            styles.bold(Role::Text),
        ))];
        lines.extend(self.field(styles, "source", &self.identity.source(), width));
        lines.extend(self.field(styles, "grant", &self.grant(density), width));
        lines.extend(self.field(
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
    /// screen's answer to what this credential can do and a summary of it is
    /// not that answer. What the tight reading drops is the repetition: the
    /// permissions are gathered under their level instead of each carrying it.
    fn grant(&self, density: Density) -> String {
        if density == Density::Full {
            return self
                .identity
                .grant
                .iter()
                .map(|permission| format!("{} {}", permission.name, permission.level))
                .collect::<Vec<_>>()
                .join(" \u{b7} ");
        }
        let mut levels: Vec<(&str, Vec<&str>)> = Vec::new();
        for permission in self.identity.grant {
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

    fn field(&self, styles: Styles, label: &str, text: &str, width: usize) -> Vec<Line<'static>> {
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
}

/// Where a scan code was drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Beside the device code.
    Alongside,
    /// Under it.
    Below,
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
    use crate::admin::sign_in::Reason;
    use crate::device::DeviceCode;
    use crate::tui::chrome::{FLOOR_WIDTH, REFERENCE_WIDTH};
    use crate::tui::theme::{ColorMode, Theme};

    /// The rows the frame leaves the body at the floor: 24 less the header,
    /// the keymap, and the status line.
    const FLOOR_BODY: u16 = 21;

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn issued() -> DeviceCode {
        DeviceCode {
            device_code: "never-shown".to_owned(),
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: 900,
            interval: 5,
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
