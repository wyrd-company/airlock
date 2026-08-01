//! Palettes, and the rule that colour never carries meaning on its own.
//!
//! Two palettes carry the same information; neither is a degraded form of the
//! other. Under `NO_COLOR` every style collapses to the terminal's own
//! foreground and background, and nothing is lost, because every distinction
//! the interface draws is also carried by glyph, lane position, bar length, or
//! heading.

use ratatui::style::{Color, Modifier, Style};

use airlock_core::findings::Status;

/// Which palette is in force. Switched at runtime with `t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    /// The dark palette.
    Dark,
    /// The light palette.
    Light,
}

impl Theme {
    /// The other palette.
    #[must_use]
    pub const fn toggled(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }

    /// The name the chrome prints beside the theme key.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }
}

/// Whether colour may be emitted at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// The palette is drawn.
    Color,
    /// No colour is emitted, per <https://no-color.org>.
    NoColor,
}

impl ColorMode {
    /// Read the mode from the environment.
    ///
    /// `NO_COLOR` set to any value, including the empty string, disables
    /// colour. That is what the convention specifies, and treating an empty
    /// value as unset would make the variable unusable from a shell that
    /// cannot easily export a non-empty one.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var_os("NO_COLOR") {
            Some(_) => Self::NoColor,
            None => Self::Color,
        }
    }
}

/// A named role in the interface, resolved to a colour by the palette.
///
/// Roles are semantic rather than chromatic so that a screen never names a
/// colour, and so that `NO_COLOR` has exactly one place to intervene.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Body text.
    Text,
    /// Secondary text: labels, glosses, counts.
    Dim,
    /// Tertiary text: inactive keys, rules, absent content.
    Faint,
    /// A border or a horizontal rule.
    Border,
    /// A border that should read as a division rather than a hairline.
    BorderStrong,
    /// The interface accent: headings and the focused element.
    Accent,
    /// The chrome background, behind the header and the footer.
    Chrome,
    /// The status-line background.
    Bar,
    /// The colour that confirms a status. Never the only carrier of it.
    Status(Status),
}

/// A resolved palette plus the colour mode, and the only source of `Style`.
#[derive(Debug, Clone, Copy)]
pub struct Styles {
    theme: Theme,
    mode: ColorMode,
}

/// The dark palette, from the design export.
struct Palette {
    bg: Color,
    chrome: Color,
    bar: Color,
    fg: Color,
    dim: Color,
    faint: Color,
    border: Color,
    border_strong: Color,
    accent: Color,
    pass: Color,
    fail: Color,
    manual: Color,
    suppressed: Color,
    skipped: Color,
    unimplemented: Color,
    inconclusive: Color,
    admin_only: Color,
    error: Color,
}

const DARK: Palette = Palette {
    bg: Color::Rgb(0x0B, 0x0D, 0x10),
    chrome: Color::Rgb(0x14, 0x18, 0x1D),
    bar: Color::Rgb(0x10, 0x14, 0x19),
    fg: Color::Rgb(0xCB, 0xD3, 0xDD),
    dim: Color::Rgb(0x79, 0x83, 0x8F),
    faint: Color::Rgb(0x4C, 0x56, 0x61),
    border: Color::Rgb(0x23, 0x2A, 0x33),
    border_strong: Color::Rgb(0x39, 0x43, 0x4F),
    accent: Color::Rgb(0xE8, 0xB8, 0x4B),
    pass: Color::Rgb(0x5F, 0xB9, 0x8A),
    fail: Color::Rgb(0xE0, 0x5C, 0x58),
    manual: Color::Rgb(0x6C, 0x9B, 0xE0),
    suppressed: Color::Rgb(0xA8, 0x86, 0xD8),
    skipped: Color::Rgb(0x77, 0x81, 0x8C),
    unimplemented: Color::Rgb(0xB7, 0x9A, 0x5A),
    inconclusive: Color::Rgb(0xD9, 0xA4, 0x41),
    // The design export predates the admin-only status. It is given a hue no
    // other status uses, in a family the palette does not otherwise occupy, so
    // it cannot be mistaken at a glance for one of the two undecided statuses
    // that do gate. Its lane and glyph carry the meaning; this only confirms.
    admin_only: Color::Rgb(0x4F, 0xA5, 0xA5),
    error: Color::Rgb(0xE8, 0x84, 0x3A),
};

const LIGHT: Palette = Palette {
    bg: Color::Rgb(0xF6, 0xF3, 0xEC),
    chrome: Color::Rgb(0xED, 0xE8, 0xDD),
    bar: Color::Rgb(0xEF, 0xEA, 0xE0),
    fg: Color::Rgb(0x2B, 0x28, 0x22),
    dim: Color::Rgb(0x6E, 0x67, 0x59),
    faint: Color::Rgb(0x95, 0x8C, 0x78),
    border: Color::Rgb(0xD8, 0xD1, 0xC2),
    border_strong: Color::Rgb(0xB9, 0xAF, 0x9B),
    accent: Color::Rgb(0x9A, 0x6B, 0x12),
    pass: Color::Rgb(0x2E, 0x7D, 0x52),
    fail: Color::Rgb(0xB0, 0x30, 0x28),
    manual: Color::Rgb(0x2F, 0x5D, 0xA8),
    suppressed: Color::Rgb(0x6C, 0x46, 0xA0),
    skipped: Color::Rgb(0x7C, 0x75, 0x66),
    unimplemented: Color::Rgb(0x8A, 0x6E, 0x22),
    inconclusive: Color::Rgb(0x9A, 0x6B, 0x12),
    admin_only: Color::Rgb(0x1F, 0x6B, 0x6B),
    error: Color::Rgb(0xB0, 0x58, 0x12),
};

impl Styles {
    /// Build the style source for a palette and a colour mode.
    #[must_use]
    pub const fn new(theme: Theme, mode: ColorMode) -> Self {
        Self { theme, mode }
    }

    /// The palette in force.
    #[must_use]
    pub const fn theme(self) -> Theme {
        self.theme
    }

    /// Whether colour is being emitted.
    #[must_use]
    pub const fn colored(self) -> bool {
        matches!(self.mode, ColorMode::Color)
    }

    const fn palette(self) -> &'static Palette {
        match self.theme {
            Theme::Dark => &DARK,
            Theme::Light => &LIGHT,
        }
    }

    /// The style for a role.
    ///
    /// Under `NO_COLOR` this is `Style::default()` for every role. Callers add
    /// modifiers on top; emphasis is not colour and survives.
    #[must_use]
    pub fn of(self, role: Role) -> Style {
        if !self.colored() {
            return Style::default();
        }
        let p = self.palette();
        let fg = match role {
            Role::Text => p.fg,
            Role::Dim => p.dim,
            Role::Faint => p.faint,
            Role::Border => p.border,
            Role::BorderStrong => p.border_strong,
            Role::Accent => p.accent,
            Role::Chrome => return Style::default().fg(p.fg).bg(p.chrome),
            Role::Bar => return Style::default().fg(p.dim).bg(p.bar),
            Role::Status(status) => match status {
                Status::Pass => p.pass,
                Status::Fail => p.fail,
                Status::Manual => p.manual,
                Status::Suppressed => p.suppressed,
                Status::Skipped => p.skipped,
                Status::Unimplemented => p.unimplemented,
                Status::Inconclusive => p.inconclusive,
                Status::AdminOnly => p.admin_only,
                Status::Error => p.error,
            },
        };
        Style::default().fg(fg)
    }

    /// The style for a role, emphasised.
    #[must_use]
    pub fn bold(self, role: Role) -> Style {
        self.of(role).add_modifier(Modifier::BOLD)
    }

    /// The whole-screen background.
    #[must_use]
    pub fn canvas(self) -> Style {
        if !self.colored() {
            return Style::default();
        }
        let p = self.palette();
        Style::default().fg(p.fg).bg(p.bg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_theme_toggles_and_names_itself() {
        assert_eq!(Theme::Dark.toggled(), Theme::Light);
        assert_eq!(Theme::Light.toggled(), Theme::Dark);
        assert_eq!(Theme::Dark.toggled().toggled(), Theme::Dark);
        assert_ne!(Theme::Dark.name(), Theme::Light.name());
    }

    #[test]
    fn no_color_flattens_every_role_in_both_themes() {
        for theme in [Theme::Dark, Theme::Light] {
            let styles = Styles::new(theme, ColorMode::NoColor);
            assert_eq!(styles.canvas(), Style::default());
            for role in roles() {
                assert_eq!(styles.of(role), Style::default(), "{role:?}");
            }
        }
    }

    #[test]
    fn emphasis_survives_no_color() {
        let styles = Styles::new(Theme::Dark, ColorMode::NoColor);
        assert_eq!(
            styles.bold(Role::Text),
            Style::default().add_modifier(Modifier::BOLD)
        );
    }

    #[test]
    fn every_status_has_its_own_colour_in_both_themes() {
        for theme in [Theme::Dark, Theme::Light] {
            let styles = Styles::new(theme, ColorMode::Color);
            let mut seen = Vec::new();
            for status in Status::ALL {
                let style = styles.of(Role::Status(*status));
                assert!(!seen.contains(&style), "{status:?} repeats a colour");
                seen.push(style);
            }
        }
    }

    #[test]
    fn the_two_palettes_never_agree_on_a_role() {
        for role in roles() {
            let dark = Styles::new(Theme::Dark, ColorMode::Color).of(role);
            let light = Styles::new(Theme::Light, ColorMode::Color).of(role);
            assert_ne!(dark, light, "{role:?}");
        }
    }

    fn roles() -> Vec<Role> {
        let mut roles = vec![
            Role::Text,
            Role::Dim,
            Role::Faint,
            Role::Border,
            Role::BorderStrong,
            Role::Accent,
            Role::Chrome,
            Role::Bar,
        ];
        roles.extend(Status::ALL.iter().copied().map(Role::Status));
        roles
    }
}
