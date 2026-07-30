//! The frame every screen sits in: header, breadcrumb, keymap footer, status
//! line, and the rule that decides how the frame degrades.
//!
//! The reference layout is 120 columns by 40 rows. Every screen also renders
//! within a floor of 80 by 24, and no screen requires more than the floor to be
//! usable. Between the two, the frame gives its rows back to the body rather
//! than to itself, and text is elided rather than clipped.

use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use super::screen::{Key, Screen, THEME_KEY, UNIVERSAL_KEYS};
use super::theme::{Role, Styles};

/// The reference width.
pub const REFERENCE_WIDTH: u16 = 120;
/// The reference height. The frame keys its own degradation off
/// [`RULES_NEED_HEIGHT`]; this is the other half of the size the specification
/// names, and it is what the snapshot suite renders at.
#[cfg_attr(not(test), allow(dead_code))]
pub const REFERENCE_HEIGHT: u16 = 40;
/// The narrowest terminal every screen must remain usable in.
pub const FLOOR_WIDTH: u16 = 80;
/// The shortest terminal every screen must remain usable in.
pub const FLOOR_HEIGHT: u16 = 24;

/// Below this height the frame drops its horizontal rules, because a row is
/// worth more to the body than a hairline is to the chrome.
const RULES_NEED_HEIGHT: u16 = 30;

/// The mark that says text was elided.
const ELLIPSIS: char = '\u{2026}';

/// The separator between breadcrumb segments.
const CRUMB_SEPARATOR: &str = " \u{203a} ";

/// The separator between facts on one chrome line.
const FACT_SEPARATOR: &str = " \u{b7} ";

/// Below this width the header drops `tty required`, which the status line on
/// every screen already carries, and gives the room to the breadcrumb.
const FULL_FACTS_NEED_WIDTH: u16 = 100;

/// The theme name is padded to the longest one so that pressing `t` repaints
/// the header rather than reflowing it. Text that moves when a palette changes
/// reads as a layout bug even when it is not.
const THEME_NAME_WIDTH: usize = 5;

/// What stands in the header's key slot while the open state has captured it.
///
/// One column, which is what the key it replaces occupies, so the facts group
/// is the same width whether or not the key is live. The header holds its
/// geometry through a focus change for the same reason it holds it through a
/// palette change: text that moves reads as a fault even when it is not, and
/// here it would move on every keystroke that opens or closes a filter.
///
/// A mark rather than a blank. A slot left empty reads as a header that forgot
/// to print something; a mark reads as a key that is not available, which is
/// what it is. It survives `NO_COLOR` because it is a glyph and not a style.
const KEY_WITHDRAWN: &str = "\u{2014}";

/// Where each part of the frame is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// The header: program identity, breadcrumb, and session facts.
    pub header: Rect,
    /// The rule under the header, where there is height for it.
    pub rule_top: Option<Rect>,
    /// Everything the screen itself draws.
    pub body: Rect,
    /// The rule over the footer, where there is height for it.
    pub rule_bottom: Option<Rect>,
    /// The keymap.
    pub keymap: Rect,
    /// The status line.
    pub status: Rect,
}

/// Whether the terminal is large enough to draw a screen at all.
#[must_use]
pub const fn fits(area: Rect) -> bool {
    area.width >= FLOOR_WIDTH && area.height >= FLOOR_HEIGHT
}

/// Divide the terminal into the frame.
///
/// The caller has already established that the area [`fits`].
#[must_use]
pub fn layout(area: Rect) -> Frame {
    let rules = area.height >= RULES_NEED_HEIGHT;
    let row = |y: u16| Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    let top = area.y;
    let bottom = area.y + area.height;
    let header = row(top);
    let rule_top = rules.then(|| row(top + 1));
    let status = row(bottom - 1);
    let keymap = row(bottom - 2);
    let rule_bottom = rules.then(|| row(bottom - 3));
    let body_top = top + 1 + u16::from(rules);
    let body_bottom = bottom - 2 - u16::from(rules);
    Frame {
        header,
        rule_top,
        body: Rect {
            x: area.x,
            y: body_top,
            width: area.width,
            height: body_bottom.saturating_sub(body_top),
        },
        rule_bottom,
        keymap,
        status,
    }
}

/// The breadcrumb for a screen: the path taken to reach it.
///
/// The shell has observed nothing, so the trail is the screens themselves. A
/// breadcrumb that named a repository the session has not selected would be a
/// shape rather than a value, and the interface prints only values.
#[must_use]
pub fn breadcrumb(screen: Screen) -> String {
    let mut trail = vec![screen.label()];
    let mut current = screen;
    while let Some(previous) = current.back() {
        trail.push(previous.label());
        current = previous;
    }
    trail.reverse();
    trail.join(CRUMB_SEPARATOR)
}

/// The header line.
///
/// The right-hand group states the session facts that hold whatever screen is
/// open. This shell holds no credential, and it says exactly that rather than
/// printing a grant or an expiry it does not have.
///
/// The keys live in the open state are passed in, and the header reads its own
/// key slot out of them rather than assuming the toggle is available. The
/// header and the footer are then two renderings of one fact and cannot
/// disagree: whatever captures a key removes it from both at once.
#[must_use]
pub fn header_line(
    screen: Screen,
    version: &str,
    styles: Styles,
    width: u16,
    keys: &[Key],
) -> Line<'static> {
    let identity = format!("AIRLOCK {version}");
    let theme = format!(
        "theme {} \u{b7} {:<THEME_NAME_WIDTH$}",
        theme_slot(keys),
        styles.theme().name()
    );
    let facts = if width >= FULL_FACTS_NEED_WIDTH {
        format!("no credential stored{FACT_SEPARATOR}tty required{FACT_SEPARATOR}{theme}")
    } else {
        format!("no credential stored{FACT_SEPARATOR}{theme}")
    };
    let width = width as usize;
    let identity_width = identity.chars().count();
    let facts_width = facts.chars().count();

    let chrome = styles.of(Role::Chrome);
    let mut spans = vec![
        Span::styled(identity, styles.bold(Role::Accent).patch(chrome)),
        Span::styled("  ", chrome),
    ];
    // The identity and the session facts are never elided: both are short and
    // both are load-bearing. The breadcrumb gives up its width first.
    let spent = identity_width + 2 + facts_width + 2;
    let crumb_room = width.saturating_sub(spent);
    let crumb = elide_start(&breadcrumb(screen), crumb_room);
    let crumb_width = crumb.chars().count();
    spans.push(Span::styled(crumb, styles.of(Role::Dim).patch(chrome)));
    let gap = width.saturating_sub(identity_width + 2 + crumb_width + facts_width);
    spans.push(Span::styled(" ".repeat(gap), chrome));
    spans.push(Span::styled(facts, styles.of(Role::Faint).patch(chrome)));
    Line::from(spans)
}

/// The header's key slot: the theme key, or the mark that stands where it is
/// not available.
///
/// Both are one column wide, so which one is drawn never moves anything.
fn theme_slot(keys: &[Key]) -> &'static str {
    if keys.contains(&THEME_KEY) {
        THEME_KEY.key
    } else {
        KEY_WITHDRAWN
    }
}

/// A horizontal rule across the frame.
#[must_use]
pub fn rule_line(styles: Styles, width: u16) -> Line<'static> {
    Line::from(Span::styled(
        "\u{2500}".repeat(width as usize),
        styles.of(Role::BorderStrong),
    ))
}

/// The keys a screen prints when no state has captured them: its own, then the
/// two that are otherwise always live.
#[must_use]
pub fn keys_of(screen: Screen) -> Vec<Key> {
    screen
        .keys()
        .iter()
        .chain(UNIVERSAL_KEYS.iter())
        .copied()
        .collect()
}

/// The keymap footer: the keys live in this state, and only those.
///
/// The caller supplies them rather than the footer reading them off the screen,
/// because which keys are live is a property of the state and not of the
/// screen. A footer that advertised a key the open text input has captured
/// would be a footer describing a different program.
///
/// Entries are dropped from the end rather than clipped mid-word, and the line
/// says how many it dropped, because a keymap that silently omits a key is
/// worse than one that admits it.
#[must_use]
pub fn keymap_line(entries: &[Key], styles: Styles, width: u16) -> Line<'static> {
    let entries: Vec<_> = entries.iter().collect();
    let width = width as usize;

    let mut spans = Vec::new();
    let mut used = 0usize;
    let mut shown = 0usize;
    for entry in &entries {
        let separator = if shown == 0 { "" } else { FACT_SEPARATOR };
        let cost = separator.chars().count()
            + entry.key.chars().count()
            + 1
            + entry.action.chars().count();
        let remaining = entries.len() - shown - 1;
        let tail = if remaining == 0 {
            0
        } else {
            overflow_note(remaining).chars().count() + FACT_SEPARATOR.chars().count()
        };
        if used + cost + tail > width {
            break;
        }
        if !separator.is_empty() {
            spans.push(Span::styled(separator, styles.of(Role::Faint)));
        }
        spans.push(Span::styled(entry.key, styles.bold(Role::Accent)));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(entry.action, styles.of(Role::Dim)));
        used += cost;
        shown += 1;
    }
    let dropped = entries.len() - shown;
    if dropped > 0 {
        spans.push(Span::styled(FACT_SEPARATOR, styles.of(Role::Faint)));
        spans.push(Span::styled(
            overflow_note(dropped),
            styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
        ));
    }
    Line::from(spans)
}

fn overflow_note(dropped: usize) -> String {
    format!("{dropped} more{ELLIPSIS}")
}

/// The status line a screen carries when it has nothing of its own to say.
///
/// Sign-in's is fixed by the specification. The rest state what the shell
/// actually knows, which is that no observation has been made yet. A screen
/// that does know something states it and passes the text to [`status_line`].
#[must_use]
pub fn status_text(screen: Screen) -> String {
    match screen {
        Screen::SignIn => format!("no credential on disk{FACT_SEPARATOR}tty required"),
        _ => format!(
            "no repository observed{FACT_SEPARATOR}\
             this shell renders the frame only{FACT_SEPARATOR}tty required"
        ),
    }
}

/// The status line, filling its row.
#[must_use]
pub fn status_line(text: &str, styles: Styles, width: u16) -> Line<'static> {
    let text = fit(text, width as usize);
    let padding = (width as usize).saturating_sub(text.chars().count());
    Line::from(vec![
        Span::styled(text, styles.of(Role::Bar)),
        Span::styled(" ".repeat(padding), styles.of(Role::Bar)),
    ])
}

/// The message shown when the terminal is smaller than the floor.
///
/// Withheld rather than clipped: a frame drawn into a terminal that cannot hold
/// it would misreport lane positions, and a lane read in the wrong column is
/// worse than no reading at all.
#[must_use]
pub fn undersized_message(area: Rect) -> Vec<String> {
    vec![
        "TERMINAL TOO SMALL".to_string(),
        String::new(),
        format!(
            "airlock needs {FLOOR_WIDTH} columns by {FLOOR_HEIGHT} rows. \
             This terminal is {} by {}.",
            area.width, area.height
        ),
        String::new(),
        "Nothing is drawn at this size rather than drawn wrongly: the status \
         lanes are column positions, and a lane in the wrong column is read as \
         the wrong lane."
            .to_string(),
        String::new(),
        "Resize the terminal, or press ctrl-c to exit.".to_string(),
    ]
}

/// Truncate to `width` columns, marking that something was dropped.
#[must_use]
pub fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push(ELLIPSIS);
    out
}

/// Break text into lines of at most `width` columns, on word boundaries.
///
/// A word longer than the line is broken rather than allowed to overflow: an
/// overflowing line would push a lane out of its column, and a lane read in the
/// wrong column is read as the wrong lane.
#[must_use]
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let mut word = word;
        while word.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let head: String = word.chars().take(width).collect();
            let taken = head.len();
            lines.push(head);
            word = &word[taken..];
        }
        let cost = word.chars().count() + usize::from(!current.is_empty());
        if current.chars().count() + cost > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Drop from the front rather than the back, so the most specific segment of a
/// breadcrumb survives.
#[must_use]
pub fn elide_start(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out = String::from(ELLIPSIS);
    out.extend(text.chars().skip(count - (width - 1)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::{ColorMode, Theme};

    fn area(width: u16, height: u16) -> Rect {
        Rect {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn rendered(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn the_reference_and_the_floor_both_fit() {
        assert!(fits(area(REFERENCE_WIDTH, REFERENCE_HEIGHT)));
        assert!(fits(area(FLOOR_WIDTH, FLOOR_HEIGHT)));
        assert!(!fits(area(FLOOR_WIDTH - 1, FLOOR_HEIGHT)));
        assert!(!fits(area(FLOOR_WIDTH, FLOOR_HEIGHT - 1)));
    }

    #[test]
    fn the_frame_covers_the_area_exactly_at_both_sizes() {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            let frame = layout(area(width, height));
            let mut rows: Vec<u16> = vec![frame.header.y, frame.keymap.y, frame.status.y];
            rows.extend(frame.rule_top.map(|r| r.y));
            rows.extend(frame.rule_bottom.map(|r| r.y));
            for y in frame.body.y..frame.body.y + frame.body.height {
                rows.push(y);
            }
            rows.sort_unstable();
            rows.dedup();
            assert_eq!(rows.len(), height as usize, "{width}x{height}");
            assert_eq!(rows.first().copied(), Some(0));
            assert_eq!(rows.last().copied(), Some(height - 1));
        }
    }

    #[test]
    fn the_floor_gives_its_rules_back_to_the_body() {
        let reference = layout(area(REFERENCE_WIDTH, REFERENCE_HEIGHT));
        let floor = layout(area(FLOOR_WIDTH, FLOOR_HEIGHT));
        assert!(reference.rule_top.is_some() && reference.rule_bottom.is_some());
        assert!(floor.rule_top.is_none() && floor.rule_bottom.is_none());
        assert_eq!(reference.body.height, REFERENCE_HEIGHT - 5);
        assert_eq!(floor.body.height, FLOOR_HEIGHT - 3);
    }

    #[test]
    fn the_breadcrumb_is_the_path_to_the_screen() {
        assert_eq!(breadcrumb(Screen::SignIn), "sign-in");
        assert_eq!(
            breadcrumb(Screen::Findings),
            "sign-in \u{203a} organizations \u{203a} repositories \u{203a} findings"
        );
        assert!(breadcrumb(Screen::PolicyInspector).ends_with("policy inspector"));
    }

    #[test]
    fn no_chrome_line_overflows_at_either_size() {
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            for screen in Screen::ALL {
                for line in [
                    header_line(screen, "0.0.0", styles(), width, &keys_of(screen)),
                    keymap_line(&keys_of(screen), styles(), width),
                    status_line(&status_text(screen), styles(), width),
                    rule_line(styles(), width),
                ] {
                    assert!(
                        rendered(&line).chars().count() <= width as usize,
                        "{screen:?} at {width}: {:?}",
                        rendered(&line)
                    );
                }
            }
        }
    }

    #[test]
    fn the_header_keeps_its_identity_and_its_session_facts_at_the_floor() {
        for screen in Screen::ALL {
            let text = rendered(&header_line(
                screen,
                "0.0.0",
                styles(),
                FLOOR_WIDTH,
                &keys_of(screen),
            ));
            assert!(text.starts_with("AIRLOCK 0.0.0"), "{screen:?}: {text}");
            assert!(text.contains("no credential stored"), "{screen:?}: {text}");
            assert!(
                text.trim_end().ends_with("theme t \u{b7} dark"),
                "{screen:?}: {text}"
            );
        }
    }

    #[test]
    fn the_header_does_not_reflow_when_the_palette_changes() {
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            for screen in Screen::ALL {
                let dark = rendered(&header_line(
                    screen,
                    "0.0.0",
                    styles(),
                    width,
                    &keys_of(screen),
                ));
                let light = rendered(&header_line(
                    screen,
                    "0.0.0",
                    Styles::new(Theme::Light, ColorMode::Color),
                    width,
                    &keys_of(screen),
                ));
                assert_eq!(dark.chars().count(), light.chars().count(), "{screen:?}");
                assert_eq!(
                    dark.find("theme t"),
                    light.find("theme t"),
                    "{screen:?} at {width}"
                );
            }
        }
    }

    #[test]
    fn a_captured_theme_key_leaves_the_header_and_takes_no_width_with_it() {
        // The header and the footer read the same list, so nothing can capture
        // a key from one and leave it advertised on the other.
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            let live = keys_of(Screen::Repositories);
            let captured: Vec<Key> = live
                .iter()
                .copied()
                .filter(|entry| *entry != THEME_KEY)
                .collect();

            let offered = rendered(&header_line(
                Screen::Repositories,
                "0.0.0",
                styles(),
                width,
                &live,
            ));
            let withdrawn = rendered(&header_line(
                Screen::Repositories,
                "0.0.0",
                styles(),
                width,
                &captured,
            ));

            assert!(offered.contains("theme t \u{b7} dark"), "{offered}");
            assert!(
                !withdrawn.contains("theme t"),
                "the header offered a key the open state had taken: {withdrawn}"
            );
            assert!(
                withdrawn.contains("theme \u{2014} \u{b7} dark"),
                "the slot is marked rather than left blank: {withdrawn}"
            );

            // The geometry is the whole point of a slot: same width, same
            // column, so a focus change repaints the header and never moves it.
            assert_eq!(
                offered.chars().count(),
                withdrawn.chars().count(),
                "at {width}"
            );
            assert_eq!(
                offered.find("theme"),
                withdrawn.find("theme"),
                "the facts group moved at {width}"
            );
            assert_eq!(
                offered.find("no credential stored"),
                withdrawn.find("no credential stored"),
                "the facts group moved at {width}"
            );
        }
    }

    #[test]
    fn the_breadcrumb_gives_up_its_head_first() {
        let text = rendered(&header_line(
            Screen::FindingDetail,
            "0.0.0",
            styles(),
            FLOOR_WIDTH,
            &keys_of(Screen::FindingDetail),
        ));
        assert!(text.contains("finding detail"), "{text}");
        assert!(text.contains(ELLIPSIS), "the head was dropped: {text}");
        assert!(
            !text.contains("sign-in"),
            "the head is gone, not the tail: {text}"
        );
    }

    #[test]
    fn a_keymap_that_fits_is_printed_whole() {
        let text = rendered(&keymap_line(
            &keys_of(Screen::Organizations),
            styles(),
            REFERENCE_WIDTH,
        ));
        assert!(!text.contains("more\u{2026}"), "{text}");
        for entry in Screen::Organizations
            .keys()
            .iter()
            .chain(UNIVERSAL_KEYS.iter())
        {
            assert!(
                text.contains(entry.action),
                "{} is missing: {text}",
                entry.action
            );
        }
    }

    #[test]
    fn a_dropped_key_is_admitted_rather_than_silently_omitted() {
        let narrow = rendered(&keymap_line(
            &keys_of(Screen::Findings),
            styles(),
            FLOOR_WIDTH,
        ));
        assert!(narrow.contains("more\u{2026}"), "{narrow}");
        // Narrowing never hides more quietly than widening does.
        let wide = rendered(&keymap_line(
            &keys_of(Screen::Findings),
            styles(),
            REFERENCE_WIDTH,
        ));
        assert!(
            wide.matches('\u{b7}').count() >= narrow.matches('\u{b7}').count(),
            "{wide} / {narrow}"
        );
    }

    #[test]
    fn the_universal_keys_are_printed_where_they_fit() {
        let text = rendered(&keymap_line(
            &keys_of(Screen::Organizations),
            styles(),
            REFERENCE_WIDTH,
        ));
        assert!(text.contains("ctrl-c exit"), "{text}");
        assert!(text.contains("t theme"), "{text}");
    }

    #[test]
    fn the_status_line_fills_its_row() {
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            for screen in Screen::ALL {
                assert_eq!(
                    rendered(&status_line(&status_text(screen), styles(), width))
                        .chars()
                        .count(),
                    width as usize,
                    "{screen:?}"
                );
            }
        }
    }

    #[test]
    fn sign_in_carries_the_status_line_the_specification_fixes() {
        let text = rendered(&status_line(
            &status_text(Screen::SignIn),
            styles(),
            REFERENCE_WIDTH,
        ));
        assert!(
            text.starts_with("no credential on disk \u{b7} tty required"),
            "{text}"
        );
    }

    #[test]
    fn wrapping_never_overflows_and_never_loses_a_word() {
        let text = "the condition was observed not to hold, and the run says so";
        for width in [10, 20, 40, 80] {
            let lines = wrap(text, width);
            for line in &lines {
                assert!(line.chars().count() <= width, "{line:?} at {width}");
            }
            assert_eq!(
                lines.join(" ").split_whitespace().collect::<Vec<_>>(),
                text.split_whitespace().collect::<Vec<_>>(),
                "at {width}"
            );
        }
    }

    #[test]
    fn a_word_longer_than_the_line_is_broken_rather_than_overflowed() {
        let lines = wrap("supercalifragilistic", 6);
        assert!(
            lines.iter().all(|line| line.chars().count() <= 6),
            "{lines:?}"
        );
        assert_eq!(lines.concat(), "supercalifragilistic");
    }

    #[test]
    fn wrapping_nothing_still_yields_a_line() {
        assert_eq!(wrap("", 10), vec![String::new()]);
        assert!(wrap("anything", 0).is_empty());
    }

    #[test]
    fn elision_marks_what_it_dropped() {
        assert_eq!(fit("abcdef", 6), "abcdef");
        assert_eq!(fit("abcdef", 4), "abc\u{2026}");
        assert_eq!(fit("abcdef", 0), "");
        assert_eq!(elide_start("abcdef", 6), "abcdef");
        assert_eq!(elide_start("abcdef", 4), "\u{2026}def");
        assert_eq!(elide_start("abcdef", 0), "");
    }

    #[test]
    fn the_undersized_message_states_the_floor_and_the_actual_size() {
        let message = undersized_message(area(60, 20)).join(" ");
        assert!(message.contains("80 columns by 24 rows"), "{message}");
        assert!(message.contains("60 by 20"), "{message}");
        assert!(message.contains("ctrl-c"), "{message}");
    }
}
