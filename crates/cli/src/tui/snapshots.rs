//! Snapshot proof of the rendering.
//!
//! Every case draws the whole interface into a buffer and records two grids:
//! the characters, and one legend key per cell naming the style that cell
//! carries. The second grid is what makes the palettes and `NO_COLOR`
//! reviewable — the character grid is identical across all three, which is
//! precisely the property being asserted.
//!
//! Run with `UPDATE_SNAPSHOTS=1` to rewrite the recorded files.

use std::fmt::Write as _;
#[cfg_attr(feature = "test-identity", allow(unused_imports))]
use std::path::PathBuf;

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

use crate::admin::flow::Issued;
use crate::admin::sign_in::SignIn;

use super::app::App;
use super::chrome::{FLOOR_HEIGHT, FLOOR_WIDTH, REFERENCE_HEIGHT, REFERENCE_WIDTH};
use super::screen::Screen;
use super::theme::{ColorMode, Theme};

/// The version printed in a snapshot, so a release never rewrites every file.
const VERSION: &str = "0.0.0";

/// The characters used as legend keys, in order of first appearance.
const KEYS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Case {
    name: &'static str,
    screen: Screen,
    theme: Theme,
    color: ColorMode,
    width: u16,
    height: u16,
    /// The sign-in state to open on, where the case is one of the five.
    flow: Option<SignIn>,
}

/// The device code every sign-in snapshot is drawn from.
///
/// A fixture, and the specification says as much: illustrative values are
/// shapes. What is asserted is that the interface prints what it was given.
fn fixture() -> Issued {
    Issued {
        user_code: "WDJB-MJHT".to_owned(),
        verification_uri: "https://github.com/login/device".to_owned(),
        expires_in: std::time::Duration::from_secs(900),
        interval: std::time::Duration::from_secs(5),
    }
}

/// Each of the five states, with the slug its snapshot is filed under.
fn flows() -> Vec<(&'static str, SignIn)> {
    let awaiting = || {
        let mut state = SignIn::opening();
        state.code_issued(&fixture());
        state
    };
    let mut interrupted = awaiting();
    interrupted.tick(std::time::Duration::from_secs(63));
    interrupted.interrupted("connection reset by peer");
    let mut awaited = awaiting();
    awaited.polled();
    awaited.polled();
    awaited.tick(std::time::Duration::from_secs(28));
    vec![
        ("requesting", SignIn::opening()),
        ("awaiting", awaited),
        ("expired", SignIn::Expired),
        ("denied", SignIn::Denied),
        ("interrupted", interrupted),
    ]
}

fn render(case: &Case) -> String {
    let backend = TestBackend::new(case.width, case.height);
    let mut terminal = Terminal::new(backend).expect("a test terminal");
    let app = match case.flow.clone() {
        Some(state) => App::new(VERSION, case.color)
            .at(case.screen, case.theme)
            .signing_in(state),
        None => App::new(VERSION, case.color).at(case.screen, case.theme),
    };
    terminal
        .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
        .expect("the interface draws");
    serialise(case, terminal.backend().buffer())
}

fn serialise(case: &Case, buffer: &Buffer) -> String {
    let mut legend: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut styles = String::new();
    for y in 0..case.height {
        for x in 0..case.width {
            let cell = buffer.cell((x, y)).expect("the cell is in the buffer");
            let symbol = cell.symbol();
            text.push_str(if symbol.is_empty() { " " } else { symbol });
            let described = describe(cell.fg, cell.bg, cell.modifier);
            let index = match legend.iter().position(|entry| *entry == described) {
                Some(index) => index,
                None => {
                    legend.push(described);
                    legend.len() - 1
                }
            };
            styles.push(char::from(
                *KEYS
                    .get(index)
                    .expect("the frame uses fewer styles than keys"),
            ));
        }
        text.push('\n');
        styles.push('\n');
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} \u{b7} {}x{} \u{b7} theme {} \u{b7} {}",
        case.name,
        case.width,
        case.height,
        case.theme.name(),
        match case.color {
            ColorMode::Color => "colour",
            ColorMode::NoColor => "NO_COLOR",
        }
    );
    out.push_str("--- text ---\n");
    out.push_str(&text);
    out.push_str("--- style keys ---\n");
    out.push_str(&styles);
    out.push_str("--- legend ---\n");
    for (index, entry) in legend.iter().enumerate() {
        let _ = writeln!(out, "{} {entry}", char::from(KEYS[index]));
    }
    out
}

fn describe(fg: Color, bg: Color, modifier: Modifier) -> String {
    let mut out = format!("fg={} bg={}", name(fg), name(bg));
    if !modifier.is_empty() {
        let _ = write!(out, " {modifier:?}");
    }
    out
}

fn name(color: Color) -> String {
    match color {
        Color::Reset => "reset".to_string(),
        Color::Rgb(r, g, b) => format!("#{r:02X}{g:02X}{b:02X}"),
        other => format!("{other:?}"),
    }
}

#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/tui")
        .join(format!("{name}.txt"))
}

#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn check(case: &Case) {
    let rendered = render(case);
    let path = path(case.name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().expect("the snapshot has a directory"))
            .expect("the snapshot directory is writable");
        std::fs::write(&path, &rendered).expect("the snapshot is writable");
        return;
    }
    let recorded = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "no snapshot at {}: {error}. Run with UPDATE_SNAPSHOTS=1 to record it.",
            path.display()
        )
    });
    assert_eq!(
        recorded,
        rendered,
        "{} changed. Run with UPDATE_SNAPSHOTS=1 and review the diff.",
        path.display()
    );
}

fn slug(screen: Screen) -> &'static str {
    match screen {
        Screen::SignIn => "sign-in",
        Screen::Organizations => "organizations",
        Screen::Repositories => "repositories",
        Screen::Findings => "findings",
        Screen::FindingDetail => "finding-detail",
        Screen::Remediation => "remediation",
        Screen::PolicyInspector => "policy-inspector",
        Screen::PublishingBootstrap => "publishing-bootstrap",
    }
}

fn size_slug(width: u16) -> &'static str {
    if width == REFERENCE_WIDTH {
        "120x40"
    } else {
        "80x24"
    }
}

/// Every case the suite records.
///
/// Every screen is drawn at the reference and at the floor, which is the whole
/// frame proven at both sizes. The two screens that carry the most chrome and
/// the most vocabulary — sign-in, which fixes its own status line, and
/// findings, which prints the entire status vocabulary — are additionally drawn
/// in the light palette and under `NO_COLOR` at both sizes.
#[cfg_attr(feature = "test-identity", allow(dead_code))]
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-dark", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
            });
        }
    }
    // The five sign-in states, each at both sizes. The scan code sits alongside
    // at the reference and is withheld at the floor, so the two sizes are also
    // the two halves of that rule.
    for (name, state) in flows() {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("sign-in-{name}-{}-dark", size_slug(width)).into_boxed_str(),
                ),
                screen: Screen::SignIn,
                theme: Theme::Dark,
                color: ColorMode::Color,
                width,
                height,
                flow: Some(state.clone()),
            });
        }
    }
    // The awaiting state is the one that draws a scan code, so it is the one
    // whose light palette and colourless renderings are worth recording.
    let awaiting = flows()
        .into_iter()
        .find(|(name, _)| *name == "awaiting")
        .map(|(_, state)| state)
        .expect("the awaiting state is one of the five");
    cases.push(Case {
        name: "sign-in-awaiting-120x40-light",
        screen: Screen::SignIn,
        theme: Theme::Light,
        color: ColorMode::Color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: Some(awaiting.clone()),
    });
    cases.push(Case {
        name: "sign-in-awaiting-120x40-no-color",
        screen: Screen::SignIn,
        theme: Theme::Dark,
        color: ColorMode::NoColor,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: Some(awaiting),
    });
    for screen in [Screen::SignIn, Screen::Findings] {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-light", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Light,
                color: ColorMode::Color,
                width,
                height,
                flow: None,
            });
            cases.push(Case {
                name: Box::leak(
                    format!("{}-{}-no-color", slug(screen), size_slug(width)).into_boxed_str(),
                ),
                screen,
                theme: Theme::Dark,
                color: ColorMode::NoColor,
                width,
                height,
                flow: None,
            });
        }
    }
    cases
}

/// The recorded files are of the shipped build, which names Airlock Admin on
/// the sign-in screen. A test build names Airlock Test there — deliberately, so
/// an operator can never be unsure which identity a development binary is bound
/// to — so the comparison is skipped rather than recorded twice. What that build
/// asserts instead is below.
#[cfg(not(feature = "test-identity"))]
#[test]
fn the_frame_renders_as_recorded() {
    for case in cases() {
        check(&case);
    }
}

#[cfg(feature = "test-identity")]
#[test]
fn a_test_build_names_the_test_identity_on_the_screen() {
    let rendered = characters(&Case {
        name: "comparison",
        screen: Screen::SignIn,
        theme: Theme::Dark,
        color: ColorMode::Color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: None,
    });
    assert!(rendered.contains("Airlock Test"), "{rendered}");
    assert!(!rendered.contains("Airlock Admin"), "{rendered}");
}

/// The character grid below the header, which is the whole reading.
///
/// The header row is excluded because it names the palette in force, which is
/// the one thing that legitimately differs between the two. That the header
/// does not otherwise move is asserted where the header is built.
fn reading(case: &Case) -> String {
    characters(case)
        .lines()
        .skip(1)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_reading_is_the_same_text_in_both_palettes_and_without_colour() {
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            let case = |theme, color| Case {
                name: "comparison",
                screen,
                theme,
                color,
                width,
                height,
                flow: None,
            };
            let dark = reading(&case(Theme::Dark, ColorMode::Color));
            let light = reading(&case(Theme::Light, ColorMode::Color));
            let mono = reading(&case(Theme::Dark, ColorMode::NoColor));
            assert_eq!(dark, light, "{screen:?} at {width}x{height}");
            assert_eq!(dark, mono, "{screen:?} at {width}x{height}");
        }
    }
}

/// The awaiting state, which is the one that draws a scan code.
fn awaiting_case(theme: Theme, color: ColorMode) -> Case {
    Case {
        name: "comparison",
        screen: Screen::SignIn,
        theme,
        color,
        width: REFERENCE_WIDTH,
        height: REFERENCE_HEIGHT,
        flow: flows()
            .into_iter()
            .find(|(name, _)| *name == "awaiting")
            .map(|(_, state)| state),
    }
}

#[test]
fn a_scan_code_reads_the_same_in_both_palettes_and_is_withheld_without_colour() {
    let dark = characters(&awaiting_case(Theme::Dark, ColorMode::Color));
    let light = characters(&awaiting_case(Theme::Light, ColorMode::Color));
    assert_eq!(
        reading(&awaiting_case(Theme::Dark, ColorMode::Color)),
        reading(&awaiting_case(Theme::Light, ColorMode::Color)),
        "the code is painted, not themed"
    );
    assert!(dark.contains('\u{2580}') && light.contains('\u{2580}'));

    // Without colour it cannot paint its own field, so it is withheld and the
    // screen says which of the two facts is missing.
    let mono = characters(&awaiting_case(Theme::Dark, ColorMode::NoColor));
    assert!(
        !mono.contains('\u{2580}'),
        "a code that cannot be painted is not drawn"
    );
    assert!(mono.contains("NO_COLOR"), "{mono}");
}

#[test]
fn the_two_palettes_never_paint_a_screen_the_same_way() {
    for screen in Screen::ALL {
        let case = |theme| Case {
            name: "comparison",
            screen,
            theme,
            color: ColorMode::Color,
            width: REFERENCE_WIDTH,
            height: REFERENCE_HEIGHT,
            flow: None,
        };
        assert_ne!(
            legend(&case(Theme::Dark)),
            legend(&case(Theme::Light)),
            "{screen:?}"
        );
    }
}

#[test]
fn no_color_emits_no_colour_at_all() {
    for screen in Screen::ALL {
        for (width, height) in [
            (REFERENCE_WIDTH, REFERENCE_HEIGHT),
            (FLOOR_WIDTH, FLOOR_HEIGHT),
        ] {
            let entries = legend(&Case {
                name: "comparison",
                screen,
                theme: Theme::Dark,
                color: ColorMode::NoColor,
                width,
                height,
                flow: None,
            });
            for entry in &entries {
                assert!(
                    entry.contains("fg=reset") && entry.contains("bg=reset"),
                    "{screen:?} at {width}x{height} emitted {entry}"
                );
            }
        }
    }
}

#[test]
fn the_whole_vocabulary_is_legible_at_the_floor_without_colour() {
    // The acceptance reading: at 80x24, with no colour at all, every one of the
    // nine statuses is on screen, each in its own lane.
    let rendered = characters(&Case {
        name: "comparison",
        screen: Screen::Findings,
        theme: Theme::Dark,
        color: ColorMode::NoColor,
        width: FLOOR_WIDTH,
        height: FLOOR_HEIGHT,
        flow: None,
    });
    for status in airlock_core::findings::Status::ALL {
        assert!(
            rendered.contains(super::lane::glyph_of(*status)),
            "{status:?} is not on screen at the floor"
        );
        assert!(
            rendered.contains(status.code()),
            "{status:?} is unnamed at the floor"
        );
    }
}

#[test]
fn a_terminal_under_the_floor_is_told_so_rather_than_drawn_into() {
    let rendered = render(&Case {
        name: "comparison",
        screen: Screen::Findings,
        theme: Theme::Dark,
        color: ColorMode::Color,
        width: 60,
        height: 20,
        flow: None,
    });
    assert!(rendered.contains("TERMINAL TOO SMALL"), "{rendered}");
    assert!(!rendered.contains("STATUS VOCABULARY"), "{rendered}");
}

fn section(rendered: &str, marker: &str) -> String {
    let start = rendered
        .find(marker)
        .map(|index| index + marker.len())
        .expect("the section is present");
    let rest = &rendered[start..];
    let end = rest.find("--- ").unwrap_or(rest.len());
    rest[..end].to_string()
}

fn characters(case: &Case) -> String {
    section(&render(case), "--- text ---\n")
}

fn legend(case: &Case) -> Vec<String> {
    section(&render(case), "--- legend ---\n")
        .lines()
        .map(str::to_string)
        .collect()
}
